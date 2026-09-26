# SPDX-License-Identifier: Apache-2.0
"""A content write DockHand answers with a 5xx, or that gets no answer once sent (#17).

The spec says every accepted `PUT …/compose` persists the content, and its 500 reads "Failed to
save or deploy", so an error does not mean nothing was written. After a 5xx, or a connection
that drops after the request went out, the tool reads the content back once:
- it matches what was sent → `ok: false`, `operation_failed`, `data.saved: true`;
- it does not (for a create: the stack does not exist) → `dockhand_http_error`, `saved: false`;
- the read-back fails → `dockhand_http_error`, `saved: "unknown"`, and the message says to check
  before retrying.

Compound writes (compose with `redeploy`, create with `start`) keep S3f's `data.steps` and add a
`read_back` step. A 4xx, a request that never left, and 2xx answers are unchanged.
"""

from typing import Any

import httpx
import pytest
import respx
from conftest import SetEnv
from test_operator_tools import (
    CASES,
    NEW_COMPOSE,
    NEW_ENV,
    OLD_COMPOSE,
    OLD_ENV,
    Route,
    Seq,
    call,
    compose_body,
    env_raw,
    mount,
    sent,
)

from dockhand_mcp.client.envelope import Envelope

SAVED_MESSAGE = "DockHand reported an error, but the content was saved."
SERVER_ERROR = {"error": "Failed to save or deploy the compose file"}
DENIED = {"error": "Permission denied"}

# tool → (args, the write endpoint, the read-back endpoint, what was sent, what was there before)
COMPOSE_PATH = "/api/stacks/shop/compose"
ENV_PATH = "/api/stacks/shop/env/raw"
WRITES: dict[str, tuple[str, str, str, str, str]] = {
    "dockhand_update_stack_compose": ("PUT", COMPOSE_PATH, COMPOSE_PATH, NEW_COMPOSE, OLD_COMPOSE),
    "dockhand_update_stack_env_raw": ("PUT", ENV_PATH, ENV_PATH, NEW_ENV, OLD_ENV),
    "dockhand_modify_stack_env": ("PUT", ENV_PATH, ENV_PATH, NEW_ENV, OLD_ENV),
}
TOOLS = [*WRITES, "dockhand_create_stack"]


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


def _read_back_body(path: str, content: str) -> Any:
    return compose_body(content) if path == COMPOSE_PATH else env_raw(content)


def routes_for(tool: str, read_back: str | None) -> list[Route]:
    """The tool's happy-path routes, with the read-back answering `read_back` (None: a 403)."""
    routes = list(CASES[tool][1])
    if tool == "dockhand_create_stack":
        return routes  # the compose GET is mounted per test
    _, _, read_path, _, before = WRITES[tool]
    out: list[Route] = []
    for method, path, body in routes:
        if (method, path) == ("GET", read_path):
            if read_path == ENV_PATH:
                # Read once for the guardrails (the current file), then once to read back.
                after = env_raw(read_back) if read_back is not None else env_raw(before)
                body = Seq((env_raw(before), after))
            elif read_back is not None:
                body = _read_back_body(path, read_back)
        out.append((method, path, body))
    return out


def fail_write(dockhand: respx.MockRouter, tool: str, **response: Any) -> None:
    method, path = ("POST", "/api/stacks") if tool == "dockhand_create_stack" else WRITES[tool][:2]
    dockhand.route(method=method, path=path).respond(**response)


def fail_read_back(dockhand: respx.MockRouter, tool: str) -> None:
    """The read-back answers 403 (the write's own earlier reads still succeed)."""
    if tool == "dockhand_create_stack":
        dockhand.route(method="GET", path=COMPOSE_PATH).respond(403, json=DENIED)
        return
    _, _, read_path, _, before = WRITES[tool]
    if read_path == ENV_PATH:
        dockhand.route(method="GET", path=ENV_PATH).side_effect = [
            httpx.Response(200, json=env_raw(before)),
            httpx.Response(403, json=DENIED),
        ]
    else:
        dockhand.route(method="GET", path=read_path).respond(403, json=DENIED)


def args_for(tool: str, **extra: Any) -> dict[str, Any]:
    return {**CASES[tool][0], **extra}


def mount_create_read_back(dockhand: respx.MockRouter, answer: Any, status: int = 200) -> None:
    dockhand.route(method="GET", path=COMPOSE_PATH).respond(status, json=answer)


def setup(dockhand: respx.MockRouter, tool: str, outcome: str) -> None:
    """Mount `tool`'s routes, its write answering 500, the read-back giving `outcome`:
    `saved` (the new content), `unsaved` (the old content, or no stack) or `unreadable`."""
    if tool == "dockhand_create_stack":
        mount(dockhand, routes_for(tool, None))
        if outcome == "saved":
            mount_create_read_back(dockhand, compose_body(NEW_COMPOSE))
        elif outcome == "unsaved":
            mount_create_read_back(dockhand, {"error": "Stack not found"}, status=404)
        else:
            fail_read_back(dockhand, tool)
    else:
        sent_content, before = WRITES[tool][3], WRITES[tool][4]
        mount(dockhand, routes_for(tool, sent_content if outcome == "saved" else before))
        if outcome == "unreadable":
            fail_read_back(dockhand, tool)
    fail_write(dockhand, tool, status_code=500, json=SERVER_ERROR)


def read_backs(dockhand: respx.MockRouter, tool: str) -> int:
    """How many times the written content was read after the write."""
    if tool == "dockhand_create_stack":
        return len(sent(dockhand, "GET", COMPOSE_PATH))
    _, _, read_path, _, _ = WRITES[tool]
    return len(sent(dockhand, "GET", read_path)) - (1 if read_path == ENV_PATH else 0)


def data(env: Envelope) -> dict[str, Any]:
    assert isinstance(env.data, dict)
    return env.data


# --- the three read-back outcomes, every content write ---------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
async def test_5xx_and_content_saved_is_operation_failed_saved_true(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    setup(dockhand, tool, "saved")
    env, _ = await call(tool, args_for(tool))
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert env.error.message.startswith(SAVED_MESSAGE)
    assert env.error.dockhand_status == 500
    assert env.verified is True
    assert data(env)["saved"] is True
    assert read_backs(dockhand, tool) == 1


@pytest.mark.parametrize("tool", TOOLS)
async def test_5xx_and_content_not_saved_is_dockhand_http_error_saved_false(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    setup(dockhand, tool, "unsaved")
    env, _ = await call(tool, args_for(tool))
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert "not saved" in env.error.message or "not created" in env.error.message
    assert env.verified is not True
    assert data(env)["saved"] is False
    assert read_backs(dockhand, tool) == 1


@pytest.mark.parametrize("tool", TOOLS)
async def test_5xx_and_read_back_failing_is_saved_unknown(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    setup(dockhand, tool, "unreadable")
    env, _ = await call(tool, args_for(tool))
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert "before retrying" in env.error.message
    assert env.verified is not True
    assert data(env)["saved"] == "unknown"
    assert read_backs(dockhand, tool) == 1


# --- what triggers a read-back ----------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
async def test_dropped_connection_after_sending_reads_back(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The request went out and no answer came: DockHand may have written the content."""
    operator_env()
    setup(dockhand, tool, "saved")
    method, path = ("POST", "/api/stacks") if tool == "dockhand_create_stack" else WRITES[tool][:2]
    dockhand.route(method=method, path=path).side_effect = httpx.RemoteProtocolError(
        "Server disconnected without sending a response."
    )
    env, _ = await call(tool, args_for(tool))
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert env.error.dockhand_status is None
    assert data(env)["saved"] is True


@pytest.mark.parametrize("tool", TOOLS)
async def test_connection_never_made_is_unchanged(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """A connect error means the request never reached DockHand: nothing to read back."""
    operator_env()
    setup(dockhand, tool, "saved")
    method, path = ("POST", "/api/stacks") if tool == "dockhand_create_stack" else WRITES[tool][:2]
    dockhand.route(method=method, path=path).side_effect = httpx.ConnectError("refused")
    env, _ = await call(tool, args_for(tool))
    assert env.error is not None
    assert env.error.code == "dockhand_unreachable"
    assert env.data is None
    assert read_backs(dockhand, tool) == 0


@pytest.mark.parametrize("tool", TOOLS)
async def test_4xx_is_unchanged(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """DockHand refused the request: nothing was written, and nothing is read back."""
    operator_env()
    setup(dockhand, tool, "saved")
    fail_write(dockhand, tool, status_code=400, json={"error": "Invalid request"})
    env, _ = await call(tool, args_for(tool))
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 400)
    assert env.data is None
    assert read_backs(dockhand, tool) == 0


@pytest.mark.parametrize("tool", TOOLS)
async def test_2xx_is_unchanged(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, CASES[tool][1])
    env, _ = await call(tool, args_for(tool))
    assert (env.ok, env.verified, env.error) == (True, True, None)
    assert "saved" not in data(env)


async def test_read_back_with_different_content_on_create_is_unknown(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """A stack the collision guard did not see now exists with other content: say so, don't
    claim it was or wasn't this call's."""
    operator_env()
    mount(dockhand, routes_for("dockhand_create_stack", None))
    mount_create_read_back(dockhand, compose_body(OLD_COMPOSE))
    fail_write(dockhand, "dockhand_create_stack", status_code=502, json=SERVER_ERROR)
    env, _ = await call("dockhand_create_stack", args_for("dockhand_create_stack"))
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 502)
    assert data(env)["saved"] == "unknown"
    assert "before retrying" in env.error.message


async def test_update_read_back_with_other_content_is_not_saved_with_a_diff(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The stored file is neither what was sent nor readable as saved: this call's content is
    not there. The diff summary holds counts and line numbers only."""
    operator_env()
    other = "services:\n  other:\n    image: busybox:1.37\n"
    mount(dockhand, routes_for("dockhand_update_stack_compose", other))
    fail_write(dockhand, "dockhand_update_stack_compose", status_code=500, json=SERVER_ERROR)
    env, structured = await call(
        "dockhand_update_stack_compose", args_for("dockhand_update_stack_compose")
    )
    assert env.error is not None
    assert env.error.code == "dockhand_http_error"
    assert data(env)["saved"] is False
    assert data(env)["read_back"]["expected_lines"] == len(NEW_COMPOSE.splitlines())
    assert "busybox" not in str(structured)


# --- compound writes: S3f's steps plus the read-back ------------------------------------------


REDEPLOY = {"redeploy": True}
START = {"start": True}


@pytest.mark.parametrize(
    ("tool", "extra", "first", "second", "flag_done", "flag_second"),
    [
        ("dockhand_update_stack_compose", REDEPLOY, "save", "redeploy", "saved", "redeployed"),
        ("dockhand_create_stack", START, "create", "start", "created", "started"),
    ],
)
@pytest.mark.parametrize(
    ("outcome", "first_outcome", "second_outcome", "read_outcome", "saved"),
    [
        ("saved", "succeeded", "failed", "succeeded", True),
        ("unsaved", "failed", "failed", "succeeded", False),
        ("unreadable", "unknown", "unknown", "failed", "unknown"),
    ],
)
async def test_compound_write_after_5xx_reports_steps(
    tool: str,
    extra: dict[str, Any],
    first: str,
    second: str,
    flag_done: str,
    flag_second: str,
    outcome: str,
    first_outcome: str,
    second_outcome: str,
    read_outcome: str,
    saved: Any,
    dockhand: respx.MockRouter,
    operator_env: SetEnv,
) -> None:
    operator_env()
    setup(dockhand, tool, outcome)
    env, _ = await call(tool, args_for(tool, **extra))
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ("operation_failed" if saved is True else "dockhand_http_error")
    body = data(env)
    assert body["saved"] == saved
    assert body[flag_done] == saved
    assert body[flag_second] is False
    names = [s["step"] for s in body["steps"]]
    outcomes = [s["outcome"] for s in body["steps"]]
    assert names == [first, second, "read_back"]
    assert outcomes == [first_outcome, second_outcome, read_outcome]
    assert body["steps"][0].get("verified") is (True if saved is True else None)
    read_step = body["steps"][2]
    assert (read_step["message"] is None) is (read_outcome == "succeeded")
    if saved is True:
        assert "rather than" in env.error.message


async def test_saved_after_error_keeps_the_env_recreate_reminder(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    setup(dockhand, "dockhand_modify_stack_env", "saved")
    env, _ = await call("dockhand_modify_stack_env", args_for("dockhand_modify_stack_env"))
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert env.warnings is not None
    assert any("recreated" in w for w in env.warnings)


async def test_create_saved_after_error_checks_the_variables_too(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The stack exists (saved), but its variables do not read back as sent: not verified."""
    operator_env()
    setup(dockhand, "dockhand_create_stack", "saved")
    dockhand.route(method="GET", path="/api/stacks/shop/env").respond(200, json={"variables": []})
    env, _ = await call("dockhand_create_stack", args_for("dockhand_create_stack"))
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert data(env)["saved"] is True
    assert env.verified is False
    assert data(env)["read_back"] == {"missing_keys": ["TZ"], "different_keys": []}


async def test_create_saved_after_error_with_unreadable_variables_stays_saved(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    setup(dockhand, "dockhand_create_stack", "saved")
    dockhand.route(method="GET", path="/api/stacks/shop/env").respond(403, json=DENIED)
    env, _ = await call("dockhand_create_stack", args_for("dockhand_create_stack"))
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert data(env)["saved"] is True
    assert env.verified is None
    assert env.warnings is not None
    assert any("variables could not be read back" in w for w in env.warnings)


async def test_only_the_write_is_sent_once(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """No retry, no rollback: one PUT, then one GET."""
    operator_env()
    setup(dockhand, "dockhand_update_stack_compose", "saved")
    await call("dockhand_update_stack_compose", args_for("dockhand_update_stack_compose"))
    assert len(sent(dockhand, "PUT", COMPOSE_PATH)) == 1
    assert [c.request.method for c in dockhand.calls if c.request.method == "DELETE"] == []


def test_the_write_tools_are_the_content_writes() -> None:
    """Every operator tool that sends compose or `.env` content is covered here."""
    from dockhand_mcp.tools.registry import REGISTRY

    content_writes = {
        t.name
        for t in REGISTRY.all()
        if any(
            (m, p) in {("PUT", "/api/stacks/{name}/compose"), ("PUT", "/api/stacks/{name}/env/raw")}
            or (m, p) == ("POST", "/api/stacks")
            for m, p in t.endpoints
        )
    }
    assert content_writes == set(TOOLS)
