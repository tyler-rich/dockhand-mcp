# SPDX-License-Identifier: Apache-2.0
"""Compound writes: a tool whose one call persists content and then starts or redeploys it.

`dockhand_create_stack` with `start` and `dockhand_update_stack_compose` with `redeploy` are
answered by one DockHand request that does both. Live DockHand 1.0.46 answers HTTP 200 with
`success: false` when the write happened and the deploy did not (fixtures
`create-start-failed` and `put-compose-redeploy-failed`, shapes recorded in S3f). Such a call is
`ok: false` with `operation_failed`, `data.steps` (each step's name, outcome and DockHand's
redacted message) and what did happen, and is never rolled back. A 5xx on the write is read
back (#17, tests/test_saved_after_error.py); a single-action call (no `start` / `redeploy`) is
unchanged.
"""

import json
from typing import Any

import pytest
import respx
from conftest import ENV, SetEnv, fake_dh_token, load_fixture
from test_operator_tools import (
    CASES,
    NEW_COMPOSE,
    OLD_COMPOSE,
    OLD_ENV,
    Route,
    call,
    compose_body,
    env_raw,
    mount,
    sent,
)

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.client.redaction import MAX_ENTRY_CHARS
from dockhand_mcp.guardrails.secrets import REDACTED

E = {"environment_id": ENV}
S = {**E, "stack": "shop"}
CREATE_ARGS = {**CASES["dockhand_create_stack"][0], "start": True}
REDEPLOY_ARGS = {**S, "content": NEW_COMPOSE, "redeploy": True}
MISSING_TAG = "nginx:no-such-tag"


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


def _with(routes: list[Route], method: str, path: str, body: Any) -> list[Route]:
    """`routes` with the answer to `(method, path)` replaced."""
    return [(m, p, body if (m, p) == (method, path) else b) for m, p, b in routes]


def create_routes(answer: Any = None, read_back: str = NEW_COMPOSE) -> list[Route]:
    routes = CASES["dockhand_create_stack"][1]
    if answer is not None:
        routes = _with(routes, "POST", "/api/stacks", answer)
    return _with(routes, "GET", "/api/stacks/shop/compose", compose_body(read_back))


def compose_routes(answer: Any = None, read_back: str = NEW_COMPOSE) -> list[Route]:
    routes = CASES["dockhand_update_stack_compose"][1]
    if answer is not None:
        routes = _with(routes, "PUT", "/api/stacks/shop/compose", answer)
    return _with(routes, "GET", "/api/stacks/shop/compose", compose_body(read_back))


def start_failed() -> Any:
    return load_fixture("stacks", "create-start-failed")


def redeploy_failed() -> Any:
    return load_fixture("stacks", "put-compose-redeploy-failed")


def steps(env: Envelope) -> list[dict[str, Any]]:
    assert isinstance(env.data, dict)
    out = env.data["steps"]
    assert isinstance(out, list)
    return out


# --- create_stack with start ------------------------------------------------------------------


async def test_create_and_start_both_succeed(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, create_routes())
    env, _ = await call("dockhand_create_stack", CREATE_ARGS)
    assert (env.ok, env.verified, env.error) == (True, True, None)
    assert (env.data["created"], env.data["started"]) == (True, True)
    assert steps(env) == [
        {"step": "create", "outcome": "succeeded", "verified": True, "message": None},
        {"step": "start", "outcome": "succeeded", "message": None},
    ]


async def test_created_but_not_started_is_operation_failed(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, create_routes(start_failed()))
    env, _ = await call("dockhand_create_stack", CREATE_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert "created" in env.error.message
    assert env.error.dockhand_status is None
    assert env.verified is True  # the compose file was read back and matched
    assert (env.data["created"], env.data["started"]) == (True, False)
    create, start = steps(env)
    assert create == {"step": "create", "outcome": "succeeded", "verified": True, "message": None}
    assert (start["step"], start["outcome"]) == ("start", "failed")
    assert MISSING_TAG in start["message"]
    # The write was verified, and nothing was undone.
    assert len(sent(dockhand, "GET", "/api/stacks/shop/compose")) == 1
    assert [c.request.method for c in dockhand.calls if c.request.method == "DELETE"] == []


async def test_create_failing_with_no_stack_afterwards_is_not_created(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """#17: a 5xx is read back; no stack means nothing was created (tests/test_saved_after_error.py
    has the other outcomes)."""
    operator_env()
    mount(dockhand, create_routes())
    dockhand.route(method="POST", path="/api/stacks").respond(
        500, json={"error": "Failed to create or deploy the stack"}
    )
    dockhand.route(method="GET", path="/api/stacks/shop/compose").respond(
        404, json={"error": "Stack not found"}
    )
    env, _ = await call("dockhand_create_stack", CREATE_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert (env.data["saved"], env.data["created"], env.data["started"]) == (False, False, False)


async def test_create_read_back_mismatch_stays_verification_failed_when_start_fails(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, create_routes(start_failed(), read_back=OLD_COMPOSE))
    env, _ = await call("dockhand_create_stack", CREATE_ARGS)
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert "steps" not in env.data


async def test_create_without_start_is_unchanged(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, create_routes())
    env, _ = await call("dockhand_create_stack", CASES["dockhand_create_stack"][0])
    assert (env.ok, env.verified) == (True, True)
    assert env.data["started"] is False
    assert "steps" not in env.data


async def test_start_failure_message_is_redacted_and_capped(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    value = "zz-" + "stack-value-" + "0451"
    token = fake_dh_token("Start9Failure_x")
    args = {**CREATE_ARGS, "env_vars": [{"key": "TZ", "value": value}]}
    answer = {
        "success": False,
        "error": f"pull failed for {value} with {token}\n" + "x" * (2 * MAX_ENTRY_CHARS),
        "output": "",
    }
    routes = create_routes(answer)
    routes = _with(
        routes, "GET", "/api/stacks/shop/env", {"variables": [{"key": "TZ", "value": value}]}
    )
    mount(dockhand, routes)
    env, content = await call("dockhand_create_stack", args)
    assert env.error is not None
    assert env.error.code == "operation_failed"
    message = steps(env)[1]["message"]
    assert REDACTED in message
    assert message.endswith("…")
    assert len(message) == MAX_ENTRY_CHARS + 1  # the cap, then the ellipsis marking the cut
    text = json.dumps(content)
    assert value not in text
    assert token not in text


# --- update_stack_compose with redeploy -------------------------------------------------------


async def test_save_and_redeploy_both_succeed(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes())
    env, _ = await call("dockhand_update_stack_compose", REDEPLOY_ARGS)
    assert (env.ok, env.verified, env.error) == (True, True, None)
    assert (env.data["saved"], env.data["redeployed"]) == (True, True)
    assert steps(env) == [
        {"step": "save", "outcome": "succeeded", "verified": True, "message": None},
        {"step": "redeploy", "outcome": "succeeded", "message": None},
    ]


async def test_saved_but_not_redeployed_is_operation_failed_and_verified(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes(redeploy_failed()))
    env, _ = await call("dockhand_update_stack_compose", REDEPLOY_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert "saved" in env.error.message
    assert env.verified is True
    assert (env.data["saved"], env.data["redeployed"]) == (True, False)
    save, redeploy = steps(env)
    assert save == {"step": "save", "outcome": "succeeded", "verified": True, "message": None}
    assert (redeploy["step"], redeploy["outcome"]) == ("redeploy", "failed")
    assert MISSING_TAG in redeploy["message"]
    assert len(sent(dockhand, "PUT", "/api/stacks/shop/compose")) == 1


async def test_save_failing_with_the_old_file_afterwards_is_not_saved(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """#17: a 5xx is read back; the old file means nothing was saved."""
    operator_env()
    mount(dockhand, compose_routes(read_back=OLD_COMPOSE))
    dockhand.route(method="PUT", path="/api/stacks/shop/compose").respond(
        500, json={"error": "Failed to save or deploy the compose file"}
    )
    env, _ = await call("dockhand_update_stack_compose", REDEPLOY_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert (env.data["saved"], env.data["redeployed"]) == (False, False)


async def test_save_read_back_mismatch_stays_verification_failed_when_redeploy_fails(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes(redeploy_failed(), read_back=OLD_COMPOSE))
    env, _ = await call("dockhand_update_stack_compose", REDEPLOY_ARGS)
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert "steps" not in env.data


async def test_save_without_redeploy_is_unchanged(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes())
    env, _ = await call("dockhand_update_stack_compose", {**S, "content": NEW_COMPOSE})
    assert (env.ok, env.verified) == (True, True)
    assert env.data["redeployed"] is False
    assert "steps" not in env.data


async def test_redeploy_failure_message_uses_the_stack_values(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    value = "zz-" + "compose-value-" + "7781"
    answer = {"success": False, "error": f"variable {value} broke the deploy"}
    routes = compose_routes(answer)
    routes = _with(routes, "GET", "/api/stacks/shop/env/raw", env_raw(f"{OLD_ENV}TOKEN={value}\n"))
    mount(dockhand, routes)
    env, content = await call("dockhand_update_stack_compose", REDEPLOY_ARGS)
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert REDACTED in steps(env)[1]["message"]
    assert value not in json.dumps(content)
