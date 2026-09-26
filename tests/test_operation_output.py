# SPDX-License-Identifier: Apache-2.0
"""Operation output is redacted on one path, and DockHand-reported failures are `operation_failed`.

Job lines, SSE progress entries, final result/error payloads and batch per-item messages are
free text from DockHand. Every tool that returns them (every tool declaring `GET /api/jobs/{id}`,
taken from the registry) is called end to end with output carrying a `dh_` token, a bearer
credential, a `user:pass@` URL, a `password=` pair and a sensitive key, all built at runtime.
Stack operations also redact the stack's own variable values (at least 8 characters, not
DockHand's `***` mask). Job and stream bodies here are invented in the live shapes S3a and S3c
recorded (ARCHIVE §14); none is a recorded response.
"""

import json
import logging
from typing import Any, Final

import pytest
import respx
from conftest import DOCKHAND_TOKEN, DOCKHAND_URL, ENV, IDS, SetEnv, fake_dh_token, fake_secret
from test_destructive_tools import CASES as DESTRUCTIVE_CASES
from test_destructive_tools import call
from test_operator_tools import CASES as OPERATOR_CASES
from test_operator_tools import Route, Sse, fx, mount, sent

from dockhand_mcp.client.batch import interpret_batch
from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.client.jobs import poll_job
from dockhand_mcp.client.redaction import (
    MAX_ENTRY_CHARS,
    MIN_CONTEXT_VALUE_CHARS,
    OutputRedactor,
    context_values,
)
from dockhand_mcp.client.sse import consume
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.tools.registry import REGISTRY

JOB: Final = "4c3b2a19-8f7e-4d6c-9b5a-1f2e3d4c5b6a"
JOB_STATUS: Final = ("GET", "/api/jobs/{id}")
E: Final = {"environment_id": ENV}
WEB, DB = IDS["CID_WEB"], IDS["CID_DB"]
SSE_HEADERS: Final = {"content-type": "text/event-stream"}

# --- runtime-built secrets (standing rule: no token-shaped literals in test files) -------------

TOKEN: Final = fake_dh_token("Zq9" + "x" * 30)
BEARER: Final = fake_secret("bearer-cred-" + "b" * 12)
URL_USER: Final = "deployer"
URL_PASS: Final = fake_secret("url-pass-" + "u" * 8)
PAIR: Final = fake_secret("pair-pass-" + "p" * 8)
KEYED: Final = fake_secret("keyed-" + "k" * 10)
TEXT: Final = (
    f"pulled with {TOKEN}; sent Authorization: Bearer {BEARER}; "
    f"from https://{URL_USER}:{URL_PASS}@registry.example.test/v2/; password={PAIR}"
)
# What must never appear anywhere in a result.
LEAKS: Final = (TOKEN, TOKEN[3:], BEARER, URL_PASS, f"{URL_USER}:", PAIR, KEYED)
# What the redacted text still says, so the output is visibly there, only masked.
MARKERS: Final = (
    "dh_***",
    "Bearer ***",
    f"https://{REDACTED}@registry.example.test",
    "password=***",
)


def assert_redacted(envelope: Envelope) -> str:
    text = json.dumps(envelope.model_dump(mode="json"))
    for leak in LEAKS:
        assert leak not in text, f"{leak!r} leaked"
    return text


def leaky_lines() -> list[Any]:
    """Every line shape seen live: `{event, data}` records, batch `{data}` records, plain text."""
    return [
        {"event": "progress", "data": {"type": "line", "line": TEXT}},
        {"event": "progress", "data": {"status": "pulling", "token": KEYED, "hasToken": True}},
        {"data": {"type": "progress", "message": TEXT}},
        TEXT,
    ]


FAILED_RESULT: Final = {"success": False, "output": TEXT, "error": TEXT}


def leaky_job(result: Any = FAILED_RESULT, status: str = "done") -> dict[str, Any]:
    return {"id": JOB, "status": status, "lines": leaky_lines(), "result": result}


# --- which tools return operation output: from the registry -----------------------------------

OUTPUT_TOOLS: Final = sorted(t.name for t in REGISTRY.all() if JOB_STATUS in t.endpoints)
# Of those, the ones that consume an event stream (ARCHITECTURE §4.2) rather than start a job.
SSE_TOOLS: Final = {
    "dockhand_check_container_updates",
    "dockhand_deploy_git_stack",
    "dockhand_deploy_stack",
    "dockhand_prune",
    "dockhand_pull_image",
    "dockhand_restart_stack",
    "dockhand_scan_all_images",
    "dockhand_scan_image",
}
BATCH_TOOLS: Final = {"dockhand_batch_containers", "dockhand_batch_remove_containers"}
STACK_TOOLS: Final = {
    "dockhand_start_stack",
    "dockhand_stop_stack",
    "dockhand_restart_stack",
    "dockhand_deploy_stack",
    "dockhand_down_stack",
}
WRITE_TOOLS: Final = sorted(set(OUTPUT_TOOLS) - {"dockhand_get_job"})


def test_the_output_tool_list_comes_from_the_registry() -> None:
    assert len(OUTPUT_TOOLS) == 14  # never vacuous; a new tool must be classified below
    assert set(OUTPUT_TOOLS) >= SSE_TOOLS | BATCH_TOOLS | STACK_TOOLS | {"dockhand_get_job"}


def env_routes(raw: str = "TZ=UTC\n", variables: list[dict[str, Any]] | None = None) -> list[Route]:
    body = {"variables": variables or [], "injectedSecretKeys": [], "secretProvider": None}
    return [
        ("GET", "/api/stacks/shop/env/raw", {"content": raw, "noEnvFile": False}),
        ("GET", "/api/stacks/shop/env", body),
    ]


def start_endpoint(tool: str, args: dict[str, Any]) -> tuple[str, str]:
    """The one non-GET request a tool sends to start its operation."""
    if tool == "dockhand_prune":
        return ("POST", f"/api/prune/{args['scope']}")
    (method, template), *_ = [
        e for e in next(t for t in REGISTRY.all() if t.name == tool).endpoints if e[0] != "GET"
    ]
    return method, template.replace("{name}", "shop").replace("{id}", "4")


def setup(tool: str) -> tuple[dict[str, Any], list[Route]]:
    """Arguments and the routes a tool reads before it starts its operation."""
    if tool == "dockhand_get_job":
        return {"job_id": JOB}, []
    if tool == "dockhand_prune":
        routes: list[Route] = [
            ("GET", "/api/images", fx("images", "list")),
            ("GET", "/api/containers", fx("containers", "list")),
        ]
        return {**E, "scope": "images", "confirm": True}, routes
    if tool in DESTRUCTIVE_CASES:
        case = DESTRUCTIVE_CASES[tool]
        routes = list(case.reads)
        if tool == "dockhand_down_stack":
            routes += env_routes()
        return {**case.args, "confirm": True}, routes
    args, all_routes = OPERATOR_CASES[tool]
    start = start_endpoint(tool, args)
    routes = [r for r in all_routes if (r[0], r[1]) != start and not r[1].startswith("/api/jobs")]
    if tool in STACK_TOOLS:
        routes += env_routes()
    return dict(args), routes


def job_answer(tool: str) -> dict[str, Any]:
    """The finished job each tool polls, carrying the secrets in every output part."""
    if tool == "dockhand_batch_containers":
        lines = [
            {"data": {"type": "start", "total": 2}},
            {"data": {"type": "progress", "id": WEB, "name": "web", "status": "success"}},
            {
                "data": {
                    "type": "progress",
                    "id": DB,
                    "name": "db",
                    "status": "error",
                    "error": TEXT,
                }
            },
        ]
        summary = {"total": 2, "success": 1, "failed": 1}
        result = {"type": "complete", "summary": summary}
        return {"id": JOB, "status": "done", "lines": lines + leaky_lines(), "result": result}
    if tool == "dockhand_batch_remove_containers":
        summary = {"total": 2, "success": 1, "failed": 1}
        return leaky_job({"type": "complete", "summary": summary, "note": TEXT})
    return leaky_job()


async def run_job_channel(tool: str, dockhand: respx.MockRouter) -> Envelope:
    args, routes = setup(tool)
    if tool != "dockhand_get_job":
        routes.append((*start_endpoint(tool, args), {"jobId": JOB}))
    routes.append(("GET", f"/api/jobs/{JOB}", job_answer(tool)))
    mount(dockhand, routes)
    return await call(tool, args)


@pytest.fixture
def admin(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_MCP_CONFIRM_MODE="param")


# --- every output tool, job channel (what live DockHand 1.0.46 answers) ------------------------


@pytest.mark.parametrize("tool", OUTPUT_TOOLS)
async def test_job_output_is_redacted(tool: str, dockhand: respx.MockRouter, admin: None) -> None:
    env = await run_job_channel(tool, dockhand)
    text = assert_redacted(env)
    for marker in MARKERS:
        assert marker in text, f"{marker!r} missing: the output should be masked, not dropped"


@pytest.mark.parametrize("tool", WRITE_TOOLS)
async def test_operation_failure_is_operation_failed(
    tool: str, dockhand: respx.MockRouter, admin: None
) -> None:
    """A job result reporting failure, or a batch with a failed item: the HTTP calls succeeded."""
    env = await run_job_channel(tool, dockhand)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed", env.error
    assert env.error.dockhand_status is None


@pytest.mark.parametrize("status", ["failed", "error"])
@pytest.mark.parametrize("tool", ["dockhand_start_stack", "dockhand_deploy_stack"])
async def test_failed_job_status_is_operation_failed(
    tool: str, status: str, dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes = setup(tool)
    job = leaky_job({"success": True}, status=status)
    routes += [(*start_endpoint(tool, args), {"jobId": JOB}), ("GET", f"/api/jobs/{JOB}", job)]
    mount(dockhand, routes)
    env = await call(tool, args)
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert_redacted(env)


@pytest.mark.parametrize("tool", WRITE_TOOLS)
async def test_dockhand_500_is_still_dockhand_http_error(
    tool: str, dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes = setup(tool)
    mount(dockhand, routes)
    dockhand.route(
        method=start_endpoint(tool, args)[0], path=start_endpoint(tool, args)[1]
    ).respond(500, json={"error": "compose failed"})
    env = await call(tool, args)
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert_redacted(env)


# --- SSE tools, real event streams --------------------------------------------------------------


def leaky_stream(terminal: tuple[str, Any]) -> Sse:
    return Sse(
        [
            ("progress", {"type": "line", "line": TEXT}),
            ("progress", {"status": "pulling", "token": KEYED}),
            ("progress", {"message": TEXT}),
            terminal,
        ]
    )


@pytest.mark.parametrize(
    "terminal",
    [
        pytest.param(("error", {"message": TEXT, "detail": TEXT}), id="error-event"),
        pytest.param(("result", FAILED_RESULT), id="failed-result"),
    ],
)
@pytest.mark.parametrize("tool", sorted(SSE_TOOLS))
async def test_stream_output_is_redacted_and_failure_is_operation_failed(
    tool: str, terminal: tuple[str, Any], dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes = setup(tool)
    mount(dockhand, [*routes, (*start_endpoint(tool, args), leaky_stream(terminal))])
    env = await call(tool, args)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    text = assert_redacted(env)
    for marker in MARKERS:
        assert marker in text


async def test_plain_text_stream_data_is_redacted(dockhand: respx.MockRouter, admin: None) -> None:
    body = f"event: progress\ndata: {TEXT}\n\nevent: error\ndata: {TEXT}\n\n".encode()
    mount(dockhand, [("GET", "/api/environments", fx("environments", "list"))])
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE_HEADERS)
    env = await call("dockhand_pull_image", {**E, "image": "nginx:1.28"})
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert_redacted(env)


async def test_stream_without_a_result_is_still_dockhand_http_error(
    dockhand: respx.MockRouter, admin: None
) -> None:
    """No terminal event is an unexpected response, not an operation DockHand reported failed."""
    body = f"event: progress\ndata: {TEXT}\n\n".encode()
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE_HEADERS)
    env = await call("dockhand_pull_image", {**E, "image": "nginx:1.28"})
    assert env.error is not None
    assert env.error.code == "dockhand_http_error"
    assert_redacted(env)


# --- other DockHand-reported failures -----------------------------------------------------------


async def test_batch_update_with_a_failed_item_is_operation_failed(
    dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes = OPERATOR_CASES["dockhand_update_containers"]
    answer = {"success": True, "summary": {"total": 2, "success": 1, "failed": 1}}
    mount(dockhand, [r for r in routes if r[1] != "/api/containers/batch-update"])
    dockhand.post("/api/containers/batch-update").respond(200, json=answer)
    env = await call("dockhand_update_containers", args)
    assert env.error is not None
    assert env.error.code == "operation_failed"


async def test_git_sync_reporting_failure_is_operation_failed(
    dockhand: respx.MockRouter, admin: None
) -> None:
    dockhand.post("/api/git/stacks/4/sync").respond(200, json={"success": False, "error": TEXT})
    env = await call("dockhand_sync_git_stack", {"git_stack_id": 4})
    assert env.error is not None
    assert env.error.code == "operation_failed"


async def test_destructive_answer_reporting_failure_is_operation_failed(
    dockhand: respx.MockRouter, admin: None
) -> None:
    case = DESTRUCTIVE_CASES["dockhand_remove_volume"]
    mount(dockhand, list(case.reads))
    dockhand.delete("/api/volumes/cache").respond(200, json={"success": False})
    env = await call("dockhand_remove_volume", {**case.args, "confirm": True})
    assert env.error is not None
    assert env.error.code == "operation_failed"


# --- context-aware redaction for stack operations -----------------------------------------------

LONG: Final = fake_secret("greeting-" + "g" * 6)
DB_ONLY: Final = fake_secret("db-only-" + "d" * 6)
SHORT: Final = "ab12"
ECHO: Final = f"greeting={LONG} tag={DB_ONLY} short={SHORT} db=***"
STACK_VARIABLES: Final = [
    {"key": "APP_GREETING", "value": LONG, "isSecret": False},
    {"key": "LOG_TAG", "value": DB_ONLY, "isSecret": False},
    {"key": "SHORT", "value": SHORT, "isSecret": False},
    {"key": "DB_PASSWORD", "value": "***", "isSecret": True},
]


def echoing_job() -> dict[str, Any]:
    lines = [{"event": "progress", "data": {"type": "line", "line": ECHO}}, ECHO]
    return {
        "id": JOB,
        "status": "done",
        "lines": lines,
        "result": {"success": True, "output": ECHO},
    }


@pytest.mark.parametrize("tool", sorted(STACK_TOOLS))
async def test_stack_env_values_are_redacted(
    tool: str, dockhand: respx.MockRouter, admin: None, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    args, routes = setup(tool)
    routes = [r for r in routes if not r[1].startswith("/api/stacks/shop/env")]
    routes += env_routes(f"APP_GREETING={LONG}\nSHORT={SHORT}\n", STACK_VARIABLES)
    routes += [
        (*start_endpoint(tool, args), {"jobId": JOB}),
        ("GET", f"/api/jobs/{JOB}", echoing_job()),
    ]
    mount(dockhand, routes)
    env = await call(tool, args)
    assert env.ok is True, env.error
    text = json.dumps(env.model_dump(mode="json"))
    assert LONG not in text
    assert DB_ONLY not in text
    assert f"greeting={REDACTED}" in text
    assert f"short={SHORT}" in text  # under 8 characters: left alone
    assert "db=***" in text  # DockHand's mask is not a value
    assert LONG not in caplog.text
    assert DB_ONLY not in caplog.text


async def test_stack_operation_is_not_started_when_its_variables_cannot_be_read(
    dockhand: respx.MockRouter, admin: None
) -> None:
    """Fail closed: output that could not be redacted is never produced."""
    args, routes = setup("dockhand_start_stack")
    mount(dockhand, [r for r in routes if not r[1].startswith("/api/stacks/shop/env")])
    dockhand.get("/api/stacks/shop/env/raw").respond(403, json={"error": "denied"})
    dockhand.get("/api/stacks/shop/env").respond(200, json={"variables": []})
    start = dockhand.post("/api/stacks/shop/start").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(200, json=echoing_job())
    env = await call("dockhand_start_stack", args)
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 403)
    assert not start.called
    assert not sent(dockhand, "POST", "/api/stacks/shop/start")


# --- the redaction path itself, and that the client modules apply it ---------------------------


def test_redactor_layers() -> None:
    redact = OutputRedactor()
    out = redact({"line": TEXT, "token": KEYED, "hasToken": True, "nested": [{"password": None}]})
    assert out["token"] == REDACTED
    assert out["hasToken"] is True  # booleans say whether a secret exists; they carry none
    assert out["nested"] == [{"password": None}]
    for leak in LEAKS:
        assert leak not in out["line"]
    for marker in MARKERS:
        assert marker in out["line"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"https://{URL_USER}:{URL_PASS}@host.example.test/x",
            f"https://{REDACTED}@host.example.test/x",
        ),
        (
            f"git clone https://{PAIR}@git.example.test/r.git",
            f"git clone https://{REDACTED}@git.example.test/r.git",
        ),
        ("ssh://git@git.example.test/r", f"ssh://{REDACTED}@git.example.test/r"),
        ("mail ops@example.test", "mail ops@example.test"),
        ("https://host.example.test/a@b", "https://host.example.test/a@b"),
    ],
)
def test_url_credentials(text: str, expected: str) -> None:
    assert OutputRedactor()(text) == expected


def test_configured_secrets_are_redacted() -> None:
    from dockhand_mcp.logging import set_redaction_secrets

    set_redaction_secrets([DOCKHAND_TOKEN])
    assert DOCKHAND_TOKEN not in OutputRedactor()(f"token was {DOCKHAND_TOKEN}")


def test_redaction_happens_before_the_cap() -> None:
    """A secret straddling the 512-character cap must not survive as a fragment."""
    long_value = fake_secret("v" * 4 + "w" * 40)
    redact = OutputRedactor.for_values([long_value])
    for secret in (TOKEN, long_value):
        line = redact.line("x" * (MAX_ENTRY_CHARS - 10) + secret)
        assert len(line) <= MAX_ENTRY_CHARS + 1
        assert secret[:10] not in line[MAX_ENTRY_CHARS - 10 :]


def test_context_values() -> None:
    longer = "abcdefgh-ij"
    assert MIN_CONTEXT_VALUE_CHARS == 8
    assert context_values(["short", "***", None, 42, "abcdefgh", longer, "abcdefgh"]) == (
        longer,
        "abcdefgh",
    )
    # Longest first: a value containing another is masked whole.
    assert OutputRedactor.for_values(["abcdefgh", longer])(f"x {longer} y") == f"x {REDACTED} y"


@pytest.fixture
def client() -> DockhandClient:
    return DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN)


async def test_poll_job_redacts(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    dockhand.get(f"/api/jobs/{JOB}").respond(200, json=leaky_job())
    job = await poll_job(client, JOB, 5)
    text = json.dumps([job.lines, job.result])
    for leak in LEAKS:
        assert leak not in text


async def test_consume_redacts(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    events = [
        ("progress", json.dumps({"type": "line", "line": TEXT})),
        ("progress", json.dumps({"status": "pulling", "token": KEYED})),
        ("progress", TEXT),
        ("result", json.dumps(FAILED_RESULT)),
    ]
    body = "".join(f"event: {e}\ndata: {d}\n\n" for e, d in events)
    dockhand.post("/api/images/pull").respond(200, content=body.encode(), headers=SSE_HEADERS)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    text = json.dumps([list(res.progress), res.final_data])
    for leak in LEAKS:
        assert leak not in text


async def test_consume_keeps_the_job_id_of_a_json_answer(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.post("/api/stacks/shop/deploy").respond(200, json={"jobId": JOB, "note": TEXT})
    res = await consume(
        client, "POST", "/api/stacks/{name}/deploy", path_params={"name": "shop"}, budget_s=5
    )
    assert res.job_id == JOB
    assert TOKEN not in json.dumps(res.final_data)


def test_batch_item_messages_are_redacted() -> None:
    sent_items = [{"id": WEB, "name": "web"}]
    lines = [{"data": {"type": "progress", "id": WEB, "status": "error", "error": TEXT}}]
    result = {"type": "complete", "summary": {"total": 1, "success": 0, "failed": 1}}
    outcome = interpret_batch("done", result, lines, sent_items)
    text = json.dumps(outcome.items)
    for leak in LEAKS:
        assert leak not in text
    assert outcome.code == "operation_failed"
