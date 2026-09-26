# SPDX-License-Identifier: Apache-2.0
"""Direct DockHand answers, read-tool free text, error bodies and log lines are redacted (#11).

Every tool whose DockHand answer is synchronous (it sends a non-GET request that is not a job or
an event stream; the list comes from the registry) is called end to end with that answer
carrying a `dh_` token, a bearer credential, a `user:pass@` URL, a `password=` pair and a
sensitive key, all built at runtime, and with DockHand's status strings carrying the same text.
The answer's other fields (`note`) are covered too, so the whole answer is redacted, not only
the fields a result happens to pass through. Stack-scoped tools also mask the stack's own values
(at least 8 characters). Read tools get the string layers on DockHand's free text; content they
exist to return (`Config.Env` under `redact_env=false`, names) is unchanged. DockHand bodies here
are the invented fixtures of the operator, destructive and read tests, with the secrets added.
"""

import json
import logging
import re
from io import StringIO
from typing import Any, Final

import anyio
import pytest
import respx
from conftest import DOCKHAND_URL, ENV, IDS, SetEnv, fake_secret, load_fixture, mcp_client
from test_destructive_tools import CASES as DESTRUCTIVE_CASES
from test_destructive_tools import call
from test_operation_output import (
    BEARER,
    KEYED,
    LEAKS,
    MARKERS,
    PAIR,
    TEXT,
    TOKEN,
    URL_PASS,
    URL_USER,
    assert_redacted,
)
from test_operator_tools import CASES as OPERATOR_CASES
from test_operator_tools import (
    NEW_COMPOSE,
    Route,
    Seq,
    Sse,
    containers_without_shop,
    env_raw,
    mount,
    stack_list_without_shop,
)
from test_read_tools import CASES as READ_CASES
from test_read_tools import call as read_call

from dockhand_mcp import logging as dm_logging
from dockhand_mcp.client import redaction
from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.config import load_settings
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.logging import JsonFormatter, redact
from dockhand_mcp.tools.registry import REGISTRY
from dockhand_mcp.transport.app import create_app

JOB_STATUS: Final = ("GET", "/api/jobs/{id}")
E: Final = {"environment_id": ENV}
S: Final = {**E, "stack": "shop"}
WEB: Final = IDS["CID_WEB"]

# A stack's own value, long enough to be masked, and a second one a write introduces.
VALUE: Final = fake_secret("stack-value-" + "v" * 8)
NEW_VALUE: Final = fake_secret("new-value-" + "n" * 8)
STACK_ENV: Final = f"# shop settings\nTZ=UTC\nAPI_HOST={VALUE}\n"


# --- which tools answer synchronously: from the registry --------------------------------------

# Job and stream tools (issue #9) poll `GET /api/jobs/{id}`. `dockhand_prune` does too, for its
# image scope; every other scope answers synchronously, and that is the scope used here.
JOB_OR_STREAM: Final = {
    t.name for t in REGISTRY.all() if JOB_STATUS in t.endpoints and t.name != "dockhand_prune"
}
SYNC_TOOLS: Final = sorted(
    t.name
    for t in REGISTRY.all()
    if any(method != "GET" for method, _ in t.endpoints) and t.name not in JOB_OR_STREAM
)


def test_the_synchronous_tool_list_comes_from_the_registry() -> None:
    # Never vacuous: 26 operator, 8 destructive and the 2 read-tier validators.
    assert len(SYNC_TOOLS) == 36
    assert {"dockhand_rename_container", "dockhand_validate_stack_compose"} <= set(SYNC_TOOLS)
    assert not set(SYNC_TOOLS) & JOB_OR_STREAM


def leaky_answer(body: Any) -> Any:
    """DockHand's answer with the secrets in its message fields and in one other field."""
    if not isinstance(body, dict):
        return body
    return {
        **body,
        "message": TEXT,
        "output": TEXT,
        "details": {"hint": TEXT},
        "note": TEXT,
        "token": KEYED,
    }


def leaky_route(route: Route) -> Route:
    method, path, body = route
    if isinstance(body, Seq | Sse | str):
        return route
    if method != "GET":
        return (method, path, leaky_answer(body))
    if path == "/api/containers" and isinstance(body, list):
        # DockHand's status strings, which lifecycle tools pass on after the action.
        return (method, path, [{**item, "status": TEXT} for item in body])
    return route


def sync_case(tool: str) -> tuple[dict[str, Any], list[Route]]:
    if tool in DESTRUCTIVE_CASES:
        case = DESTRUCTIVE_CASES[tool]
        return {**case.args, "confirm": True}, [*case.reads, case.write, *case.after]
    if tool in OPERATOR_CASES:
        args, routes = OPERATOR_CASES[tool]
        return dict(args), list(routes)
    args, routes = READ_CASES[tool]
    return dict(args), list(routes)


@pytest.fixture
def admin(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_MCP_CONFIRM_MODE="param")


def outcome(envelope: Envelope) -> tuple[bool, str | None]:
    return envelope.ok, envelope.error.code if envelope.error is not None else None


@pytest.mark.parametrize("tool", SYNC_TOOLS)
async def test_every_synchronous_answer_is_redacted(
    tool: str, dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes = sync_case(tool)
    mount(dockhand, routes)
    clean = await call(tool, args)
    dockhand.clear()
    mount(dockhand, [leaky_route(r) for r in routes])
    leaky = await call(tool, args)
    assert_redacted(leaky)
    # Redaction never changes what the tool reports as success or failure.
    assert outcome(leaky) == outcome(clean)


async def test_a_stored_detached_result_is_redacted_when_read_back(
    dockhand: respx.MockRouter, admin: None
) -> None:
    tool = "dockhand_clear_pending_updates"
    args, routes = OPERATOR_CASES[tool]
    mount(dockhand, [leaky_route(r) for r in routes])
    app = create_app(load_settings())
    async with mcp_client(app) as c:
        started = await c.call_tool(tool, {**args, "wait": False})
        assert started.structured_content is not None
        op_id = started.structured_content["operation"]["id"]
        for _ in range(100):
            later = await c.call_tool("dockhand_get_operation", {"op_id": op_id})
            assert later.structured_content is not None
            if later.structured_content["operation"]["status"] != "running":
                break
            await anyio.sleep(0.01)
    envelope = Envelope.model_validate(later.structured_content)
    assert envelope.ok is True
    text = assert_redacted(envelope)
    for marker in MARKERS:
        assert marker in text
    # `note` is no free-text field: only the answer's own redaction, in the client, covers it.
    assert envelope.data["result"]["result"]["note"] == redaction.PLAIN(TEXT)


# --- stack-scoped tools also mask the stack's values ------------------------------------------


def echoing(body: Any, *values: str) -> Any:
    return {**body, "output": " ".join(f"used {v}" for v in values), "note": values[0]}


def env_raw_routes(*contents: str) -> Route:
    bodies = tuple(env_raw(c) for c in contents)
    return ("GET", "/api/stacks/shop/env/raw", Seq(bodies) if len(bodies) > 1 else bodies[0])


STACK_ENV_VARS: Final[Route] = ("GET", "/api/stacks/shop/env", load_fixture("stacks", "env"))
COMPOSE_BACK: Final[Route] = (
    "GET",
    "/api/stacks/shop/compose",
    {**load_fixture("stacks", "compose"), "content": NEW_COMPOSE},
)
OLD_COMPOSE_BODY: Final[Route] = (
    "GET",
    "/api/stacks/shop/compose",
    load_fixture("stacks", "compose"),
)
NEW_STACK_ENV: Final = f"# shop settings\nTZ=UTC\nAPI_HOST={NEW_VALUE}\n"

# tool -> (arguments, routes, the values its answer must not show)
STACK_CASES: Final[dict[str, tuple[dict[str, Any], list[Route], tuple[str, ...]]]] = {
    "dockhand_update_stack_compose": (
        {**S, "content": NEW_COMPOSE, "redeploy": True},
        [
            ("GET", "/api/stacks", load_fixture("stacks", "list")),
            env_raw_routes(STACK_ENV),
            STACK_ENV_VARS,
            ("POST", "/api/stacks/shop/validate", load_fixture("stacks", "validate")),
            ("PUT", "/api/stacks/shop/compose", echoing({"success": True}, VALUE)),
            COMPOSE_BACK,
        ],
        (VALUE,),
    ),
    "dockhand_update_stack_env_raw": (
        {**S, "content": NEW_STACK_ENV},
        [
            ("GET", "/api/stacks", load_fixture("stacks", "list")),
            env_raw_routes(STACK_ENV, NEW_STACK_ENV),
            STACK_ENV_VARS,
            OLD_COMPOSE_BODY,
            ("PUT", "/api/stacks/shop/env/raw", echoing({"success": True}, VALUE, NEW_VALUE)),
        ],
        (VALUE, NEW_VALUE),
    ),
    "dockhand_modify_stack_env": (
        {**S, "set_vars": {"API_HOST": NEW_VALUE}},
        [
            ("GET", "/api/stacks", load_fixture("stacks", "list")),
            env_raw_routes(STACK_ENV, NEW_STACK_ENV),
            STACK_ENV_VARS,
            OLD_COMPOSE_BODY,
            ("PUT", "/api/stacks/shop/env/raw", echoing({"success": True}, VALUE, NEW_VALUE)),
        ],
        (VALUE, NEW_VALUE),
    ),
    "dockhand_create_stack": (
        {
            **E,
            "name": "shop",
            "compose": NEW_COMPOSE,
            "env_vars": [{"key": "API_HOST", "value": VALUE}],
        },
        [
            stack_list_without_shop(),
            containers_without_shop(),
            (
                "POST",
                "/api/stacks/shop/validate",
                echoing(load_fixture("stacks", "validate"), VALUE),
            ),
            ("POST", "/api/stacks", echoing(load_fixture("stacks", "create"), VALUE)),
            COMPOSE_BACK,
            (
                "GET",
                "/api/stacks/shop/env",
                {"variables": [{"key": "API_HOST", "value": VALUE, "isSecret": False}]},
            ),
        ],
        (VALUE,),
    ),
    "dockhand_delete_stack": (
        {**S, "confirm": True},
        [
            ("GET", "/api/stacks", load_fixture("stacks", "list")),
            ("GET", "/api/stacks/shop/delete-preview", load_fixture("stacks", "delete-preview")),
            env_raw_routes(STACK_ENV),
            STACK_ENV_VARS,
            ("DELETE", "/api/stacks/shop", echoing({"success": True}, VALUE)),
        ],
        (VALUE,),
    ),
    "dockhand_validate_stack_compose": (
        {**S, "compose": NEW_COMPOSE, "env_vars": {"API_HOST": VALUE}},
        [
            (
                "POST",
                "/api/stacks/shop/validate",
                {
                    **load_fixture("stacks", "validate"),
                    "findings": [{"severity": "warn", "message": f"API_HOST is {VALUE}"}],
                },
            )
        ],
        (VALUE,),
    ),
}


@pytest.mark.parametrize("tool", sorted(STACK_CASES))
async def test_stack_scoped_answers_mask_the_stack_values(
    tool: str, dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes, values = STACK_CASES[tool]
    mount(dockhand, routes)
    envelope = await call(tool, args)
    assert envelope.ok is True, envelope.error
    text = json.dumps(envelope.model_dump(mode="json"))
    for value in values:
        assert value not in text
    assert REDACTED in text


async def test_a_stack_tools_error_body_masks_the_stack_values_and_url_credentials(
    dockhand: respx.MockRouter, admin: None
) -> None:
    args, routes, _ = STACK_CASES["dockhand_update_stack_compose"]
    mount(dockhand, [r for r in routes if r[0] != "PUT"])
    body = {"error": f"cannot pull https://{URL_USER}:{URL_PASS}@registry.example.test for {VALUE}"}
    dockhand.put("/api/stacks/shop/compose").respond(400, json=body)
    envelope = await call("dockhand_update_stack_compose", args)
    assert envelope.error is not None and envelope.error.detail is not None
    assert envelope.error.code == "dockhand_http_error"
    detail = envelope.error.detail
    assert VALUE not in detail and URL_PASS not in detail and f"{URL_USER}:" not in detail
    assert f"https://{REDACTED}@registry.example.test" in detail


# --- read tools: DockHand free text -----------------------------------------------------------


async def test_read_tools_redact_dockhand_status_text_but_not_names(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    name = "dh_" + "cache"  # a legitimate container name shaped like the token prefix
    items = load_fixture("containers", "list")
    items[0] = {**items[0], "name": name, "status": TEXT}
    dockhand.get("/api/containers").respond(json=items)
    envelope, _, _ = await read_call("dockhand_list_containers", E)
    assert_redacted(envelope)
    listed = {item["name"]: item for item in envelope.data["items"]}
    assert name in listed
    assert "password=***" in listed[name]["status"]


def leaky_inspect(env: list[str]) -> dict[str, Any]:
    inspect = load_fixture("containers", "inspect")
    state = {
        **inspect.get("State", {}),
        "Error": TEXT,
        "Health": {"Status": "unhealthy", "Log": [{"ExitCode": 1, "Output": TEXT}]},
    }
    return {**inspect, "State": state, "Config": {**inspect["Config"], "Env": env}}


@pytest.mark.parametrize("redact_env", [True, False])
async def test_container_state_text_is_redacted_and_redact_env_is_unchanged(
    redact_env: bool, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    env = [f"DB_PASSWORD={PAIR}", f"DSN=https://{URL_USER}:{URL_PASS}@db.example.test", "TZ=UTC"]
    dockhand.get("/api/containers").respond(json=load_fixture("containers", "list"))
    dockhand.get(f"/api/containers/{WEB}").respond(json=leaky_inspect(env))
    envelope, _, _ = await read_call(
        "dockhand_get_container", {**E, "ref": "web", "redact_env": redact_env}
    )
    state = envelope.data["State"]
    for text in (state["Error"], state["Health"]["Log"][0]["Output"]):
        for leak in (TOKEN, BEARER, URL_PASS, PAIR):
            assert leak not in text
    expected = (
        ["DB_PASSWORD=" + REDACTED, "DSN=" + REDACTED, "TZ=" + REDACTED] if redact_env else env
    )
    assert envelope.data["Config"]["Env"] == expected


# --- the client: answers and error bodies -----------------------------------------------------


@pytest.fixture
def client() -> DockhandClient:
    return DockhandClient(DOCKHAND_URL, retry_attempts=1)


async def test_a_bound_redactor_masks_answers_but_never_the_job_id(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    job_id = "4c3b2a19-" + VALUE + "-9b5a"
    dockhand.post("/api/x").respond(json={"jobId": job_id, "note": f"{VALUE} {TEXT}"})
    with redaction.redacting(redaction.OutputRedactor.for_values([VALUE])):
        answer = await client.post_json("/api/x")
    assert answer["jobId"] == job_id
    assert VALUE not in answer["note"]
    for leak in LEAKS:
        assert leak not in answer["note"]


async def test_error_bodies_get_the_structured_and_url_layers(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    body = {"error": f"https://{URL_USER}:{URL_PASS}@git.example.test failed", "password": PAIR}
    dockhand.post("/api/x").respond(400, json=body)
    with pytest.raises(DockhandError) as caught:
        await client.post_json("/api/x")
    excerpt = caught.value.body_excerpt
    assert excerpt is not None
    assert URL_PASS not in excerpt and PAIR not in excerpt
    assert f"https://{REDACTED}@git.example.test" in excerpt


# --- logs: URL credentials, one shared implementation -----------------------------------------


def test_log_redaction_masks_url_credentials() -> None:
    text = f"cloning https://{URL_USER}:{URL_PASS}@git.example.test/repo.git as ops@example.test"
    assert redact(text) == (
        f"cloning https://{REDACTED}@git.example.test/repo.git as ops@example.test"
    )
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("dockhand_mcp.test_url_credentials")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.warning(text, extra={"source": text})
    finally:
        logger.removeHandler(handler)
    line = stream.getvalue()
    assert URL_PASS not in line and f"{URL_USER}:" not in line
    assert json.loads(line)["source"].startswith(f"cloning https://{REDACTED}@git.example.test")


def test_log_and_output_redaction_share_one_url_implementation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    real = getattr(dm_logging, "redact_url_credentials", None)

    def spy(text: str) -> str:
        seen.append(text)
        return real(text) if real is not None else text

    monkeypatch.setattr(dm_logging, "redact_url_credentials", spy, raising=False)
    redact("log line")
    redaction.PLAIN("operation output")
    redaction.PLAIN.text("progress line")
    assert seen == ["log line", "operation output", "progress line"]
    # And `client/redaction.py` keeps no URL pattern of its own.
    own = [v for v in vars(redaction).values() if isinstance(v, re.Pattern)]
    assert not [p for p in own if "://" in p.pattern]
