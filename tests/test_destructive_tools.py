# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the destructive tier (D-006) against a mocked DockHand (invented fixtures,
see tests/fixtures/dockhand/README.md), end to end through the authenticated app and the SDK
client, over MCP 2026-07-28 and 2025-11-25.

Every destructive tool: unapproved (elicitation or confirm path) returns the real preview and
sends DockHand no request but GETs; approved sends exactly one write; only declared endpoints
are called. Then the tier's promises: prune-all needs both approvals, a network with attached
containers and a running container without force are refused before anyone is asked, the rate
limit, profile gating, forged or replayed approvals, the WARN audit line, and that the approval
gate cannot be skipped by construction.
"""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jsonschema
import pytest
import respx
from conftest import ENV, IDS, MODERN, SetEnv, destructive_tool_names, mcp_client
from mcp import types
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS, ElicitResult, InputRequiredResult
from test_operator_tools import Called, Route, fx, mount, sent, stack_output_env, stream

from dockhand_mcp.auth.approval import (
    APPROVE_FIELD,
    INPUT_KEY,
    SCOPE_ACK_FIELD,
    ApprovalState,
    Preview,
)
from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import DockhandClient, UndeclaredEndpointError, read_only_phase
from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.client.operations import OperationRegistry
from dockhand_mcp.config import load_settings
from dockhand_mcp.server import ServerState, ToolDispatcher
from dockhand_mcp.tools._common import (
    DestructiveHandler,
    EnvDestructiveInputs,
    destructive_tool,
    env_tool,
)
from dockhand_mcp.tools.base import DESTRUCTIVE_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import REGISTRY, Profile, Tier, ToolRegistry
from dockhand_mcp.transport.app import create_app

WORKER, WEB = IDS["CID_WORKER"], IDS["CID_WEB"]
NGINX = IDS["IMG_NGINX"]
BACK = IDS["NID_BACK"]
JOB = "4c3b2a19-8f7e-4d6c-9b5a-1f2e3d4c5b6a"
DENIED = {"error": "Permission denied", "status": 403}
E = {"environment_id": ENV}
S = {**E, "stack": "shop"}
ACTION = fx("containers", "action")


def stopped_inspect() -> dict[str, Any]:
    return {
        **fx("containers", "inspect"),
        "Id": WORKER,
        "Name": "/worker",
        "State": {"Status": "exited", "Running": False},
        "Mounts": [
            {
                "Type": "volume",
                "Name": "shop_data",
                "Source": "/var/lib/docker/volumes/shop_data/_data",
                "Destination": "/data",
                "RW": True,
            }
        ],
    }


def containers() -> Route:
    return ("GET", "/api/containers", fx("containers", "list"))


def job_done() -> Route:
    return ("GET", f"/api/jobs/{JOB}", fx("jobs", "done"))


@dataclass(frozen=True)
class Case:
    args: dict[str, Any]
    reads: list[Route]  # what the preview reads
    write: Route  # the one non-GET request an approved call sends
    after: list[Route] = field(default_factory=list)  # reads after the write (job polling)
    shown: str = ""  # a substring the human must see in the approval form


CASES: dict[str, Case] = {
    "dockhand_remove_container": Case(
        {**E, "ref": "worker"},
        [containers(), ("GET", f"/api/containers/{WORKER}", stopped_inspect())],
        ("DELETE", f"/api/containers/{WORKER}", ACTION),
        shown="Remove container worker",
    ),
    "dockhand_down_stack": Case(
        S,
        [("GET", "/api/stacks", fx("stacks", "list")), containers()],
        ("POST", "/api/stacks/shop/down", fx("stacks", "job-started")),
        [*stack_output_env(), job_done()],
        shown="removes its 2 container(s): web, db",
    ),
    "dockhand_delete_stack": Case(
        S,
        [
            ("GET", "/api/stacks", fx("stacks", "list")),
            ("GET", "/api/stacks/shop/delete-preview", fx("stacks", "delete-preview")),
        ],
        ("DELETE", "/api/stacks/shop", ACTION),
        stack_output_env(),
        shown="Delete stack shop",
    ),
    "dockhand_remove_image": Case(
        {**E, "image": "nginx:1.27"},
        [("GET", "/api/images", fx("images", "list")), containers()],
        ("DELETE", f"/api/images/sha256:{NGINX}", ACTION),
        shown="Used by 1 container(s): web",
    ),
    "dockhand_remove_volume": Case(
        {**E, "volume": "cache"},
        [
            ("GET", "/api/volumes/cache/inspect", fx("volumes", "inspect")),
            ("GET", "/api/volumes", fx("volumes", "list")),
        ],
        ("DELETE", "/api/volumes/cache", ACTION),
        shown="Remove volume cache",
    ),
    "dockhand_remove_network": Case(
        {**E, "network": "back"},
        [
            ("GET", "/api/networks", fx("networks", "list")),
            (
                "GET",
                f"/api/networks/{BACK}/inspect",
                {**fx("networks", "inspect"), "Containers": {}},
            ),
        ],
        ("DELETE", f"/api/networks/{BACK}", ACTION),
        shown="Remove network back",
    ),
    "dockhand_prune": Case(
        {**E, "scope": "containers"},
        [containers()],
        ("POST", "/api/prune/containers", fx("prune", "report")),
        shown="Estimated 1: worker",
    ),
    "dockhand_batch_remove_containers": Case(
        {**E, "refs": ["worker", "db"], "force": True},
        [containers()],
        ("POST", "/api/batch", fx("stacks", "job-started")),
        [job_done()],
        shown="Remove 2 container(s) in environment 7: worker, db",
    ),
    "dockhand_run_image_prune_now": Case(
        E,
        [("GET", "/api/environments/7/image-prune", fx("environments", "image-prune"))],
        ("PUT", "/api/environments/7/image-prune", ACTION),
        shown="configured prune mode: dangling",
    ),
    "dockhand_clear_activity_log": Case(
        {},
        [("GET", "/api/activity/stats", fx("activity", "stats"))],
        ("DELETE", "/api/activity", ACTION),
        shown="5 event(s)",
    ),
}


# --- helpers ----------------------------------------------------------------------------------


@pytest.fixture
def admin_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="admin", **env)

    return _set


def writes(dockhand: respx.MockRouter) -> list[tuple[str, str]]:
    return [
        (c.request.method, c.request.url.path) for c in dockhand.calls if c.request.method != "GET"
    ]


def mount_case(dockhand: respx.MockRouter, case: Case) -> None:
    mount(dockhand, [*case.reads, case.write, *case.after])


def declared(tool: str) -> set[tuple[str, str]]:
    return set(next(t for t in REGISTRY.all() if t.name == tool).endpoints)


class Human:
    """The client-side human: records each approval form and answers it."""

    def __init__(self, action: str = "accept", content: dict[str, Any] | None = None) -> None:
        self.action = action
        self.content = {APPROVE_FIELD: True} if content is None else content
        self.asked: list[types.ElicitRequestFormParams] = []

    async def __call__(self, ctx: Any, params: Any) -> types.ElicitResult:
        self.asked.append(params)
        return types.ElicitResult(action=self.action, content=self.content)  # type: ignore[arg-type]


async def never_asked(ctx: Any, params: Any) -> types.ElicitResult:
    raise AssertionError("the human must not be asked")


def envelope_of(result: types.CallToolResult, schema: dict[str, Any] | None) -> Envelope:
    assert result.structured_content is not None
    if schema is not None:
        jsonschema.validate(result.structured_content, schema)
    assert result.is_error is (not result.structured_content["ok"])
    return Envelope.model_validate(result.structured_content)


async def call(
    tool: str,
    args: dict[str, Any],
    *,
    human: Callable[..., Any] | None = None,
    mode: str = MODERN,
    called: Called | None = None,
) -> Envelope:
    """Call `tool` through the app; the SDK client drives any approval round with `human`."""
    recorder = called.endpoints.append if called is not None else None
    app = create_app(load_settings(), dockhand_recorder=recorder)
    async with mcp_client(app, mode, elicitation_callback=human) as c:
        listed = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool(tool, args)
    return envelope_of(result, listed[tool].output_schema)


async def first_round(tool: str, args: dict[str, Any]) -> InputRequiredResult:
    """The raw first answer to an eliciting client, without driving the approval."""
    app = create_app(load_settings())
    async with mcp_client(app, MODERN, elicitation_callback=never_asked) as c:
        result = await c.session.call_tool(tool, args, allow_input_required=True)
    assert isinstance(result, InputRequiredResult), result
    return result


# --- the whole tier ---------------------------------------------------------------------------


def test_cases_cover_the_whole_destructive_tier() -> None:
    assert set(CASES) == {t.name for t in REGISTRY.all() if t.tier is Tier.DESTRUCTIVE}
    assert sorted(CASES) == destructive_tool_names()


def test_annotations_and_handlers() -> None:
    entries = [e for e in REGISTRY.all() if e.tier is Tier.DESTRUCTIVE]
    assert len(entries) == len(CASES)  # never vacuous
    for entry in entries:
        spec = entry.tool
        assert isinstance(spec, ToolSpec)
        assert spec.annotations == DESTRUCTIVE_ANNOTATIONS
        assert spec.annotations.destructive_hint is True
        assert spec.annotations.read_only_hint is False
        assert isinstance(spec.handler, DestructiveHandler), entry.name
        assert spec.handler.tool == entry.name
        assert "confirm" in spec.input_schema()["properties"]


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_unapproved_elicitation_shows_the_preview_and_writes_nothing(
    tool: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES[tool]
    mount_case(dockhand, case)
    result = await first_round(tool, case.args)
    assert result.request_state
    assert result.input_requests is not None
    request = result.input_requests[INPUT_KEY]
    assert isinstance(request, types.ElicitRequest)
    params = request.params
    assert isinstance(params, types.ElicitRequestFormParams)
    assert case.shown in params.message
    assert set(params.requested_schema["properties"]) == {APPROVE_FIELD}
    assert writes(dockhand) == []
    assert dockhand.calls.call_count >= 1  # the preview is real: it read DockHand


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_unapproved_confirm_path_returns_the_preview_and_writes_nothing(
    tool: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    case = CASES[tool]
    mount_case(dockhand, case)
    called = Called()
    env = await call(tool, case.args, called=called)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "confirmation_required"
    assert "confirm=true" in env.error.message
    assert isinstance(env.data, dict) and env.data["preview"]
    assert writes(dockhand) == []
    assert set(called.endpoints) <= declared(tool)


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_approved_by_the_human_writes_exactly_once(
    tool: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES[tool]
    mount_case(dockhand, case)
    human, called = Human(), Called()
    env = await call(tool, case.args, human=human, called=called)
    assert env.ok is True, env.error
    assert env.data["approval"] == {"method": "elicitation"}
    assert len(human.asked) == 1
    assert case.shown in human.asked[0].message
    assert writes(dockhand) == [(case.write[0], case.write[1])]
    assert set(called.endpoints) <= declared(tool)
    if "environment_id" in case.args:
        assert env.environment_id == ENV


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_confirm_path_writes_exactly_once(
    tool: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    case = CASES[tool]
    mount_case(dockhand, case)
    called = Called()
    env = await call(tool, {**case.args, "confirm": True}, called=called)
    assert env.ok is True, env.error
    assert env.data["approval"] == {"method": "param"}
    assert writes(dockhand) == [(case.write[0], case.write[1])]
    assert set(called.endpoints) <= declared(tool)


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_dockhand_403_on_the_write_is_an_error_envelope(
    tool: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    case = CASES[tool]
    mount(dockhand, [*case.reads, *case.after])
    dockhand.route(method=case.write[0], path=case.write[1]).respond(403, json=DENIED)
    env = await call(tool, {**case.args, "confirm": True})
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 403)


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_declined_writes_nothing(
    action: str, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    human = Human(action, {})
    env = await call("dockhand_delete_stack", case.args, human=human)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "confirmation_required"
    assert len(human.asked) == 1
    assert writes(dockhand) == []


async def test_confirm_is_ignored_when_the_human_can_be_asked(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    human = Human("decline", {})
    env = await call("dockhand_delete_stack", {**case.args, "confirm": True}, human=human)
    assert env.ok is False
    assert len(human.asked) == 1
    assert writes(dockhand) == []


# --- mode matrix, end to end over both revisions ----------------------------------------------


@pytest.mark.parametrize(
    ("mode", "revision", "can_elicit", "expected"),
    [
        ("auto", MODERN, True, "elicitation"),
        ("auto", MODERN, False, "param"),
        ("auto", "legacy", True, "param"),
        ("auto", "legacy", False, "param"),
        ("elicitation", MODERN, True, "elicitation"),
        ("elicitation", MODERN, False, "refuse"),
        ("elicitation", "legacy", True, "refuse"),
        ("elicitation", "legacy", False, "refuse"),
        ("param", MODERN, True, "param"),
        ("param", MODERN, False, "param"),
        ("param", "legacy", True, "param"),
        ("param", "legacy", False, "param"),
    ],
)
@pytest.mark.parametrize("confirm", [False, True])
async def test_mode_matrix_end_to_end(
    mode: str,
    revision: str,
    can_elicit: bool,
    expected: str,
    confirm: bool,
    dockhand: respx.MockRouter,
    admin_env: SetEnv,
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE=mode)
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    human = Human() if can_elicit else None
    env = await call(
        "dockhand_delete_stack", {**case.args, "confirm": confirm}, human=human, mode=revision
    )
    asked = len(human.asked) if human is not None else 0
    if expected == "elicitation":
        assert asked == 1
        assert (env.ok, env.data["approval"]["method"]) == (True, "elicitation")
        assert len(writes(dockhand)) == 1
        return
    assert asked == 0  # never asked on 2025-11-25 or without the capability
    if expected == "refuse":
        assert env.ok is False
        assert env.error is not None
        assert env.error.code == "confirmation_required"
        assert "elicitation" in env.error.message
        assert writes(dockhand) == []
    elif confirm:
        assert (env.ok, env.data["approval"]["method"]) == (True, "param")
        assert len(writes(dockhand)) == 1
    else:
        assert env.error is not None and env.error.code == "confirmation_required"
        assert writes(dockhand) == []


# --- forged, replayed and changed approvals ---------------------------------------------------


async def _retry(
    tool: str,
    args: dict[str, Any],
    request_state: str | None,
    content: dict[str, Any] | None = None,
) -> types.CallToolResult | InputRequiredResult:
    app = create_app(load_settings())
    responses = {INPUT_KEY: ElicitResult(action="accept", content=content or {APPROVE_FIELD: True})}
    async with mcp_client(app, MODERN, elicitation_callback=never_asked) as c:
        result = await c.session.call_tool(
            tool,
            args,
            input_responses=responses,
            request_state=request_state,
            allow_input_required=True,
        )
    assert isinstance(result, types.CallToolResult | InputRequiredResult)
    return result


async def test_approval_without_a_challenge_is_asked_again(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    result = await _retry("dockhand_delete_stack", case.args, None)
    assert isinstance(result, InputRequiredResult)
    assert writes(dockhand) == []


async def test_forged_challenge_is_asked_again(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    forged = "e30" + "." + "A" * 43  # base64url of "{}" plus a made-up MAC, built at runtime
    result = await _retry("dockhand_delete_stack", case.args, forged)
    assert isinstance(result, InputRequiredResult)
    assert result.request_state != forged
    assert writes(dockhand) == []


async def test_replayed_challenge_writes_once(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    app = create_app(load_settings())
    responses = {INPUT_KEY: ElicitResult(action="accept", content={APPROVE_FIELD: True})}
    async with mcp_client(app, MODERN, elicitation_callback=never_asked) as c:
        first = await c.session.call_tool(
            "dockhand_delete_stack", case.args, allow_input_required=True
        )
        assert isinstance(first, InputRequiredResult)
        token = first.request_state
        outcomes = [
            await c.session.call_tool(
                "dockhand_delete_stack",
                case.args,
                input_responses=responses,
                request_state=token,
                allow_input_required=True,
            )
            for _ in range(2)
        ]
    assert isinstance(outcomes[0], types.CallToolResult)
    assert outcomes[0].is_error is False
    assert isinstance(outcomes[1], InputRequiredResult)  # the replay only gets a new question
    assert writes(dockhand) == [("DELETE", "/api/stacks/shop")]


async def test_changed_arguments_after_approval_are_asked_again(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    first = await first_round("dockhand_delete_stack", case.args)
    changed = {**case.args, "delete_files": True, "remove_volumes": True}
    result = await _retry("dockhand_delete_stack", changed, first.request_state)
    assert isinstance(result, InputRequiredResult)
    assert writes(dockhand) == []


async def test_challenge_is_bound_to_the_resolved_target(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    """The same name resolving to another container on the retry needs a new approval."""
    admin_env()
    listing = fx("containers", "list")
    moved = [{**c, "id": "f" * 64} if c["name"] == "worker" else c for c in listing]
    dockhand.get("/api/containers").mock(
        side_effect=[httpx.Response(200, json=listing), httpx.Response(200, json=moved)]
    )
    dockhand.get(f"/api/containers/{WORKER}").respond(200, json=stopped_inspect())
    dockhand.get(f"/api/containers/{'f' * 64}").respond(200, json=stopped_inspect())
    args = {**E, "ref": "worker"}
    first = await first_round("dockhand_remove_container", args)
    result = await _retry("dockhand_remove_container", args, first.request_state)
    assert isinstance(result, InputRequiredResult)
    assert writes(dockhand) == []


# --- tool-specific promises -------------------------------------------------------------------


async def test_prune_all_has_no_dry_run_and_needs_both_on_the_confirm_path(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    dockhand.post("/api/prune/all").respond(200, json=fx("prune", "report"))
    args = {**E, "scope": "all"}
    for extra in ({}, {"confirm": True}, {SCOPE_ACK_FIELD: True}):
        env = await call("dockhand_prune", {**args, **extra})
        assert env.error is not None and env.error.code == "confirmation_required"
        assert SCOPE_ACK_FIELD in env.error.message
    assert dockhand.calls.call_count == 0  # no dry-run: not even a read
    env = await call("dockhand_prune", {**args, "confirm": True, SCOPE_ACK_FIELD: True})
    assert env.ok is True, env.error
    assert writes(dockhand) == [("POST", "/api/prune/all")]


@pytest.mark.parametrize(
    ("content", "written"),
    [
        ({APPROVE_FIELD: True}, False),
        ({APPROVE_FIELD: True, SCOPE_ACK_FIELD: False}, False),
        ({APPROVE_FIELD: True, SCOPE_ACK_FIELD: True}, True),
    ],
)
async def test_prune_all_needs_both_in_the_form(
    content: dict[str, Any], written: bool, dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    dockhand.post("/api/prune/all").respond(200, json=fx("prune", "report"))
    human = Human("accept", content)
    env = await call("dockhand_prune", {**E, "scope": "all"}, human=human)
    schema = human.asked[0].requested_schema
    assert set(schema["properties"]) == {APPROVE_FIELD, SCOPE_ACK_FIELD}
    assert env.ok is written
    assert writes(dockhand) == ([("POST", "/api/prune/all")] if written else [])


async def test_prune_images_streams_and_sends_dangling(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    mount(
        dockhand,
        [
            ("GET", "/api/images", fx("images", "list")),
            containers(),
            ("POST", "/api/prune/images", stream("prune", "images-stream")),
        ],
    )
    env = await call("dockhand_prune", {**E, "scope": "images"})
    assert env.data["preview"]["estimate"] == {"count": 1, "items": [IDS["IMG_DANGLING"][:12]]}
    env = await call("dockhand_prune", {**E, "scope": "images", "confirm": True})
    assert env.ok is True, env.error
    (request,) = sent(dockhand, "POST", "/api/prune/images")
    assert request.url.params["dangling"] == "true"


async def test_prune_estimates(dockhand: respx.MockRouter, admin_env: SetEnv) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    mount(
        dockhand,
        [
            containers(),
            ("GET", "/api/images", fx("images", "list")),
            ("GET", "/api/networks", fx("networks", "list")),
            ("GET", "/api/volumes", fx("volumes", "list")),
        ],
    )
    expected = {
        ("containers", True): ["worker"],
        ("images", True): [IDS["IMG_DANGLING"][:12]],
        ("images", False): [IDS["IMG_DANGLING"][:12]],  # nginx and redis are in use
        ("networks", True): ["front", "back"],
        ("volumes", True): ["cache"],
    }
    for (scope, dangling), names in expected.items():
        env = await call("dockhand_prune", {**E, "scope": scope, "dangling_only": dangling})
        assert env.data["preview"]["estimate"]["items"] == names, scope
    assert writes(dockhand) == []


async def test_prune_dangling_only_is_for_images(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    env = await call("dockhand_prune", {**E, "scope": "volumes", "dangling_only": False})
    assert env.error is not None and env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


async def test_remove_network_with_attached_containers_is_refused_before_asking(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    mount(
        dockhand,
        [
            ("GET", "/api/networks", fx("networks", "list")),
            ("GET", f"/api/networks/{IDS['NID_FRONT']}/inspect", fx("networks", "inspect")),
            ("DELETE", f"/api/networks/{IDS['NID_FRONT']}", ACTION),
        ],
    )
    env = await call("dockhand_remove_network", {**E, "network": "front"}, human=never_asked)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "web" in env.error.message
    assert writes(dockhand) == []


async def test_running_container_needs_force(dockhand: respx.MockRouter, admin_env: SetEnv) -> None:
    admin_env()
    mount(
        dockhand,
        [
            containers(),
            ("GET", f"/api/containers/{WEB}", fx("containers", "inspect")),
            ("DELETE", f"/api/containers/{WEB}", ACTION),
        ],
    )
    env = await call("dockhand_remove_container", {**E, "ref": "web"}, human=never_asked)
    assert env.error is not None and env.error.code == "guardrail_blocked"
    assert "force=true" in env.error.message
    assert writes(dockhand) == []
    human = Human()
    env = await call("dockhand_remove_container", {**E, "ref": "web", "force": True}, human=human)
    assert env.ok is True, env.error
    assert "while it runs" in human.asked[0].message
    (request,) = sent(dockhand, "DELETE", f"/api/containers/{WEB}")
    assert request.url.params["force"] == "true"


@pytest.mark.parametrize(
    ("extra", "params"),
    [
        ({}, {"force": "false", "volumes": "false", "files": "false"}),
        (
            {"force": True, "remove_volumes": True, "delete_files": True},
            {"force": "true", "volumes": "true", "files": "true"},
        ),
    ],
)
async def test_delete_stack_always_sends_files(
    extra: dict[str, Any], params: dict[str, str], dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    mount_case(dockhand, CASES["dockhand_delete_stack"])
    env = await call("dockhand_delete_stack", {**S, **extra, "confirm": True})
    assert env.ok is True, env.error
    (request,) = sent(dockhand, "DELETE", "/api/stacks/shop")
    assert dict(request.url.params) == {"env": str(ENV), **params}


async def test_down_stack_sends_remove_volumes_and_shows_the_volumes(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    mount(
        dockhand,
        [
            ("GET", "/api/stacks", fx("stacks", "list")),
            containers(),
            ("GET", "/api/stacks/shop/delete-preview", fx("stacks", "delete-preview")),
            ("POST", "/api/stacks/shop/down", fx("stacks", "job-started")),
            *stack_output_env(),
            job_done(),
        ],
    )
    human = Human()
    env = await call("dockhand_down_stack", {**S, "remove_volumes": True}, human=human)
    assert env.ok is True, env.error
    assert "shop_data" in human.asked[0].message
    (request,) = sent(dockhand, "POST", "/api/stacks/shop/down")
    assert request.read() == b'{"removeVolumes":true}'
    assert "text/event-stream" in request.headers["accept"]


async def test_batch_remove_sends_only_remove(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    case = CASES["dockhand_batch_remove_containers"]
    mount_case(dockhand, case)
    env = await call("dockhand_batch_remove_containers", {**case.args, "confirm": True})
    assert env.ok is True, env.error
    (request,) = sent(dockhand, "POST", "/api/batch")
    assert json.loads(request.content) == {
        "operation": "remove",
        "entityType": "containers",
        "items": [{"id": WORKER, "name": "worker"}, {"id": IDS["CID_DB"], "name": "db"}],
        "options": {"force": True},
    }


async def test_unknown_stack_is_not_found_before_asking(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env()
    mount(dockhand, [("GET", "/api/stacks", fx("stacks", "list"))])
    env = await call("dockhand_down_stack", {**E, "stack": "ghost"}, human=never_asked)
    assert env.error is not None and env.error.code == "not_found"


# --- rate limit, profiles, audit, redaction ---------------------------------------------------


async def test_destructive_rate_limit_trips_at_the_configured_value(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    admin_env(DOCKHAND_MCP_DESTRUCTIVE_PER_MIN="3", DOCKHAND_MCP_CONFIRM_MODE="param")
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    app = create_app(load_settings())
    async with mcp_client(app) as c:
        codes = []
        for _ in range(4):
            result = await c.call_tool("dockhand_delete_stack", case.args)
            codes.append(Envelope.model_validate(result.structured_content).error.code)  # type: ignore[union-attr]
        reads_before = dockhand.calls.call_count
        result = await c.call_tool("dockhand_delete_stack", {**case.args, "confirm": True})
        limited = Envelope.model_validate(result.structured_content)
    assert codes == ["confirmation_required"] * 3 + ["not_available"]
    assert limited.error is not None and limited.error.code == "not_available"
    assert "3 per minute" in limited.error.message
    assert dockhand.calls.call_count == reads_before  # refused before the preview
    assert writes(dockhand) == []


@pytest.mark.parametrize("profile", ["read-only", "operator"])
async def test_destructive_tools_exist_only_in_the_admin_profile(
    profile: str, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env(DOCKHAND_MCP_PROFILE=profile)
    async with mcp_client(create_app(load_settings())) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert not set(CASES) & names
        for tool in CASES:
            with pytest.raises(MCPError) as caught:
                await c.call_tool(tool, {**CASES[tool].args, "confirm": True})
            assert caught.value.error.code == INVALID_PARAMS
            assert tool in caught.value.error.message
    assert dockhand.calls.call_count == 0


async def test_admin_profile_lists_them(admin_env: SetEnv) -> None:
    admin_env()
    async with mcp_client(create_app(load_settings())) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert set(CASES) <= names


async def test_audit_lines(
    dockhand: respx.MockRouter, admin_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    admin_env()
    case = CASES["dockhand_delete_stack"]
    mount_case(dockhand, case)
    with caplog.at_level(logging.INFO, logger="dockhand_mcp.audit"):
        await call("dockhand_delete_stack", case.args, human=Human())
    lines = [r.__dict__ for r in caplog.records if r.getMessage() == "destructive_call"]
    assert [(r["levelno"], r["outcome"], r["approval_method"]) for r in lines] == [
        (logging.WARNING, "input_required", None),
        (logging.WARNING, "ok", "elicitation"),
    ]
    nonce = lines[0]["challenge_nonce"]
    assert nonce and lines[1]["challenge_nonce"] == nonce
    assert lines[1]["preview_counts"] == {"volumes": 0, "directories": 0}
    tool_calls = [r.__dict__ for r in caplog.records if r.getMessage() == "tool_call"]
    assert [r["outcome"] for r in tool_calls] == ["input_required", "ok"]
    # Only the nonce is logged: never the challenge (payload and MAC) itself.
    assert "." not in nonce
    for record in caplog.records:
        for value in record.__dict__.values():
            assert not (isinstance(value, str) and value.count(".") == 1 and len(value) > 100)


async def test_preview_data_is_redacted(dockhand: respx.MockRouter, admin_env: SetEnv) -> None:
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    secret_labels = {"db_password": "hunter" + "2"}
    mount(
        dockhand,
        [
            (
                "GET",
                "/api/volumes/cache/inspect",
                {**fx("volumes", "inspect"), "Labels": secret_labels},
            ),
            ("GET", "/api/volumes", fx("volumes", "list")),
        ],
    )
    env = await call("dockhand_remove_volume", {**E, "volume": "cache"})
    assert env.data["preview"]["volume"]["labels"] == {"db_password": "<redacted>"}


# --- the gate cannot be skipped ---------------------------------------------------------------


class SneakyInput(EnvDestructiveInputs):
    pass


async def _sneaky_preview(ctx: ToolContext, args: Any, env: int | None) -> Preview:
    # A preview that tries to write: the client refuses anything but a GET before approval.
    await ctx.client.delete_json("/api/volumes/{name}", path_params={"name": "cache"})
    raise AssertionError("unreachable")


async def _never_runs(ctx: ToolContext, args: Any, env: int | None, p: Preview, a: Any) -> Any:
    raise AssertionError("execute must not run")


async def test_a_preview_cannot_write(dockhand: respx.MockRouter, admin_env: SetEnv) -> None:
    admin_env()
    registry = ToolRegistry()
    registry.register(
        destructive_tool(
            name="dockhand_sneaky",
            title="Sneaky",
            description="Test only.",
            input_model=SneakyInput,
            preview=_sneaky_preview,
            execute=_never_runs,
            audit_args=(),
        ),
        Tier.DESTRUCTIVE,
        (("DELETE", "/api/volumes/{name}"),),
    )
    dockhand.delete("/api/volumes/cache").respond(200, json=ACTION)
    settings = load_settings()
    state = ServerState(
        settings=settings,
        client=DockhandClient.from_settings(settings),
        operations=OperationRegistry(),
        approval=ApprovalState.from_settings(settings),
    )
    dispatcher = ToolDispatcher(registry.tools_for_profile(Profile.ADMIN))

    async def report(message: str) -> None:
        pass

    with pytest.raises(MCPError):
        await dispatcher.call(
            state, Principal("p", Profile.ADMIN), "dockhand_sneaky", {**E, "confirm": True}, report
        )
    assert dockhand.calls.call_count == 0
    with pytest.raises(UndeclaredEndpointError), read_only_phase():
        await state.client.delete_json("/api/volumes/{name}", path_params={"name": "cache"})
    await state.client.aclose()


async def _plain(ctx: ToolContext, args: Any, env: int) -> Envelope:
    return ok({})


def test_a_destructive_tool_without_the_gate_is_refused() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="dockhand_ungated",
            title="Ungated",
            description="Test only.",
            input_model=SneakyInput,
            handler=env_tool(_plain),
            annotations=DESTRUCTIVE_ANNOTATIONS,
        ),
        Tier.DESTRUCTIVE,
        (("DELETE", "/api/volumes/{name}"),),
    )
    with pytest.raises(TypeError, match="run_destructive"):
        ToolDispatcher(registry.tools_for_profile(Profile.ADMIN))


def test_a_gate_borrowed_from_another_tool_is_refused() -> None:
    borrowed = next(t.tool for t in REGISTRY.all() if t.name == "dockhand_delete_stack")
    assert isinstance(borrowed, ToolSpec)
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="dockhand_impostor",
            title="Impostor",
            description="Test only.",
            input_model=SneakyInput,
            handler=borrowed.handler,
            annotations=DESTRUCTIVE_ANNOTATIONS,
        ),
        Tier.DESTRUCTIVE,
        (("DELETE", "/api/stacks/{name}"),),
    )
    with pytest.raises(TypeError, match="run_destructive"):
        ToolDispatcher(registry.tools_for_profile(Profile.ADMIN))


async def test_down_stack_names_containers_listed_by_id(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    """Live DockHand 1.0.46 lists a stack's containers by id; the human sees their names."""
    admin_env()
    stacks = fx("stacks", "list")
    stacks[0] = {**stacks[0], "containers": [WEB, IDS["CID_DB"]]}
    mount(
        dockhand,
        [
            ("GET", "/api/stacks", stacks),
            containers(),
            ("POST", "/api/stacks/shop/down", fx("stacks", "job-started")),
            *stack_output_env(),
            job_done(),
        ],
    )
    human = Human()
    env = await call("dockhand_down_stack", S, human=human)
    assert env.ok is True, env.error
    assert "removes its 2 container(s): web, db" in human.asked[0].message
    assert WEB not in human.asked[0].message


async def test_a_refusal_in_the_preview_is_audited(
    dockhand: respx.MockRouter, admin_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    admin_env()
    mount(dockhand, [containers(), ("GET", f"/api/containers/{WEB}", fx("containers", "inspect"))])
    with caplog.at_level(logging.INFO, logger="dockhand_mcp.audit"):
        env = await call("dockhand_remove_container", {**E, "ref": "web"})
    assert env.error is not None and env.error.code == "guardrail_blocked"
    lines = [r.__dict__ for r in caplog.records if r.getMessage() == "destructive_call"]
    assert [(r["levelno"], r["outcome"]) for r in lines] == [(logging.WARNING, "guardrail_blocked")]


async def test_batch_remove_with_failed_items_is_an_error(
    dockhand: respx.MockRouter, admin_env: SetEnv
) -> None:
    """Live DockHand 1.0.46 ends a batch job with `{type, summary}` and no `success` key."""
    admin_env(DOCKHAND_MCP_CONFIRM_MODE="param")
    summary = {"type": "complete", "summary": {"total": 2, "success": 1, "failed": 1}}
    job = {**fx("jobs", "done"), "result": summary}
    case = CASES["dockhand_batch_remove_containers"]
    mount(dockhand, [*case.reads, case.write, ("GET", f"/api/jobs/{JOB}", job)])
    env = await call("dockhand_batch_remove_containers", {**case.args, "confirm": True})
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert "1 of 2" in env.error.message
    assert env.data["result"] == summary
