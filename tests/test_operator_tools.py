# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the operator tier against a mocked DockHand (invented fixtures, see
tests/fixtures/dockhand/README.md), end to end through the authenticated app.

Every operator tool: happy path validated against its outputSchema, DockHand 403 → error
envelope, only declared endpoints called, annotations. Then what the tier promises: compose
guardrails and DockHand validation before writes, read-back verification, the placeholder
write-back guard, `.env` edits and their recreate reminder, the batch operation limit, the
`dockhand.update=false` opt-out, and the key-based output redaction.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx
import jsonschema
import pytest
import respx
from conftest import ENV, IDS, SetEnv, fake_dh_token, load_fixture, mcp_client

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.config import load_settings
from dockhand_mcp.guardrails.secrets import MASKED, REDACTED
from dockhand_mcp.tools._common import ENV_RECREATE_WARNING
from dockhand_mcp.tools.registry import REGISTRY, Tier
from dockhand_mcp.transport.app import create_app

WEB, DB = IDS["CID_WEB"], IDS["CID_DB"]
NGINX = IDS["IMG_NGINX"]
FRONT = IDS["NID_FRONT"]
JOB = "4c3b2a19-8f7e-4d6c-9b5a-1f2e3d4c5b6a"
DENIED = {"error": "Permission denied", "status": 403}
E = {"environment_id": ENV}
S = {**E, "stack": "shop"}
GOLDEN = Path(__file__).resolve().parent / "fixtures" / "env"

OLD_COMPOSE = "services:\n  web:\n    image: nginx:1.27\n"
NEW_COMPOSE = "services:\n  web:\n    image: nginx:1.28\n    restart: unless-stopped\n"
PRIVILEGED = "services:\n  web:\n    image: nginx:1.28\n    privileged: true\n"
DATA_COMPOSE = "services:\n  web:\n    image: nginx:1.28\n    volumes: ['${DATA_DIR}:/data']\n"
OLD_ENV = "# shop settings\nTZ=UTC\n"
NEW_ENV = "# shop settings\nTZ=Europe/Paris\n"
IDEMPOTENT = {
    "dockhand_start_container",
    "dockhand_stop_container",
    "dockhand_pause_container",
    "dockhand_unpause_container",
    "dockhand_start_stack",
    "dockhand_stop_stack",
}


def fx(domain: str, name: str) -> Any:
    return load_fixture(domain, name)


@dataclass(frozen=True)
class Sse:
    events: list[Any]


@dataclass(frozen=True)
class Seq:
    bodies: tuple[Any, ...]


def stream(domain: str, name: str) -> Sse:
    return Sse(fx(domain, name)["events"])


def compose_body(content: str) -> dict[str, Any]:
    return {**fx("stacks", "compose"), "content": content}


def env_raw(content: str) -> dict[str, Any]:
    return {"content": content, "noEnvFile": False}


Route = tuple[str, str, Any]


def containers() -> Route:
    return ("GET", "/api/containers", fx("containers", "list"))


def job_done() -> Route:
    return ("GET", f"/api/jobs/{JOB}", fx("jobs", "job"))


def batch_job(**outcomes: str) -> dict[str, Any]:
    """A finished batch job in the live shape (`jobs/batch-mixed`), one outcome per container.

    `outcomes` maps a container name (`web`, `db`) to `success` or `error`.
    """
    recorded = fx("jobs", "batch-mixed")
    ids = {"web": WEB, "db": DB}
    total = len(outcomes)
    lines: list[Any] = [recorded["lines"][0]]
    for n, (name, status) in enumerate(outcomes.items(), start=1):
        item = {"type": "progress", "id": ids[name], "name": name, "current": n, "total": total}
        lines.append({"data": {**item, "status": "processing"}})
        done = {**item, "status": status}
        if status == "error":
            done["error"] = f"Container {ids[name]} is not paused"
        lines.append({"data": done})
    failed = sum(1 for s in outcomes.values() if s == "error")
    summary = {"total": total, "success": total - failed, "failed": failed}
    result = {"type": "complete", "summary": summary}
    lines.append({"data": result})
    return {**recorded, "lines": lines, "result": result}


def stack_env() -> list[Route]:
    return [("GET", "/api/stacks/shop/env", fx("stacks", "env"))]


def stack_list() -> Route:
    """The stack list every write to an existing stack checks first (`shop` is tracked there)."""
    return ("GET", "/api/stacks", fx("stacks", "list"))


def stack_list_without_shop() -> Route:
    """The stack list `dockhand_create_stack` checks first: `shop` is not in use yet (#19)."""
    return ("GET", "/api/stacks", [s for s in fx("stacks", "list") if s["name"] != "shop"])


def containers_without_shop() -> Route:
    """Every container `dockhand_create_stack` also checks: none is labelled `shop` (#21)."""
    items = [
        c
        for c in fx("containers", "list")
        if c.get("labels", {}).get("com.docker.compose.project") != "shop"
    ]
    return ("GET", "/api/containers", items)


def stack_output_env() -> list[Route]:
    """What a stack operation reads to redact the stack's own values from its output."""
    return [("GET", "/api/stacks/shop/env/raw", env_raw(OLD_ENV)), *stack_env()]


# tool -> (arguments, DockHand routes it needs)
CASES: dict[str, tuple[dict[str, Any], list[Route]]] = {
    **{
        f"dockhand_{action}_container": (
            {**E, "ref": "web"},
            [
                containers(),
                ("POST", f"/api/containers/{WEB}/{action}", fx("containers", "action")),
            ],
        )
        for action in ("start", "stop", "restart", "pause", "unpause")
    },
    "dockhand_rename_container": (
        {**E, "ref": "web", "new_name": "web-2"},
        [containers(), ("POST", f"/api/containers/{WEB}/rename", fx("containers", "action"))],
    ),
    "dockhand_update_containers": (
        {**E, "refs": ["web", "db"]},
        [
            containers(),
            ("GET", f"/api/containers/{WEB}", fx("containers", "inspect")),
            ("GET", f"/api/containers/{DB}", fx("containers", "inspect")),
            ("POST", "/api/containers/batch-update", fx("containers", "batch-update")),
        ],
    ),
    "dockhand_check_container_updates": (
        E,
        [
            ("POST", "/api/containers/check-updates", stream("containers", "check-updates-stream")),
            ("GET", "/api/containers/pending-updates", fx("containers", "pending-updates")),
        ],
    ),
    "dockhand_clear_pending_updates": (
        {**E, "ref": "web"},
        [containers(), ("DELETE", "/api/containers/pending-updates", fx("containers", "action"))],
    ),
    "dockhand_set_container_auto_update": (
        {**E, "container_name": "web", "enabled": True, "cron": "0 4 * * *"},
        [containers(), ("POST", "/api/auto-update/web", fx("containers", "auto-update-set"))],
    ),
    "dockhand_start_stack": (
        S,
        [
            stack_list(),
            *stack_output_env(),
            ("POST", "/api/stacks/shop/start", fx("stacks", "job-started")),
            job_done(),
        ],
    ),
    "dockhand_stop_stack": (
        S,
        [
            stack_list(),
            *stack_output_env(),
            ("POST", "/api/stacks/shop/stop", fx("stacks", "job-started")),
            job_done(),
        ],
    ),
    "dockhand_restart_stack": (
        {**S, "mode": "recreate"},
        [
            stack_list(),
            *stack_output_env(),
            ("POST", "/api/stacks/shop/restart", stream("stacks", "deploy-stream")),
        ],
    ),
    "dockhand_deploy_stack": (
        {**S, "pull": True},
        [
            stack_list(),
            *stack_output_env(),
            ("POST", "/api/stacks/shop/deploy", stream("stacks", "deploy-stream")),
        ],
    ),
    "dockhand_update_stack_compose": (
        {**S, "content": NEW_COMPOSE},
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", env_raw(OLD_ENV)),
            *stack_env(),
            ("POST", "/api/stacks/shop/validate", fx("stacks", "validate")),
            ("PUT", "/api/stacks/shop/compose", fx("stacks", "put-compose")),
            ("GET", "/api/stacks/shop/compose", compose_body(NEW_COMPOSE)),
        ],
    ),
    "dockhand_update_stack_env_raw": (
        {**S, "content": NEW_ENV},
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", Seq((env_raw(OLD_ENV), env_raw(NEW_ENV)))),
            *stack_env(),
            ("GET", "/api/stacks/shop/compose", compose_body(OLD_COMPOSE)),
            ("PUT", "/api/stacks/shop/env/raw", fx("stacks", "put-env-raw")),
        ],
    ),
    "dockhand_modify_stack_env": (
        {**S, "set_vars": {"TZ": "Europe/Paris"}},
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", Seq((env_raw(OLD_ENV), env_raw(NEW_ENV)))),
            *stack_env(),
            ("GET", "/api/stacks/shop/compose", compose_body(OLD_COMPOSE)),
            ("PUT", "/api/stacks/shop/env/raw", fx("stacks", "put-env-raw")),
        ],
    ),
    "dockhand_create_stack": (
        {**E, "name": "shop", "compose": NEW_COMPOSE, "env_vars": [{"key": "TZ", "value": "UTC"}]},
        [
            stack_list_without_shop(),
            containers_without_shop(),
            ("POST", "/api/stacks/shop/validate", fx("stacks", "validate")),
            ("POST", "/api/stacks", fx("stacks", "create")),
            ("GET", "/api/stacks/shop/compose", compose_body(NEW_COMPOSE)),
            *stack_env(),
        ],
    ),
    "dockhand_pull_image": (
        {**E, "image": "nginx:1.28"},
        [("POST", "/api/images/pull", stream("images", "pull-stream"))],
    ),
    "dockhand_tag_image": (
        {**E, "image": "nginx:1.27", "repo": "registry.example.test:5000/web", "tag": "stable"},
        [
            ("GET", "/api/images", fx("images", "list")),
            ("POST", f"/api/images/sha256:{NGINX}/tag", fx("images", "tag")),
        ],
    ),
    "dockhand_scan_image": (
        {**E, "image": "nginx:1.27", "scanner": "grype"},
        [
            ("POST", "/api/images/scan", stream("images", "scan-stream")),
            ("GET", "/api/images/scan", fx("images", "scan")),
        ],
    ),
    "dockhand_scan_all_images": (
        {**E, "wait": True},
        [("POST", "/api/vulnerabilities/scan-all", stream("vulnerabilities", "scan-all-stream"))],
    ),
    "dockhand_create_volume": (
        {**E, "name": "cache", "labels": {"app": "shop"}},
        [("POST", "/api/volumes", fx("volumes", "create"))],
    ),
    "dockhand_clone_volume": (
        {**E, "source": "cache", "new_name": "cache-copy"},
        [("POST", "/api/volumes/cache/clone", fx("volumes", "clone"))],
    ),
    "dockhand_create_network": (
        {**E, "name": "back", "internal": True},
        [("POST", "/api/networks", fx("networks", "create"))],
    ),
    "dockhand_connect_container_to_network": (
        {**E, "network": "front", "ref": "web"},
        [
            ("GET", "/api/networks", fx("networks", "list")),
            containers(),
            ("POST", f"/api/networks/{FRONT}/connect", fx("networks", "connect")),
        ],
    ),
    "dockhand_disconnect_container_from_network": (
        {**E, "network": "front", "ref": "web", "force": True},
        [
            ("GET", "/api/networks", fx("networks", "list")),
            containers(),
            ("POST", f"/api/networks/{FRONT}/disconnect", fx("networks", "connect")),
        ],
    ),
    "dockhand_run_schedule_now": (
        {"schedule_type": "container_update", "schedule_id": 3},
        [("POST", "/api/schedules/container_update/3/run", fx("schedules", "run"))],
    ),
    "dockhand_toggle_schedule": (
        {"schedule_type": "git_stack_sync", "schedule_id": 2},
        [("POST", "/api/schedules/git_stack_sync/2/toggle", fx("schedules", "toggle"))],
    ),
    "dockhand_cancel_job": (
        {"job_id": JOB},
        [("DELETE", f"/api/jobs/{JOB}", fx("jobs", "cancel"))],
    ),
    "dockhand_test_environment": (
        E,
        [("POST", "/api/environments/7/test", fx("environments", "test"))],
    ),
    "dockhand_sync_git_stack": (
        {"git_stack_id": 4},
        [("POST", "/api/git/stacks/4/sync", fx("git", "sync-result"))],
    ),
    "dockhand_deploy_git_stack": (
        {"git_stack_id": 4},
        [("POST", "/api/git/stacks/4/deploy", stream("git", "deploy-stream"))],
    ),
    "dockhand_sync_git_repository": (
        {"repository_id": 1},
        [("POST", "/api/git/repositories/1/sync", fx("git", "sync-result"))],
    ),
    "dockhand_deploy_git_repository": (
        {"repository_id": 1},
        [("POST", "/api/git/repositories/1/deploy", fx("git", "sync-result"))],
    ),
    "dockhand_batch_containers": (
        {**E, "operation": "restart", "refs": ["web", "db"]},
        [
            containers(),
            ("POST", "/api/batch", fx("stacks", "job-started")),
            ("GET", f"/api/jobs/{JOB}", batch_job(web="success", db="success")),
        ],
    ),
}

ENV_WRITES = {"dockhand_update_stack_env_raw", "dockhand_modify_stack_env"}
VERIFIED = ENV_WRITES | {"dockhand_update_stack_compose", "dockhand_create_stack"}


def _response(body: Any, status: int = 200) -> httpx.Response:
    if isinstance(body, Sse):
        content = b"".join(
            f"event: {e}\ndata: {json.dumps(d)}\n\n".encode() for e, d in body.events
        )
        return httpx.Response(
            status, content=content, headers={"content-type": "text/event-stream"}
        )
    if isinstance(body, str):
        return httpx.Response(status, text=body, headers={"content-type": "text/plain"})
    return httpx.Response(status, json=body)


def mount(dockhand: respx.MockRouter, routes: list[Route], status: int | None = None) -> None:
    for method, path, body in routes:
        route = dockhand.route(method=method, path=path)
        if status is not None:
            route.respond(status, json=DENIED)
        elif isinstance(body, Seq):
            route.side_effect = [_response(b) for b in body.bodies]
        else:
            route.mock(return_value=_response(body))


class Called:
    def __init__(self) -> None:
        self.endpoints: list[tuple[str, str]] = []


async def call(
    tool: str, args: dict[str, Any], called: Called | None = None
) -> tuple[Envelope, dict[str, Any]]:
    """Call `tool` through the app (operator profile). Returns (envelope, structured content)."""
    recorder = called.endpoints.append if called is not None else None
    app = create_app(load_settings(), dockhand_recorder=recorder)
    async with mcp_client(app) as c:
        listed = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool(tool, args)
    assert result.structured_content is not None
    schema = listed[tool].output_schema
    assert schema is not None
    jsonschema.validate(result.structured_content, schema)
    assert result.is_error is (not result.structured_content["ok"])
    return Envelope.model_validate(result.structured_content), result.structured_content


def declared(tool: str) -> set[tuple[str, str]]:
    return set(next(t for t in REGISTRY.all() if t.name == tool).endpoints)


def sent(dockhand: respx.MockRouter, method: str, path: str) -> list[httpx.Request]:
    return [
        c.request
        for c in dockhand.calls
        if (c.request.method, c.request.url.path) == (method, path)
    ]


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


# --- the whole tier ---------------------------------------------------------------------------


def test_cases_cover_the_whole_operator_tier() -> None:
    assert set(CASES) == {t.name for t in REGISTRY.all() if t.tier is Tier.OPERATOR}


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_happy_path(tool: str, dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    args, routes = CASES[tool]
    mount(dockhand, routes)
    called = Called()
    env, _ = await call(tool, args, called)
    assert env.ok is True, env.error
    assert env.data is not None
    expected_warnings = [ENV_RECREATE_WARNING] if tool in ENV_WRITES else None
    assert env.warnings == expected_warnings
    assert called.endpoints, "an operator tool must call DockHand"
    assert set(called.endpoints) <= declared(tool)
    if tool in VERIFIED:
        assert env.verified is True
    if "environment_id" in args:
        assert env.environment_id == ENV


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_dockhand_403_is_an_error_envelope(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args, routes = CASES[tool]
    mount(dockhand, routes, status=403)
    env, _ = await call(tool, args)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "dockhand_http_error"
    assert env.error.dockhand_status == 403


def test_annotations() -> None:
    for entry in REGISTRY.all():
        if entry.tier is not Tier.OPERATOR:
            continue
        hints = entry.tool.annotations  # type: ignore[attr-defined]
        assert hints.read_only_hint is False, entry.name
        assert hints.destructive_hint is False, entry.name
        assert hints.open_world_hint is True, entry.name
        assert hints.idempotent_hint is (entry.name in IDEMPOTENT), entry.name


@pytest.mark.parametrize(("profile", "visible"), [("read-only", False), ("operator", True)])
async def test_operator_tools_exist_only_in_their_profile(
    base_env: SetEnv, profile: str, visible: bool
) -> None:
    base_env(DOCKHAND_MCP_PROFILE=profile)
    async with mcp_client(create_app(load_settings())) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert (set(CASES) <= names) is visible
    assert bool(set(CASES) & names) is visible


# --- placeholder write-back guard -------------------------------------------------------------

PLACEHOLDER_CASES = [
    ("dockhand_update_stack_compose", lambda m: {**S, "content": f"{NEW_COMPOSE}# {m}\n"}),
    ("dockhand_update_stack_env_raw", lambda m: {**S, "content": f"DB_PASSWORD={m}\n"}),
    ("dockhand_modify_stack_env", lambda m: {**S, "set_vars": {"DB_PASSWORD": m}}),
    ("dockhand_create_stack", lambda m: {**E, "name": "shop", "compose": f"{NEW_COMPOSE}#{m}\n"}),
    (
        "dockhand_create_stack",
        lambda m: {
            **E,
            "name": "shop",
            "compose": NEW_COMPOSE,
            "env_vars": [{"key": "DB_PASSWORD", "value": m, "isSecret": True}],
        },
    ),
]


@pytest.mark.parametrize("marker", [REDACTED, MASKED])
@pytest.mark.parametrize(("tool", "make"), PLACEHOLDER_CASES)
async def test_placeholders_are_refused_before_any_request(
    tool: str, make: Any, marker: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call(tool, make(marker))
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "dockhand_modify_stack_env" in env.error.message
    assert dockhand.calls.call_count == 0


async def test_rename_targets_cannot_carry_placeholders(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call("dockhand_modify_stack_env", {**S, "rename": {"TZ": REDACTED}})
    assert env.ok is False
    assert dockhand.calls.call_count == 0


# --- compose guardrails and DockHand validation ------------------------------------------------


def compose_routes(read_back: str = PRIVILEGED, validate: Any = None) -> list[Route]:
    return [
        stack_list(),
        ("GET", "/api/stacks/shop/env/raw", env_raw(OLD_ENV)),
        *stack_env(),
        ("POST", "/api/stacks/shop/validate", validate or fx("stacks", "validate")),
        ("PUT", "/api/stacks/shop/compose", fx("stacks", "put-compose")),
        ("GET", "/api/stacks/shop/compose", compose_body(read_back)),
    ]


async def test_strict_guardrails_refuse_the_write(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes())
    env, _ = await call("dockhand_update_stack_compose", {**S, "content": PRIVILEGED})
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    guardrails = env.data["guardrails"]
    assert (guardrails["mode"], guardrails["blocked"]) == ("strict", True)
    assert [f["rule"] for f in guardrails["findings"]] == ["privileged"]
    assert "dockhand" in guardrails
    assert sent(dockhand, "PUT", "/api/stacks/shop/compose") == []


async def test_warn_mode_writes_and_reports(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env(DOCKHAND_MCP_GUARDRAILS="warn")
    mount(dockhand, compose_routes())
    env, _ = await call("dockhand_update_stack_compose", {**S, "content": PRIVILEGED})
    assert env.ok is True, env.error
    assert env.verified is True
    assert env.data["guardrails"]["blocked"] is False
    assert [f["rule"] for f in env.data["guardrails"]["findings"]] == ["privileged"]


async def test_dockhand_validator_errors_refuse_the_write(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    failing = {
        "findings": [{"ruleId": "yaml", "severity": "error", "message": "bad", "line": 2}],
        "counts": {"error": 1, "warn": 0, "info": 0},
    }
    mount(dockhand, compose_routes(NEW_COMPOSE, validate=failing))
    env, _ = await call("dockhand_update_stack_compose", {**S, "content": NEW_COMPOSE})
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert env.data["guardrails"]["dockhand"]["counts"]["error"] == 1
    assert sent(dockhand, "PUT", "/api/stacks/shop/compose") == []


async def test_compose_put_sends_content_and_redeploy_flags_only(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes(NEW_COMPOSE))
    args = {**S, "content": NEW_COMPOSE, "redeploy": True, "force_recreate": True}
    env, _ = await call("dockhand_update_stack_compose", args)
    assert env.ok is True
    (put,) = sent(dockhand, "PUT", "/api/stacks/shop/compose")
    assert json.loads(put.content) == {
        "content": NEW_COMPOSE,
        "restart": True,
        "pull": False,
        "forceRecreate": True,
    }


async def test_compose_content_is_sent_verbatim(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    padded = "\n" + NEW_COMPOSE + "\n\n"
    mount(dockhand, compose_routes(padded))
    env, _ = await call("dockhand_update_stack_compose", {**S, "content": padded})
    assert env.verified is True
    (put,) = sent(dockhand, "PUT", "/api/stacks/shop/compose")
    assert json.loads(put.content)["content"] == padded


async def test_create_stack_guardrails_use_the_given_variables(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args = {
        **E,
        "name": "shop",
        "compose": DATA_COMPOSE,
        "env_vars": [{"key": "DATA_DIR", "value": "/"}],
    }
    mount(dockhand, CASES["dockhand_create_stack"][1])
    env, _ = await call("dockhand_create_stack", args)
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert [f["rule"] for f in env.data["guardrails"]["findings"]] == ["bind_mount_denied"]
    assert sent(dockhand, "POST", "/api/stacks") == []


async def test_create_stack_warns_about_secrets_in_context(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    value = "s3cr3t-" + "value"
    args = {
        **E,
        "name": "shop",
        "compose": NEW_COMPOSE,
        "env_vars": [{"key": "DB_PASSWORD", "value": value, "isSecret": True}],
    }
    mount(dockhand, CASES["dockhand_create_stack"][1])
    env, content = await call("dockhand_create_stack", args)
    assert env.ok is True
    assert env.warnings is not None
    assert any("passed through the model's context" in w for w in env.warnings)
    assert value not in json.dumps(content)
    (create,) = sent(dockhand, "POST", "/api/stacks")
    assert json.loads(create.content)["envVars"] == [
        {"key": "DB_PASSWORD", "value": value, "isSecret": True}
    ]


async def test_create_stack_env_read_back(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    args = {**E, "name": "shop", "compose": NEW_COMPOSE, "env_vars": [{"key": "NEW", "value": "1"}]}
    mount(dockhand, CASES["dockhand_create_stack"][1])
    env, _ = await call("dockhand_create_stack", args)
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert env.data["read_back"] == {"missing_keys": ["NEW"], "different_keys": []}


# --- lint and validate (read tier) ------------------------------------------------------------


async def test_lint_reports_without_blocking(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()  # read-only profile: lint is a read
    mount(
        dockhand,
        [
            ("GET", "/api/stacks/shop/compose", compose_body(DATA_COMPOSE)),
            ("GET", "/api/stacks/shop/env/raw", env_raw("DATA_DIR=/\n")),
            *stack_env(),
        ],
    )
    env, _ = await call("dockhand_get_stack_compose", {**S, "lint": True})
    assert env.ok is True
    assert env.data["content"] == DATA_COMPOSE
    guardrails = env.data["guardrails"]
    assert (guardrails["mode"], guardrails["blocked"]) == ("warn", False)
    assert [f["rule"] for f in guardrails["findings"]] == ["bind_mount_denied"]


async def test_lint_off_is_the_plain_read(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [("GET", "/api/stacks/shop/compose", compose_body(PRIVILEGED))])
    env, _ = await call("dockhand_get_stack_compose", S)
    assert "guardrails" not in env.data


async def test_validate_includes_our_findings(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [("POST", "/api/stacks/shop/validate", fx("stacks", "validate"))])
    env, _ = await call("dockhand_validate_stack_compose", {**S, "compose": PRIVILEGED})
    assert env.ok is True
    assert env.data["counts"] == fx("stacks", "validate")["counts"]
    assert [f["rule"] for f in env.data["guardrails"]["findings"]] == ["privileged"]


# --- read-back verification -------------------------------------------------------------------


async def test_compose_silent_no_op_is_a_failure(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, compose_routes(read_back=OLD_COMPOSE))
    env, content = await call("dockhand_update_stack_compose", {**S, "content": NEW_COMPOSE})
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert env.data["read_back"] == {
        "expected_lines": 4,
        "actual_lines": 3,
        "expected_bytes": len(NEW_COMPOSE),
        "actual_bytes": len(OLD_COMPOSE),
        "first_differing_lines": [3, 4],
    }
    assert "nginx:1.27" not in json.dumps(content)


async def test_env_raw_mismatch_is_a_failure(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    tool = "dockhand_update_stack_env_raw"
    routes = [r for r in CASES[tool][1] if r[:2] != ("GET", "/api/stacks/shop/env/raw")]
    routes.append(("GET", "/api/stacks/shop/env/raw", env_raw(OLD_ENV)))
    mount(dockhand, routes)
    env, _ = await call(tool, CASES[tool][0])
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert env.data["read_back"]["first_differing_lines"] == [2]
    assert env.warnings == [ENV_RECREATE_WARNING]


def _stale_read_back(tool: str) -> list[Route]:
    """The tool's routes, with every read-back answering the old content."""
    stale = {
        ("GET", "/api/stacks/shop/env/raw"): env_raw(OLD_ENV),
        ("GET", "/api/stacks/shop/compose"): compose_body(OLD_COMPOSE),
    }
    return [(m, p, stale.get((m, p), body)) for m, p, body in CASES[tool][1]]


@pytest.mark.parametrize("tool", sorted(VERIFIED))
async def test_every_read_back_mismatch_is_verification_failed(
    tool: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, _stale_read_back(tool))
    env, content = await call(tool, CASES[tool][0])
    assert (env.ok, env.verified) == (False, False)
    assert env.error is not None
    assert env.error.code == "verification_failed"
    read_back = env.data["read_back"]
    assert set(read_back) == {
        "expected_lines",
        "actual_lines",
        "expected_bytes",
        "actual_bytes",
        "first_differing_lines",
    }
    assert OLD_ENV.splitlines()[-1] not in json.dumps(content)  # counts only, never content


# --- .env edits -------------------------------------------------------------------------------


async def test_modify_preserves_the_file_golden(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    before = (GOLDEN / "modify-input.env").read_bytes().decode()
    after = (GOLDEN / "modify-expected.env").read_bytes().decode()
    mount(
        dockhand,
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", Seq((env_raw(before), env_raw(after)))),
            *stack_env(),
            ("GET", "/api/stacks/shop/compose", compose_body(OLD_COMPOSE)),
            ("PUT", "/api/stacks/shop/env/raw", fx("stacks", "put-env-raw")),
        ],
    )
    args = {
        **S,
        "set_vars": {"TZ": "Europe/Paris", "APP_PORT": "9090", "GREETING": "hello world"},
        "rename": {"OLD_NAME": "NEW_NAME"},
        "delete": ["REMOVE_ME"],
    }
    env, _ = await call("dockhand_modify_stack_env", args)
    assert env.ok is True, env.error
    assert env.verified is True
    (put,) = sent(dockhand, "PUT", "/api/stacks/shop/env/raw")
    assert json.loads(put.content) == {"content": after}
    assert env.data["changes"]["added"] == ["GREETING"]
    assert env.warnings == [ENV_RECREATE_WARNING]


@pytest.mark.parametrize(
    "edit",
    [
        {"delete": ["NOPE"]},
        {"rename": {"NOPE": "OTHER"}},
        {"rename": {"TZ": "TZ2"}, "delete": ["TZ2"]},
    ],
)
async def test_modify_refuses_unknown_or_conflicting_keys(
    edit: dict[str, Any], dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, CASES["dockhand_modify_stack_env"][1])
    env, _ = await call("dockhand_modify_stack_env", {**S, **edit})
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert sent(dockhand, "PUT", "/api/stacks/shop/env/raw") == []


async def test_modify_parameter_is_set_vars_not_set(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call("dockhand_modify_stack_env", {**S, "set": {"TZ": "UTC"}})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("dockhand_modify_stack_env", {**S, "set_vars": {"DATA_DIR": "/"}}),
        ("dockhand_update_stack_env_raw", {**S, "content": "DATA_DIR=/\n"}),
    ],
)
async def test_env_change_that_resolves_a_bind_into_a_denied_path_is_refused(
    tool: str, args: dict[str, Any], dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(
        dockhand,
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", env_raw("DATA_DIR=/srv/data\n")),
            *stack_env(),
            ("GET", "/api/stacks/shop/compose", compose_body(DATA_COMPOSE)),
            ("PUT", "/api/stacks/shop/env/raw", fx("stacks", "put-env-raw")),
        ],
    )
    env, _ = await call(tool, args)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    findings = env.data["guardrails"]["findings"]
    assert [f["rule"] for f in findings] == ["bind_mount_denied"]
    assert "DATA_DIR" in findings[0]["message"]
    assert sent(dockhand, "PUT", "/api/stacks/shop/env/raw") == []


async def test_env_change_does_not_answer_for_existing_findings(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(
        dockhand,
        [
            stack_list(),
            ("GET", "/api/stacks/shop/env/raw", Seq((env_raw(OLD_ENV), env_raw(NEW_ENV)))),
            *stack_env(),
            ("GET", "/api/stacks/shop/compose", compose_body(PRIVILEGED)),
            ("PUT", "/api/stacks/shop/env/raw", fx("stacks", "put-env-raw")),
        ],
    )
    env, _ = await call("dockhand_modify_stack_env", {**S, "set_vars": {"TZ": "Europe/Paris"}})
    assert env.ok is True, env.error
    assert env.data["guardrails"]["findings"] == []


async def test_empty_env_content_needs_allow_empty(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call("dockhand_update_stack_env_raw", {**S, "content": ""})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


async def test_env_write_warning_when_not_waiting(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args, routes = CASES["dockhand_modify_stack_env"]
    mount(dockhand, routes)
    env, _ = await call("dockhand_modify_stack_env", {**args, "wait": False})
    assert env.ok is True
    assert env.warnings is not None
    assert ENV_RECREATE_WARNING in env.warnings


# --- batch, updates, jobs ---------------------------------------------------------------------


@pytest.mark.parametrize("operation", ["remove", "down", "kill", "delete", "REMOVE"])
async def test_batch_refuses_non_operator_operations(
    operation: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call("dockhand_batch_containers", {**E, "operation": operation, "refs": ["web"]})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


async def test_batch_body_and_job_accept(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    args, routes = CASES["dockhand_batch_containers"]
    mount(dockhand, routes)
    env, _ = await call("dockhand_batch_containers", args)
    assert env.ok is True
    (post,) = sent(dockhand, "POST", "/api/batch")
    assert json.loads(post.content) == {
        "operation": "restart",
        "entityType": "containers",
        "items": [{"id": WEB, "name": "web"}, {"id": DB, "name": "db"}],
    }
    assert "text/event-stream" in post.headers["accept"]
    assert env.operation is not None
    assert (env.operation.kind, env.operation.id) == ("job", JOB)


def batch_routes(job: Any) -> list[Route]:
    return [
        containers(),
        ("POST", "/api/batch", fx("stacks", "job-started")),
        ("GET", f"/api/jobs/{JOB}", job),
    ]


BATCH_ARGS = {**E, "operation": "unpause", "refs": ["web", "db"]}


def items_by_name(env: Envelope) -> dict[str, dict[str, Any]]:
    return {i["name"]: i for i in env.data["items"]}


async def test_batch_all_succeeded_is_ok(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    mount(dockhand, batch_routes(batch_job(web="success", db="success")))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is True
    assert env.error is None
    assert env.data["summary"] == {"total": 2, "succeeded": 2, "failed": 0}
    assert items_by_name(env) == {
        "web": {"id": WEB, "name": "web", "outcome": "succeeded"},
        "db": {"id": DB, "name": "db", "outcome": "succeeded"},
    }


async def test_batch_with_a_failed_item_is_not_ok(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The recorded live shape: status `done`, `{type, summary}`, no `success` key (#6)."""
    operator_env()
    mount(dockhand, batch_routes(fx("jobs", "batch-mixed")))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert "1 of 2" in env.error.message
    assert env.data["summary"] == {"total": 2, "succeeded": 1, "failed": 1}
    items = items_by_name(env)
    assert items["web"] == {"id": WEB, "name": "web", "outcome": "succeeded"}
    assert items["db"] == {
        "id": DB,
        "name": "db",
        "outcome": "failed",
        "message": f"Container {DB} is not paused",
    }
    assert env.operation is not None
    assert (env.operation.id, env.operation.status) == (JOB, "done")


async def test_batch_all_failed_is_not_ok(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    mount(dockhand, batch_routes(batch_job(web="error", db="error")))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert "2 of 2" in env.error.message
    assert env.data["summary"] == {"total": 2, "succeeded": 0, "failed": 2}
    assert {i["outcome"] for i in env.data["items"]} == {"failed"}


def _with_result(result: Any) -> dict[str, Any]:
    job = batch_job(web="success", db="success")
    if result is _MISSING:
        del job["result"]
    else:
        job["result"] = result
    return job


_MISSING = object()
_OK_SUMMARY = {"total": 2, "success": 2, "failed": 0}


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(_MISSING, id="no-result"),
        pytest.param(None, id="null-result"),
        pytest.param({"success": True, "output": "done"}, id="generic-job-shape"),
        pytest.param({"type": "complete"}, id="no-summary"),
        pytest.param({"type": "complete", "summary": "2 ok"}, id="summary-not-object"),
        pytest.param(
            {"type": "complete", "summary": {"total": 2, "success": 2}}, id="no-failed-count"
        ),
        pytest.param(
            {"type": "complete", "summary": {"total": 2, "success": "2", "failed": 0}},
            id="count-not-int",
        ),
        pytest.param(
            {"type": "complete", "summary": {"total": 2, "success": True, "failed": False}},
            id="count-bool",
        ),
        pytest.param(
            {"type": "complete", "summary": {"total": 3, "success": 3, "failed": 0}},
            id="total-not-items-sent",
        ),
        pytest.param(
            {"type": "complete", "summary": {"total": 2, "success": 1, "failed": 0}},
            id="counts-do-not-add-up",
        ),
        pytest.param({"type": "error", "summary": _OK_SUMMARY}, id="type-not-complete"),
        pytest.param({"truncated": True, "bytes": 99999}, id="oversized"),
    ],
)
async def test_batch_missing_or_malformed_result_is_not_ok(
    result: Any, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, batch_routes(_with_result(result)))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "dockhand_http_error"
    assert {i["name"] for i in env.data["items"]} == {"web", "db"}


async def test_batch_summary_contradicted_by_an_item_is_not_ok(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """A per-item `error` line with a summary that claims no failures is not taken as success."""
    operator_env()
    job = batch_job(web="success", db="error")
    job["result"] = {"type": "complete", "summary": _OK_SUMMARY}
    mount(dockhand, batch_routes(job))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert items_by_name(env)["db"]["outcome"] == "failed"


async def test_batch_failed_job_status_is_not_ok(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    job = {**batch_job(web="success", db="success"), "status": "failed"}
    mount(dockhand, batch_routes(job))
    env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"


async def test_batch_synchronous_summary_without_item_lines(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The spec's synchronous answer: a summary only, so item outcomes are unknown."""
    operator_env()
    for summary, expect_ok in (
        (_OK_SUMMARY, True),
        ({"total": 2, "success": 1, "failed": 1}, False),
    ):
        dockhand.reset()
        dockhand.routes.clear()
        answer = {"type": "complete", "summary": summary}
        mount(dockhand, [containers(), ("POST", "/api/batch", answer)])
        env, _ = await call("dockhand_batch_containers", BATCH_ARGS)
        assert env.ok is expect_ok
        assert env.data["summary"]["failed"] == summary["failed"]
        assert {i["outcome"] for i in env.data["items"]} == {"unknown"}


async def test_batch_item_messages_are_redacted_and_truncated(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    token = fake_dh_token()
    job = fx("jobs", "batch-mixed")
    for line in job["lines"]:
        if line["data"].get("status") == "error":
            line["data"]["error"] = f"failed with {token} " + "x" * 5000
    mount(dockhand, batch_routes(job))
    env, raw = await call("dockhand_batch_containers", BATCH_ARGS)
    message = items_by_name(env)["db"]["message"]
    assert token not in json.dumps(raw)
    assert "dh_***" in message
    assert len(message) <= 513


async def test_batch_without_waiting_reports_the_job(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, batch_routes(fx("jobs", "batch-mixed")))
    env, _ = await call("dockhand_batch_containers", {**BATCH_ARGS, "wait": False})
    assert env.ok is True
    assert env.data == {"job_id": JOB}
    assert sent(dockhand, "GET", f"/api/jobs/{JOB}") == []


async def test_stack_start_asks_for_a_job(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    args, routes = CASES["dockhand_start_stack"]
    mount(dockhand, routes)
    await call("dockhand_start_stack", args)
    (post,) = sent(dockhand, "POST", "/api/stacks/shop/start")
    assert "text/event-stream" in post.headers["accept"]


async def test_update_containers_honours_the_opt_out_label(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    opted_out = fx("containers", "inspect")
    opted_out["Config"]["Labels"]["dockhand.update"] = "false"
    routes = [r for r in CASES["dockhand_update_containers"][1] if r[1] != f"/api/containers/{DB}"]
    routes.append(("GET", f"/api/containers/{DB}", opted_out))
    mount(dockhand, routes)
    env, _ = await call("dockhand_update_containers", {**E, "refs": ["web", "db"]})
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "db" in env.error.message and "web" not in env.error.message
    assert sent(dockhand, "POST", "/api/containers/batch-update") == []


async def test_container_lifecycle_rereads_state(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args, routes = CASES["dockhand_stop_container"]
    mount(dockhand, routes)
    env, _ = await call("dockhand_stop_container", args)
    assert env.data["container"] == {"id": WEB, "name": "web"}
    assert (env.data["state"], env.data["status"]) == ("running", "Up 2 hours")
    assert env.operation is not None
    assert env.operation.kind == "detached"
    assert len(sent(dockhand, "GET", "/api/containers")) == 2


async def test_detached_container_restart_is_retrievable(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args, routes = CASES["dockhand_restart_container"]
    mount(dockhand, routes)
    app = create_app(load_settings())
    async with mcp_client(app) as c:
        started = await c.call_tool("dockhand_restart_container", {**args, "wait": False})
        assert started.structured_content is not None
        op_id = started.structured_content["operation"]["id"]
        for _ in range(100):
            later = await c.call_tool("dockhand_get_operation", {"op_id": op_id})
            assert later.structured_content is not None
            if later.structured_content["operation"]["status"] != "running":
                break
            await anyio.sleep(0.01)
    assert later.structured_content["ok"] is True
    assert later.structured_content["data"]["result"]["state"] == "running"


@pytest.mark.parametrize("schedule_type", ["image_prune", "repo_prune", "backup", "system_cleanup"])
async def test_run_schedule_refuses_other_types(
    schedule_type: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await call(
        "dockhand_run_schedule_now", {"schedule_type": schedule_type, "schedule_id": 1}
    )
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


async def test_system_schedule_toggle(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    mount(dockhand, [("POST", "/api/schedules/system/2/toggle", fx("schedules", "toggle"))])
    env, _ = await call("dockhand_toggle_schedule", {"schedule_type": "system", "schedule_id": 2})
    assert env.ok is True
    bad, _ = await call("dockhand_toggle_schedule", {"schedule_type": "system", "schedule_id": 3})
    assert bad.error is not None
    assert bad.error.code == "validation_error"


async def test_restart_and_deploy_parameters(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    for tool in ("dockhand_restart_stack", "dockhand_deploy_stack"):
        mount(dockhand, CASES[tool][1])
        await call(tool, CASES[tool][0])
    (restart,) = sent(dockhand, "POST", "/api/stacks/shop/restart")
    assert restart.url.params["mode"] == "recreate"
    (deploy,) = sent(dockhand, "POST", "/api/stacks/shop/deploy")
    assert json.loads(deploy.content) == {"pull": True, "build": False, "forceRecreate": False}


# --- output redaction -------------------------------------------------------------------------


async def test_operator_output_passes_the_key_redaction(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    args, routes = CASES["dockhand_sync_git_repository"]
    mount(dockhand, routes)
    env, content = await call("dockhand_sync_git_repository", args)
    assert env.data["result"]["repository"]["webhookSecret"] == REDACTED
    assert "s3cr3t-value" not in json.dumps(content)
