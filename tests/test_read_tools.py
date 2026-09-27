# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the read tier against a mocked DockHand (invented fixtures, see
tests/fixtures/dockhand/README.md), end to end through the authenticated app.

Every read tool: happy path validated against its outputSchema, DockHand 403 → error envelope,
and only declared endpoints called. Then the behaviours the tier promises: name resolution,
pagination, truncation, env redaction, credential canaries, key redaction, F-09, and the exact
query parameter names each route takes.
"""

import json
import logging
from typing import Any

import jsonschema
import pytest
import respx
from conftest import ENV, IDS, SetEnv, fake_secret, load_fixture, mcp_client

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.config import load_settings
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.tools.registry import REGISTRY, Tier
from dockhand_mcp.transport.app import create_app

SECRET = fake_secret("s3cr3t-value")
WEB, DB = IDS["CID_WEB"], IDS["CID_DB"]
NGINX = "sha256:" + IDS["IMG_NGINX"]
FRONT = IDS["NID_FRONT"]
JOB = "4c3b2a19-8f7e-4d6c-9b5a-1f2e3d4c5b6a"
DENIED = {"error": "Permission denied", "status": 403}

Route = tuple[str, str, Any]  # method, path, body (str = text/plain)


def fx(domain: str, name: str) -> Any:
    return load_fixture(domain, name)


def containers() -> Route:
    return ("GET", "/api/containers", fx("containers", "list"))


E = {"environment_id": ENV}

# tool -> (arguments, DockHand routes it needs)
CASES: dict[str, tuple[dict[str, Any], list[Route]]] = {
    "dockhand_list_environments": ({}, [("GET", "/api/environments", fx("environments", "list"))]),
    "dockhand_get_environment": (
        E,
        [
            ("GET", "/api/environments/7", fx("environments", "get")),
            ("GET", "/api/environments/7/timezone", fx("environments", "timezone")),
            ("GET", "/api/environments/7/update-check", fx("environments", "update-check")),
            ("GET", "/api/environments/7/image-prune", fx("environments", "image-prune")),
            ("GET", "/api/environments/7/disk-warning", fx("environments", "disk-warning")),
            (
                "GET",
                "/api/environments/7/remote-stacks-dir",
                fx("environments", "remote-stacks-dir"),
            ),
        ],
    ),
    "dockhand_get_host_info": (E, [("GET", "/api/host", fx("system", "host"))]),
    "dockhand_get_system_info": (
        E,
        [
            ("GET", "/api/system", fx("system", "system")),
            ("GET", "/api/system/disk", fx("system", "disk")),
        ],
    ),
    "dockhand_get_dashboard_stats": (
        E,
        [("GET", "/api/dashboard/stats", fx("system", "dashboard-stats"))],
    ),
    "dockhand_list_containers": (E, [containers()]),
    "dockhand_get_container": (
        {**E, "ref": "web"},
        [containers(), ("GET", f"/api/containers/{WEB}", fx("containers", "inspect"))],
    ),
    "dockhand_get_container_logs": (
        {**E, "ref": "web", "tail": 20},
        [containers(), ("GET", f"/api/containers/{WEB}/logs", fx("containers", "logs"))],
    ),
    "dockhand_get_container_stats": (
        {**E, "ref": "web"},
        [containers(), ("GET", f"/api/containers/{WEB}/stats", fx("containers", "stats"))],
    ),
    "dockhand_get_all_container_stats": (
        E,
        [("GET", "/api/containers/stats", fx("containers", "stats-all"))],
    ),
    "dockhand_get_container_processes": (
        {**E, "ref": "web"},
        [containers(), ("GET", f"/api/containers/{WEB}/top", fx("containers", "top"))],
    ),
    "dockhand_get_container_sizes": (
        E,
        [containers(), ("GET", "/api/containers/sizes", fx("containers", "sizes"))],
    ),
    "dockhand_generate_container_compose": (
        {**E, "ref": "web"},
        [containers(), ("GET", f"/api/containers/{WEB}/compose", fx("containers", "compose"))],
    ),
    "dockhand_get_pending_updates": (
        E,
        [
            ("GET", "/api/containers/pending-updates", fx("containers", "pending-updates")),
            ("GET", "/api/containers/check-updates", fx("containers", "check-updates")),
        ],
    ),
    "dockhand_get_version_notes": (
        {**E, "ref": "web", "versions": ["1.28"]},
        [
            containers(),
            ("GET", f"/api/containers/{WEB}/version-notes", fx("containers", "version-notes")),
        ],
    ),
    "dockhand_list_stacks": (E, [("GET", "/api/stacks", fx("stacks", "list"))]),
    "dockhand_get_stack_compose": (
        {**E, "stack": "shop"},
        [("GET", "/api/stacks/shop/compose", fx("stacks", "compose"))],
    ),
    "dockhand_get_stack_env": (
        {**E, "stack": "shop"},
        [("GET", "/api/stacks/shop/env", fx("stacks", "env"))],
    ),
    "dockhand_get_stack_env_raw": (
        {**E, "stack": "shop"},
        [("GET", "/api/stacks/shop/env/raw", fx("stacks", "env-raw"))],
    ),
    "dockhand_list_stack_deploys": (
        {**E, "stack": "shop", "limit": 2},
        [("GET", "/api/stacks/shop/deploys", fx("stacks", "deploys"))],
    ),
    "dockhand_get_stack_deploy_log": (
        {"stack": "shop", "run_id": 3},
        [
            ("GET", "/api/stacks/shop/deploys/3", fx("stacks", "deploy-run")),
            ("GET", "/api/stacks/shop/deploys/3/log", fx("stacks", "deploy-log")),
        ],
    ),
    "dockhand_preview_stack_delete": (
        {**E, "stack": "shop"},
        [("GET", "/api/stacks/shop/delete-preview", fx("stacks", "delete-preview"))],
    ),
    "dockhand_validate_stack_compose": (
        {**E, "stack": "shop", "compose": "services:\n  web:\n    image: nginx:latest\n"},
        [("POST", "/api/stacks/shop/validate", fx("stacks", "validate"))],
    ),
    "dockhand_validate_stack_env": (
        {**E, "stack": "shop"},
        [("POST", "/api/stacks/shop/env/validate", fx("stacks", "env-validate"))],
    ),
    "dockhand_get_stack_paths": (
        {**E, "stack": "shop"},
        [
            ("GET", "/api/stacks/base-path", fx("stacks", "base-path")),
            ("GET", "/api/stacks/sources", fx("stacks", "sources")),
            ("GET", "/api/stacks/default-path", fx("stacks", "default-path")),
            ("GET", "/api/stacks/path-hints", fx("stacks", "path-hints")),
        ],
    ),
    "dockhand_list_images": (E, [("GET", "/api/images", fx("images", "list"))]),
    "dockhand_get_image_history": (
        {**E, "image": "nginx:1.27"},
        [
            ("GET", "/api/images", fx("images", "list")),
            ("GET", f"/api/images/{NGINX}/history", fx("images", "history")),
        ],
    ),
    "dockhand_get_image_scan": (
        {**E, "image": "nginx:1.27", "limit": 2},
        [("GET", "/api/images/scan", fx("images", "scan"))],
    ),
    "dockhand_list_volumes": (E, [("GET", "/api/volumes", fx("volumes", "list"))]),
    "dockhand_get_volume": (
        {**E, "volume": "shop_data"},
        [("GET", "/api/volumes/shop_data/inspect", fx("volumes", "inspect"))],
    ),
    "dockhand_list_networks": (E, [("GET", "/api/networks", fx("networks", "list"))]),
    "dockhand_get_network": (
        {**E, "network": "front"},
        [
            ("GET", "/api/networks", fx("networks", "list")),
            ("GET", f"/api/networks/{FRONT}/inspect", fx("networks", "inspect")),
        ],
    ),
    "dockhand_get_job": ({"job_id": JOB}, [("GET", f"/api/jobs/{JOB}", fx("jobs", "job"))]),
    "dockhand_get_activity": ({"limit": 2}, [("GET", "/api/activity", fx("activity", "events"))]),
    "dockhand_get_activity_stats": (E, [("GET", "/api/activity/stats", fx("activity", "stats"))]),
    "dockhand_get_audit_log": ({}, [("GET", "/api/audit", fx("activity", "audit"))]),
    "dockhand_list_schedules": ({}, [("GET", "/api/schedules", fx("schedules", "list"))]),
    "dockhand_list_schedule_executions": (
        {"limit": 1},
        [("GET", "/api/schedules/executions", fx("schedules", "executions"))],
    ),
    "dockhand_get_schedule_execution": (
        {"execution_id": 3},
        [("GET", "/api/schedules/executions/3", fx("schedules", "execution"))],
    ),
    "dockhand_get_auto_update_settings": (E, [("GET", "/api/auto-update", fx("updates", "all"))]),
    "dockhand_list_vulnerabilities": (
        {**E, "limit": 2},
        [("GET", "/api/vulnerabilities", fx("vulnerabilities", "list"))],
    ),
    "dockhand_get_vulnerability_summary": (
        E,
        [("GET", "/api/vulnerabilities/count", fx("vulnerabilities", "count"))],
    ),
    "dockhand_search_registry": (
        {"term": "nginx"},
        [("GET", "/api/registry/search", fx("registries", "search"))],
    ),
    "dockhand_list_image_tags": (
        {"image": "library/nginx", "page_size": 2},
        [("GET", "/api/registry/tags", fx("registries", "tags"))],
    ),
    "dockhand_list_registries": ({}, [("GET", "/api/registries", fx("registries", "list"))]),
    "dockhand_get_settings": (
        {},
        [
            ("GET", "/api/settings/general", fx("settings", "general")),
            ("GET", "/api/settings/scanner", fx("settings", "scanner")),
            ("GET", "/api/settings/semver", fx("settings", "semver")),
        ],
    ),
    "dockhand_list_git_repositories": (
        {},
        [("GET", "/api/git/repositories", fx("git", "repositories"))],
    ),
    "dockhand_list_git_stacks": ({}, [("GET", "/api/git/stacks", fx("git", "stacks"))]),
    "dockhand_list_tags": (
        E,
        [
            ("GET", "/api/tags", fx("tags", "catalogue")),
            ("GET", "/api/container-tags", fx("tags", "containers")),
            ("GET", "/api/stack-tags", fx("tags", "stacks")),
        ],
    ),
}

# Phase 1 tools with their own tests (test_health_tool.py, test_operations.py).
PHASE_1 = {"dockhand_health", "dockhand_get_operation"}


def mount(dockhand: respx.MockRouter, routes: list[Route], status: int | None = None) -> None:
    for method, path, body in routes:
        route = dockhand.route(method=method, path=path)
        if status is not None:
            route.respond(status, json=DENIED)
        elif isinstance(body, str):
            route.respond(200, text=body, headers={"content-type": "text/plain"})
        else:
            route.respond(200, json=body)


class Called:
    def __init__(self) -> None:
        self.endpoints: list[tuple[str, str]] = []


async def call(
    tool: str, args: dict[str, Any], called: Called | None = None
) -> tuple[Envelope, dict[str, Any], dict[str, Any]]:
    """Call `tool` through the app. Returns (envelope, structured content, outputSchema)."""
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
    return Envelope.model_validate(result.structured_content), result.structured_content, schema


def declared(tool: str) -> set[tuple[str, str]]:
    return set(next(t for t in REGISTRY.all() if t.name == tool).endpoints)


def test_cases_cover_the_whole_read_tier() -> None:
    read = {t.name for t in REGISTRY.all() if t.tier is Tier.READ}
    assert set(CASES) | PHASE_1 == read


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_happy_path(tool: str, dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    args, routes = CASES[tool]
    mount(dockhand, routes)
    called = Called()
    env, _, _ = await call(tool, args, called)
    assert env.ok is True, env.error
    assert env.data is not None
    assert env.warnings is None, env.warnings
    assert called.endpoints, "a read tool must call DockHand"
    assert set(called.endpoints) <= declared(tool)
    if "environment_id" in args:
        assert env.environment_id == ENV


@pytest.mark.parametrize("tool", sorted(CASES))
async def test_dockhand_403_is_an_error_envelope(
    tool: str, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    args, routes = CASES[tool]
    mount(dockhand, routes, status=403)
    env, content, _ = await call(tool, args)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "dockhand_http_error"
    assert env.error.dockhand_status == 403
    assert "data" not in content


# --- F-09 -------------------------------------------------------------------------------------


async def test_environment_defaults_to_the_only_one(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/environments").respond(200, json=fx("environments", "list"))
    route = dockhand.get("/api/host").respond(200, json=fx("system", "host"))
    env, _, _ = await call("dockhand_get_host_info", {})
    assert env.ok is True
    assert env.environment_id == ENV
    assert env.warnings == ["environment_id not given; used the only environment, 7 (env-seven)"]
    assert route.calls.last.request.url.params["env"] == "7"


async def test_environment_required_with_several(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/environments").respond(200, json=fx("environments", "list-two"))
    route = dockhand.get("/api/containers")
    env, _, _ = await call("dockhand_list_containers", {})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert "7 (env-seven), 8 (env-eight)" in env.error.message
    assert route.call_count == 0


async def test_configured_default_environment(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env(DOCKHAND_DEFAULT_ENVIRONMENT_ID="7")
    envs = dockhand.get("/api/environments")
    route = dockhand.get("/api/images").respond(200, json=fx("images", "list"))
    env, _, _ = await call("dockhand_list_images", {})
    assert env.ok is True
    assert env.environment_id == ENV
    assert envs.call_count == 0
    assert route.calls.last.request.url.params["env"] == "7"


# --- containers -------------------------------------------------------------------------------


async def test_list_containers_filters_and_pages(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    route = dockhand.get("/api/containers").respond(200, json=fx("containers", "list"))
    env, _, _ = await call("dockhand_list_containers", {**E, "limit": 1})
    assert env.data["count"] == 1
    assert env.data["total"] == 3
    assert env.data["has_more"] is True
    assert env.data["items"][0] == {
        "id": WEB,
        "name": "web",
        "image": "nginx:1.27",
        "state": "running",
        "status": "Up 2 hours",
        "health": "healthy",
        "stack": "shop",
    }
    assert route.calls.last.request.url.params["all"] == "true"
    env, _, _ = await call("dockhand_list_containers", {**E, "state": "running", "offset": 1})
    assert [i["name"] for i in env.data["items"]] == ["db"]
    assert env.data["has_more"] is False
    env, _, _ = await call("dockhand_list_containers", {**E, "stack": "shop", "name_contains": "D"})
    assert [i["name"] for i in env.data["items"]] == ["db"]
    await call("dockhand_list_containers", {**E, "all": False})
    assert route.calls.last.request.url.params["all"] == "false"


async def test_get_container_redacts_env_by_default(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_container"][1])
    env, content, _ = await call("dockhand_get_container", {**E, "ref": "web"})
    assert env.data["Config"]["Env"] == [
        f"PATH={REDACTED}",
        f"DB_PASSWORD={REDACTED}",
        f"EMPTY={REDACTED}",
        "FLAG_ONLY",
    ]
    assert SECRET not in json.dumps(content)


async def test_get_container_redact_env_false_returns_values(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_container"][1])
    env, _, _ = await call("dockhand_get_container", {**E, "ref": "web", "redact_env": False})
    assert f"DB_PASSWORD={SECRET}" in env.data["Config"]["Env"]


async def test_get_container_sections(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_container"][1])
    env, _, _ = await call(
        "dockhand_get_container", {**E, "ref": WEB[:12], "sections": ["State", "Nope"]}
    )
    assert set(env.data) == {"Id", "Name", "State"}
    assert env.warnings == ["not in the inspect payload: Nope"]


@pytest.mark.parametrize(
    ("ref", "code"),
    [("nope", "not_found"), ("f" * 12, "not_found"), ("/web", "validation_error")],
)
async def test_container_resolution_errors(
    dockhand: respx.MockRouter, base_env: SetEnv, ref: str, code: str
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_container_stats"][1])
    inspect = dockhand.get(f"/api/containers/{WEB}/stats")
    env, _, _ = await call("dockhand_get_container_stats", {**E, "ref": ref})
    assert env.error is not None
    assert env.error.code == code
    assert env.environment_id == ENV
    assert inspect.call_count == 0


async def test_container_resolution_ambiguous(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    body = fx("containers", "list")
    body.append({**body[0], "id": IDS["CID_WORKER"]})
    dockhand.get("/api/containers").respond(200, json=body)
    env, _, _ = await call("dockhand_get_container_processes", {**E, "ref": "web"})
    assert env.error is not None
    assert env.error.code == "ambiguous_name"


async def test_logs_truncated_to_max_bytes(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    text = "".join(f"line {i:06d}\n" for i in range(10_000))
    dockhand.get("/api/containers").respond(200, json=fx("containers", "list"))
    route = dockhand.get(f"/api/containers/{WEB}/logs").respond(200, json={"logs": text})
    args = {
        **E,
        "ref": "web",
        "tail": 5000,
        "since": "10m",
        "until": "1767323045",
        "max_bytes": 2048,
    }
    env, _, _ = await call("dockhand_get_container_logs", args)
    data = env.data
    assert data["truncated"] is True
    assert data["bytes"] == len(text)
    assert data["dropped_bytes"] == len(text) - len(data["logs"].encode())
    assert len(data["logs"].encode()) <= 2048
    assert data["logs"].endswith("line 009999\n")
    assert data["container"] == {"id": WEB, "name": "web"}
    params = route.calls.last.request.url.params
    assert (params["env"], params["tail"], params["since"], params["until"]) == (
        "7",
        "5000",
        "10m",
        "1767323045",
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"since": "yesterday"},
        {"until": "10 m"},
        {"tail": 5001},
        {"tail": 0},
        {"max_bytes": 2**20 + 1},
    ],
)
async def test_logs_arguments_validated(
    dockhand: respx.MockRouter, base_env: SetEnv, bad: dict[str, Any]
) -> None:
    base_env()
    env, _, _ = await call("dockhand_get_container_logs", {**E, "ref": "web", **bad})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert not dockhand.calls


async def test_generated_compose_redacted_by_default(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_generate_container_compose"][1])
    env, content, _ = await call("dockhand_generate_container_compose", {**E, "ref": "web"})
    assert SECRET not in json.dumps(content)
    assert "composeFullEnv" not in json.dumps(content)
    assert f"DB_PASSWORD={REDACTED}" in env.data["compose"]
    assert env.data["env_redacted"] is True
    assert env.data["serviceName"] == "web"


async def test_generated_compose_redact_env_false(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_generate_container_compose"][1])
    env, content, _ = await call(
        "dockhand_generate_container_compose", {**E, "ref": "web", "redact_env": False}
    )
    assert f"DB_PASSWORD={SECRET}" in env.data["compose"]
    assert "composeFullEnv" not in json.dumps(content)
    assert "INHERITED" not in json.dumps(content)


async def test_generated_compose_unparseable_is_refused(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/containers").respond(200, json=fx("containers", "list"))
    broken = {"compose": f"services: [\n  DB_PASSWORD={SECRET}", "serviceName": "web"}
    dockhand.get(f"/api/containers/{WEB}/compose").respond(200, json=broken)
    env, content, _ = await call("dockhand_generate_container_compose", {**E, "ref": "web"})
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert SECRET not in json.dumps(content)


async def test_container_sizes_joined_with_names(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_container_sizes"][1])
    env, _, _ = await call("dockhand_get_container_sizes", E)
    assert [(i["name"], i["sizeRw"]) for i in env.data["items"]] == [
        ("db", 30),
        ("web", 10),
        ("worker", 0),
    ]


async def test_pending_updates_reports_last_check(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_pending_updates"][1])
    env, _, _ = await call("dockhand_get_pending_updates", E)
    assert env.data["last_checked_at"] == "2026-01-02T03:04:05.000Z"
    assert env.data["pending_updates"][0]["containerName"] == "web"


async def test_version_notes_sends_comma_list(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/containers").respond(200, json=fx("containers", "list"))
    route = dockhand.get(f"/api/containers/{WEB}/version-notes").respond(
        200, json=fx("containers", "version-notes")
    )
    await call(
        "dockhand_get_version_notes", {**E, "ref": "web", "versions": ["1.28", "1.29-alpine"]}
    )
    assert route.calls.last.request.url.params["versions"] == "1.28,1.29-alpine"
    env, _, _ = await call("dockhand_get_version_notes", {**E, "ref": "web", "versions": ["a,b"]})
    assert env.error is not None
    assert env.error.code == "validation_error"


# --- environments, canaries -------------------------------------------------------------------


@pytest.mark.parametrize("key", ["tlsKey", "hawserToken"])
async def test_list_environments_canary_fails_closed(
    dockhand: respx.MockRouter, base_env: SetEnv, caplog: pytest.LogCaptureFixture, key: str
) -> None:
    base_env()
    body = fx("environments", "list")
    body[0][key] = fake_secret("leaked-material")
    dockhand.get("/api/environments").respond(200, json=body)
    with caplog.at_level(logging.ERROR):
        env, content, _ = await call("dockhand_list_environments", {})
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "leaked-material" not in json.dumps(content)
    assert "data" not in content
    records = [r for r in caplog.records if r.getMessage() == "credential_canary"]
    assert records and records[0].levelno == logging.ERROR
    assert records[0].__dict__["keys"] == [key]
    assert "leaked-material" not in caplog.text


async def test_get_environment_canary_fails_closed(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    routes = CASES["dockhand_get_environment"][1]
    mount(dockhand, routes[1:])
    body = fx("environments", "get")
    body["tlsKey"] = None  # the key's presence is the breach, whatever its value
    dockhand.get("/api/environments/7").respond(200, json=body)
    env, _, _ = await call("dockhand_get_environment", E)
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"


async def test_get_environment_reports_failed_sections(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    routes = CASES["dockhand_get_environment"][1]
    mount(dockhand, [r for r in routes if not r[1].endswith("disk-warning")])
    dockhand.get("/api/environments/7/disk-warning").respond(500, json={"error": "boom"})
    env, _, _ = await call("dockhand_get_environment", E)
    assert env.ok is True
    assert env.data["environment"]["name"] == "env-seven"
    assert env.data["timezone"] == {"timezone": "UTC"}
    assert "disk_warning" not in env.data
    assert env.data["errors"]["disk_warning"]["dockhand_status"] == 500
    assert env.warnings == ["disk_warning unavailable: DockHand server error (HTTP 500)"]


async def test_list_registries_canary_fails_closed(
    dockhand: respx.MockRouter, base_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    base_env()
    body = fx("registries", "list")
    body[1]["password"] = fake_secret("registry-pass")
    dockhand.get("/api/registries").respond(200, json=body)
    with caplog.at_level(logging.ERROR):
        env, content, _ = await call("dockhand_list_registries", {})
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "registry-pass" not in json.dumps(content)
    assert any(r.getMessage() == "credential_canary" for r in caplog.records)


# --- key-based redaction (dispatcher) ---------------------------------------------------------


async def test_webhook_secret_redacted_null_kept(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/git/repositories").respond(200, json=fx("git", "repositories"))
    env, content, _ = await call("dockhand_list_git_repositories", {})
    assert [i["webhookSecret"] for i in env.data["items"]] == [REDACTED, None]
    assert SECRET not in json.dumps(content)


async def test_git_repository_with_upstream(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/git/repositories/1").respond(200, json=fx("git", "repository"))
    sync = dockhand.get("/api/git/repositories/1/sync").respond(200, json=fx("git", "sync"))
    env, content, _ = await call(
        "dockhand_list_git_repositories", {"repository_id": 1, "check_upstream": True}
    )
    assert env.data["upstream"] == {"hasUpdates": True}
    assert env.data["repository"]["webhookSecret"] == REDACTED
    assert SECRET not in json.dumps(content)
    assert sync.call_count == 1
    env, _, _ = await call("dockhand_list_git_repositories", {"check_upstream": True})
    assert env.error is not None
    assert env.error.code == "validation_error"


async def test_git_stack_env_files_names_only(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/git/stacks/4").respond(200, json=fx("git", "stack"))
    files = dockhand.get("/api/git/stacks/4/env-files").respond(200, json=fx("git", "env-files"))
    called = Called()
    env, _, _ = await call("dockhand_list_git_stacks", {"git_stack_id": 4}, called)
    assert env.data["env_files"] == [".env", ".env.production"]
    assert files.calls.last.request.method == "GET"
    assert ("POST", "/api/git/stacks/{id}/env-files") not in called.endpoints


# --- stacks -----------------------------------------------------------------------------------


async def test_list_stacks_type_filter(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/stacks").respond(200, json=fx("stacks", "list"))
    env, _, _ = await call("dockhand_list_stacks", {**E, "type": "git"})
    assert [s["name"] for s in env.data["items"]] == ["tools"]
    assert "containerDetails" not in env.data["items"][0]
    env, _, _ = await call("dockhand_list_stacks", {**E, "limit": 2})
    assert env.data["has_more"] is True


@pytest.mark.parametrize("stack", ["../etc", "a b", "-x", "x" * 65, "a/b"])
async def test_stack_names_validated(
    dockhand: respx.MockRouter, base_env: SetEnv, stack: str
) -> None:
    base_env()
    env, _, _ = await call("dockhand_get_stack_compose", {**E, "stack": stack})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert not dockhand.calls


async def test_deploy_log_truncated(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    text = "".join(f"step {i:05d}\n" for i in range(5000))
    dockhand.get("/api/stacks/shop/deploys/3").respond(200, json=fx("stacks", "deploy-run"))
    route = dockhand.get("/api/stacks/shop/deploys/3/log").respond(200, text=text)
    env, _, _ = await call(
        "dockhand_get_stack_deploy_log", {"stack": "shop", "run_id": 3, "max_bytes": 1024}
    )
    assert env.data["truncated"] is True
    assert env.data["log"].endswith("step 04999\n")
    assert env.data["run"]["id"] == 3
    assert "env" not in route.calls.last.request.url.params  # these routes take no environment


async def test_validate_compose_posts_only_what_the_spec_lists(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    route = dockhand.post("/api/stacks/shop/validate").respond(200, json=fx("stacks", "validate"))
    args = {
        **E,
        "stack": "shop",
        "compose": "services: {}\n",
        "env_vars": {"TZ": "UTC"},
        "existing": True,
    }
    called = Called()
    env, _, _ = await call("dockhand_validate_stack_compose", args, called)
    assert env.data["counts"] == {"error": 0, "warn": 1, "info": 0}
    body = json.loads(route.calls.last.request.content)
    assert body == {"compose": "services: {}", "existing": True, "envVars": {"TZ": "UTC"}}
    assert route.calls.last.request.url.params["env"] == "7"
    assert called.endpoints == [("POST", "/api/stacks/{name}/validate")]


async def test_validate_env_body(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.post("/api/stacks/shop/env/validate").respond(
        200, json=fx("stacks", "env-validate")
    )
    await call("dockhand_validate_stack_env", {**E, "stack": "shop"})
    assert json.loads(route.calls.last.request.content) == {}
    await call("dockhand_validate_stack_env", {**E, "stack": "shop", "variables": ["TZ"]})
    assert json.loads(route.calls.last.request.content) == {"variables": ["TZ"]}


async def test_stack_paths_one_stack(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_stack_paths"][1])
    env, _, _ = await call("dockhand_get_stack_paths", {**E, "stack": "shop"})
    assert list(env.data["sources"]) == ["shop"]
    assert env.data["path_hints"]["stackName"] == "shop"
    hints = dockhand.routes[-1]
    assert hints.calls.last.request.url.params["name"] == "shop"


# --- images, networks -------------------------------------------------------------------------


async def test_list_images_dangling_and_tags(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/images").respond(200, json=fx("images", "list"))
    env, _, _ = await call("dockhand_list_images", {**E, "dangling_only": True})
    assert [i["id"] for i in env.data["items"]] == ["sha256:" + IDS["IMG_DANGLING"]]
    env, _, _ = await call("dockhand_list_images", {**E, "repo_contains": "REDIS"})
    assert env.data["items"][0]["repoTags"] == ["redis:7", "redis:latest"]


async def test_image_scan_summary_and_findings_page(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    route = dockhand.get("/api/images/scan").respond(200, json=fx("images", "scan"))
    env, _, _ = await call(
        "dockhand_get_image_scan", {**E, "image": "nginx:1.27", "scanner": "grype", "limit": 2}
    )
    assert env.data["summary"]["criticalCount"] == 1
    assert "vulnerabilities" not in env.data["summary"]
    assert env.data["findings"]["has_more"] is True
    params = route.calls.last.request.url.params
    assert (params["image"], params["scanner"]) == ("nginx:1.27", "grype")
    dockhand.get("/api/images/scan").respond(200, json={"found": False})
    env, _, _ = await call("dockhand_get_image_scan", {**E, "image": "nginx:1.27"})
    assert env.data == {"found": False}


async def test_get_network_by_id_prefix(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_network"][1])
    env, _, _ = await call("dockhand_get_network", {**E, "network": FRONT[:12]})
    assert env.data["Name"] == "front"
    env, _, _ = await call("dockhand_get_network", {**E, "network": "side"})
    assert env.error is not None
    assert env.error.code == "not_found"


# --- jobs, activity, audit, schedules ---------------------------------------------------------


async def test_job_lines_capped(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    body = fx("jobs", "job")
    body["lines"] = [{"event": "progress", "data": {"n": i}} for i in range(600)]
    dockhand.get(f"/api/jobs/{JOB}").respond(200, json=body)
    env, _, _ = await call("dockhand_get_job", {"job_id": JOB})
    assert len(env.data["lines"]) == 500
    assert env.data["lines"][-1]["data"]["n"] == 599
    assert env.data["lines_dropped"] == 100


async def test_activity_parameter_names(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/activity").respond(200, json=fx("activity", "events"))
    args = {
        **E,
        "container": WEB[:12],
        "actions": ["start", "health_status: healthy"],
        "from_date": "2026-01-01",
        "limit": 2,
    }
    env, _, _ = await call("dockhand_get_activity", args)
    assert env.data["has_more"] is True
    assert env.data["total"] == 5
    params = route.calls.last.request.url.params
    assert params["environmentId"] == "7"
    assert params["containerId"] == WEB[:12]
    assert "containerName" not in params
    assert params["actions"] == "start,health_status: healthy"
    assert params["fromDate"] == "2026-01-01"
    await call("dockhand_get_activity", {"container": "web"})
    assert route.calls.last.request.url.params["containerName"] == "web"
    stats = dockhand.get("/api/activity/stats").respond(200, json=fx("activity", "stats"))
    await call("dockhand_get_activity_stats", E)
    assert stats.calls.last.request.url.params["environment_id"] == "7"


async def test_audit_enterprise_403_is_not_available(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/audit").respond(
        403, json={"error": "Enterprise license required", "status": 403}
    )
    env, _, _ = await call("dockhand_get_audit_log", {})
    assert env.error is not None
    assert env.error.code == "not_available"
    assert env.error.message == "Audit log requires DockHand Enterprise"
    assert env.error.dockhand_status == 403


async def test_audit_parameters_and_page(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/audit").respond(200, json=fx("activity", "audit"))
    env, _, _ = await call(
        "dockhand_get_audit_log", {**E, "usernames": ["admin", "ops"], "entity_types": ["stack"]}
    )
    assert env.data["total"] == 1
    params = route.calls.last.request.url.params
    assert (params["environmentId"], params["usernames"], params["entityTypes"]) == (
        "7",
        "admin,ops",
        "stack",
    )


async def test_schedule_lists_drop_logs(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/schedules").respond(200, json=fx("schedules", "list"))
    env, content, _ = await call("dockhand_list_schedules", {})
    assert "checked web" not in json.dumps(content)
    assert env.data["items"][0]["lastExecution"]["status"] == "success"
    route = dockhand.get("/api/schedules/executions").respond(
        200, json=fx("schedules", "executions")
    )
    env, content, _ = await call(
        "dockhand_list_schedule_executions",
        {"status": "failed", "triggered_by": "cron", "limit": 1},
    )
    assert "checked web" not in json.dumps(content)
    assert env.data["has_more"] is True
    params = route.calls.last.request.url.params
    assert (params["status"], params["triggeredBy"], params["limit"]) == ("failed", "cron", "1")


async def test_schedule_execution_log_capped(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    body = fx("schedules", "execution")
    body["logs"] = "x" * 5000 + "\nlast line\n"
    dockhand.get("/api/schedules/executions/3").respond(200, json=body)
    env, _, _ = await call(
        "dockhand_get_schedule_execution", {"execution_id": 3, "max_bytes": 1024}
    )
    assert env.data["truncated"] is True
    assert env.data["log"].endswith("last line\n")
    assert "logs" not in env.data["execution"]


# --- updates, vulnerabilities, registries, settings --------------------------------------------


async def test_auto_update_one_container(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/auto-update/web").respond(200, json=fx("updates", "one"))
    env, _, _ = await call("dockhand_get_auto_update_settings", {**E, "container_name": "web"})
    assert env.data["setting"]["enabled"] is False
    assert route.calls.last.request.url.params["env"] == "7"


async def test_vulnerabilities_send_env(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/vulnerabilities").respond(200, json=fx("vulnerabilities", "list"))
    env, _, _ = await call(
        "dockhand_list_vulnerabilities", {**E, "severity": "critical", "q": "CVE-2026", "limit": 2}
    )
    assert env.data["has_more"] is True
    assert env.data["summary"]["critical"] == 1
    params = route.calls.last.request.url.params
    assert (params["env"], params["severity"], params["q"], params["limit"]) == (
        "7",
        "critical",
        "CVE-2026",
        "2",
    )
    count = dockhand.get("/api/vulnerabilities/count").respond(
        200, json=fx("vulnerabilities", "count")
    )
    await call("dockhand_get_vulnerability_summary", E)
    assert count.calls.last.request.url.params["env"] == "7"


async def test_image_tags_with_info(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    tags = dockhand.get("/api/registry/tags").respond(200, json=fx("registries", "tags"))
    info = dockhand.get("/api/registry/tag-info").respond(200, json=fx("registries", "tag-info"))
    env, _, _ = await call(
        "dockhand_list_image_tags", {"image": "library/nginx", "page_size": 2, "with_info": True}
    )
    assert env.data["has_more"] is True
    assert env.data["total"] == 40
    assert all(t["info"]["size"] == 600 for t in env.data["items"])
    assert info.call_count == 2
    assert tags.calls.last.request.url.params["pageSize"] == "2"


async def test_settings_scanner_is_settings_only(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_settings"][1])
    await call("dockhand_get_settings", E)
    scanner = next(
        r for r in dockhand.routes if r.calls and "scanner" in str(r.calls.last.request.url)
    )
    params = scanner.calls.last.request.url.params
    assert (params["env"], params["settingsOnly"]) == ("7", "true")
    assert "checkUpdates" not in params


async def test_dashboard_stats_one_or_all(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/dashboard/stats").respond(
        200, json=fx("system", "dashboard-stats")[0]
    )
    env, _, _ = await call("dockhand_get_dashboard_stats", E)
    assert env.data["count"] == 1
    dockhand.get("/api/dashboard/stats").respond(200, json=fx("system", "dashboard-stats"))
    env, _, _ = await call("dockhand_get_dashboard_stats", {})
    assert env.environment_id is None
    assert "env" not in route.calls.last.request.url.params


async def test_system_disk_summarised(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, CASES["dockhand_get_system_info"][1])
    env, _, _ = await call("dockhand_get_system_info", E)
    disk = env.data["disk"]
    assert disk["ImagesCount"] == 2
    assert "Images" not in disk
    assert "Items" not in disk["ImageUsage"]
    env, _, _ = await call("dockhand_get_system_info", {**E, "include_disk": False})
    assert "disk" not in env.data


# --- per-tool resolution and pagination -------------------------------------------------------

RESOLVING = sorted(
    tool
    for tool, (args, _) in CASES.items()
    if {"ref", "network", "image"} & set(args)
    # These pass the image through to DockHand unresolved.
    and tool not in {"dockhand_get_image_scan", "dockhand_list_image_tags"}
)


def _ambiguous_routes(tool: str) -> list[Route]:
    routes = CASES[tool][1]
    out = []
    for method, path, body in routes:
        if path == "/api/containers":
            body = [*body, {**body[0], "id": IDS["CID_WORKER"]}]  # two containers named "web"
        elif path == "/api/networks":
            body = [*body, {**body[0], "id": IDS["NID_BACK"][::-1]}]  # two networks named "front"
        elif path == "/api/images":
            body = [*body, {**body[0], "id": NGINX[:-1] + "0"}]  # two images tagged nginx:1.27
        out.append((method, path, body))
    return out


def _ref_arg(tool: str) -> str:
    args = CASES[tool][0]
    return next(k for k in ("ref", "network", "image") if k in args)


def test_resolving_tools_cover_containers_networks_and_images() -> None:
    assert {_ref_arg(t) for t in RESOLVING} == {"ref", "network", "image"}
    assert len(RESOLVING) == 8  # six container tools, one network, one image


@pytest.mark.parametrize("tool", RESOLVING)
async def test_resolution_exact_missing_ambiguous(
    tool: str, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    args, routes = CASES[tool]
    key = _ref_arg(tool)
    mount(dockhand, routes)
    env, _, _ = await call(tool, args)  # exact
    assert env.ok is True, env.error
    env, _, _ = await call(tool, {**args, key: "absent-name:1" if key == "image" else "absent"})
    assert env.error is not None
    assert env.error.code == "not_found"
    mount(dockhand, _ambiguous_routes(tool))
    env, _, _ = await call(tool, args)
    assert env.error is not None
    assert env.error.code == "ambiguous_name"


LOCALLY_PAGED = {
    "dockhand_list_containers": "/api/containers",
    "dockhand_get_all_container_stats": "/api/containers/stats",
    "dockhand_list_stacks": "/api/stacks",
    "dockhand_list_images": "/api/images",
    "dockhand_list_volumes": "/api/volumes",
    "dockhand_list_stack_deploys": "/api/stacks/shop/deploys",
}


@pytest.mark.parametrize("tool", sorted(LOCALLY_PAGED))
async def test_list_has_more(tool: str, dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    args, routes = CASES[tool]
    mount(dockhand, routes)
    env, _, _ = await call(tool, {**args, "limit": 1})
    assert env.data["count"] == 1
    assert env.data["total"] >= 2
    assert env.data["has_more"] is True
    if tool != "dockhand_list_stack_deploys":  # a newest-N view: no offset
        last = env.data["total"] - 1
        env, _, _ = await call(tool, {**args, "limit": 1, "offset": last})
        assert env.data["count"] == 1
        assert env.data["has_more"] is False
