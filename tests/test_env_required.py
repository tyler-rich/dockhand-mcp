# SPDX-License-Identifier: Apache-2.0
"""Every request to an endpoint whose environment parameter DockHand requires carries it.

DockHand 1.0.49 made `env` (`envId` on exec) required on the container endpoints, where 1.0.46
let it be omitted for the local Docker host (ARCHIVE §14, 1.0.49). Each tool that declares such
an endpoint is run through its tier's happy-path case, and every request it sends there must carry
the environment it was given. These guard against regression: no tool omitted it before 1.0.49.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import respx
import test_destructive_tools as destructive
import test_operator_tools as operator
import test_read_tools as read
from conftest import ENV, SetEnv

from dockhand_mcp.tools.registry import REGISTRY, Tier

REFERENCE_SPEC = (
    Path(__file__).resolve().parents[1] / "docs" / "api" / "dockhand-openapi-1.0.49.json"
)

# Every operation in the 1.0.49 spec with a required environment query parameter.
ENV_REQUIRED: dict[tuple[str, str], str] = {
    ("POST", "/api/containers/batch-update"): "env",
    ("POST", "/api/containers/batch-update-stream"): "env",
    ("GET", "/api/containers/check-updates"): "env",
    ("POST", "/api/containers/check-updates"): "env",
    ("GET", "/api/containers/pending-updates"): "env",
    ("DELETE", "/api/containers/pending-updates"): "env",
    ("GET", "/api/containers/sizes"): "env",
    ("GET", "/api/containers/stats"): "env",
    ("GET", "/api/containers/{id}"): "env",
    ("DELETE", "/api/containers/{id}"): "env",
    ("GET", "/api/containers/{id}/compose"): "env",
    ("POST", "/api/containers/{id}/exec"): "envId",
    ("POST", "/api/containers/{id}/exec/run"): "envId",
    ("GET", "/api/containers/{id}/files"): "env",
    ("POST", "/api/containers/{id}/files/chmod"): "env",
    ("POST", "/api/containers/{id}/files/chown"): "env",
    ("GET", "/api/containers/{id}/files/content"): "env",
    ("PUT", "/api/containers/{id}/files/content"): "env",
    ("POST", "/api/containers/{id}/files/create"): "env",
    ("DELETE", "/api/containers/{id}/files/delete"): "env",
    ("GET", "/api/containers/{id}/files/download"): "env",
    ("POST", "/api/containers/{id}/files/rename"): "env",
    ("POST", "/api/containers/{id}/files/upload"): "env",
    ("GET", "/api/containers/{id}/inspect"): "env",
    ("GET", "/api/containers/{id}/logs"): "env",
    ("GET", "/api/containers/{id}/logs/stream"): "env",
    ("POST", "/api/containers/{id}/pause"): "env",
    ("POST", "/api/containers/{id}/rename"): "env",
    ("POST", "/api/containers/{id}/restart"): "env",
    ("GET", "/api/containers/{id}/shells"): "env",
    ("POST", "/api/containers/{id}/start"): "env",
    ("GET", "/api/containers/{id}/stats"): "env",
    ("POST", "/api/containers/{id}/stop"): "env",
    ("GET", "/api/containers/{id}/top"): "env",
    ("POST", "/api/containers/{id}/unpause"): "env",
    ("POST", "/api/containers/{id}/update"): "env",
    ("GET", "/api/containers/{id}/version-notes"): "env",
    ("GET", "/api/preferences/favorite-groups"): "env",
    ("GET", "/api/preferences/favorites"): "env",
    ("GET", "/api/system/disk"): "env",
}

AFFECTED = sorted(
    (tool.name, endpoint)
    for tool in REGISTRY.all()
    for endpoint in tool.endpoints
    if endpoint in ENV_REQUIRED
)


def _pattern(template: str) -> re.Pattern[str]:
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)) + "$")


PATTERNS = {endpoint: _pattern(endpoint[1]) for endpoint in ENV_REQUIRED}


def template_of(method: str, path: str) -> tuple[str, str] | None:
    """The env-required operation a request is for; the most literal template wins."""
    matches = [e for e, p in PATTERNS.items() if e[0] == method and p.match(path)]
    return min(matches, key=lambda e: e[1].count("{"), default=None)


def test_list_matches_the_reference_spec() -> None:
    if not REFERENCE_SPEC.exists():
        pytest.skip(f"{REFERENCE_SPEC.name} is not present (git-ignored)")
    spec = json.loads(REFERENCE_SPEC.read_text(encoding="utf-8"))
    found = {
        (method.upper(), path): p["name"]
        for path, ops in spec["paths"].items()
        for method, op in ops.items()
        if isinstance(op, dict)
        for p in op.get("parameters", [])
        if p.get("in") == "query" and p.get("required") and p["name"] in ("env", "envId")
    }
    assert found == ENV_REQUIRED


def test_list_matches_the_clients_generated_list() -> None:
    """The client's guard (#5) refuses exactly these operations without the parameter."""
    from dockhand_mcp.client import env_required

    assert dict(env_required.ENV_REQUIRED) == ENV_REQUIRED


def test_the_container_endpoints_tools_use_are_covered() -> None:
    """The tools this file exercises, so a new one cannot slip past unnoticed."""
    assert {name for name, _ in AFFECTED} == {
        "dockhand_check_container_updates",
        "dockhand_clear_pending_updates",
        "dockhand_generate_container_compose",
        "dockhand_get_all_container_stats",
        "dockhand_get_container",
        "dockhand_get_container_logs",
        "dockhand_get_container_processes",
        "dockhand_get_container_sizes",
        "dockhand_get_container_stats",
        "dockhand_get_pending_updates",
        "dockhand_get_system_info",
        "dockhand_get_version_notes",
        "dockhand_pause_container",
        "dockhand_remove_container",
        "dockhand_rename_container",
        "dockhand_restart_container",
        "dockhand_start_container",
        "dockhand_stop_container",
        "dockhand_unpause_container",
        "dockhand_update_containers",
    }


async def _run(tool: str, dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    tier = next(t.tier for t in REGISTRY.all() if t.name == tool)
    if tier is Tier.READ:
        base_env()
        args, routes = read.CASES[tool]
        read.mount(dockhand, routes)
        envelope: Any = (await read.call(tool, args))[0]
    elif tier is Tier.OPERATOR:
        base_env(DOCKHAND_MCP_PROFILE="operator")
        args, routes = operator.CASES[tool]
        operator.mount(dockhand, routes)
        envelope = (await operator.call(tool, args))[0]
    else:
        base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_MCP_CONFIRM_MODE="param")
        case = destructive.CASES[tool]
        destructive.mount_case(dockhand, case)
        envelope = await destructive.call(tool, {**case.args, "confirm": True})
    assert envelope.ok is True, envelope.error


@pytest.mark.parametrize(("tool", "endpoint"), AFFECTED)
async def test_environment_is_sent(
    tool: str, endpoint: tuple[str, str], dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    await _run(tool, dockhand, base_env)
    requests = [
        c.request
        for c in dockhand.calls
        if template_of(c.request.method, c.request.url.path) == endpoint
    ]
    assert requests, f"{tool}'s case never reached {endpoint}"
    param = ENV_REQUIRED[endpoint]
    for request in requests:
        assert request.url.params.get_list(param) == [str(ENV)], request.url
