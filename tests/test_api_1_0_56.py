# SPDX-License-Identifier: Apache-2.0
"""DockHand 1.0.56 adoption (ARCHIVE §14, 1.0.56).

The spec adds `GET`/`POST /api/exposure-status` and gives the three stack write operations the
optional request fields `pullBase` and `respectPullPolicy`. The GET is classified read and the
POST excluded, and no tool is registered for either. Our stack tools never send the new fields, so
DockHand's own defaults apply (the two regression guards below).
"""

import json
import re
from typing import Any, Final

import pytest
import respx
from conftest import SetEnv
from test_destructive_tools import call as destructive_call
from test_destructive_tools import never_asked
from test_endpoint_map import ENDPOINT_MAP, _entry, parse_endpoint_map, violations
from test_operator_tools import CASES as OPERATOR_CASES
from test_operator_tools import mount

from dockhand_mcp.tools.registry import REGISTRY, Profile, Tier

EXPOSURE_GET: Final = ("GET", "/api/exposure-status")
EXPOSURE_POST: Final = ("POST", "/api/exposure-status")
NEW_FIELDS: Final = ("pullBase", "respectPullPolicy")
# The three operations that gained the fields, and the tools that call each.
STACK_TOOLS: Final = {
    "dockhand_create_stack": ("POST", "/api/stacks"),
    "dockhand_update_stack_compose": ("PUT", "/api/stacks/{name}/compose"),
    "dockhand_deploy_stack": ("POST", "/api/stacks/{name}/deploy"),
}


@pytest.fixture(scope="module")
def emap() -> dict[tuple[str, str], str]:
    return parse_endpoint_map(ENDPOINT_MAP.read_text(encoding="utf-8"))


def test_exposure_status_operations_are_classified(emap: dict[tuple[str, str], str]) -> None:
    assert emap.get(EXPOSURE_GET) == "read"
    assert emap.get(EXPOSURE_POST) == "excluded"


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize(
    ("endpoint", "tier"), [(EXPOSURE_GET, "read"), (EXPOSURE_POST, "excluded")]
)
def test_no_tool_calls_exposure_status_in_any_profile(
    emap: dict[tuple[str, str], str], profile: Profile, endpoint: tuple[str, str], tier: str
) -> None:
    assert emap.get(endpoint) == tier  # classified, not merely absent from the map
    for tool in REGISTRY.tools_for_profile(profile):
        assert endpoint not in tool.endpoints, tool.name


@pytest.mark.parametrize("tier", list(Tier))
def test_dismissing_the_exposure_warning_cannot_be_declared_at_any_tier(
    emap: dict[tuple[str, str], str], tier: Tier
) -> None:
    assert emap.get(EXPOSURE_POST) == "excluded"
    assert violations(_entry(tier, EXPOSURE_POST), emap) != []


def test_the_map_header_states_the_version_honestly() -> None:
    """The 1.0.56 document still reports 1.0.55 as its info.version; the map says both."""
    first = ENDPOINT_MAP.read_text(encoding="utf-8").splitlines()[0]
    assert first == "# DockHand API endpoint map (v1.0.56; spec info.version reports 1.0.55)"


@pytest.fixture
def admin(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_MCP_CONFIRM_MODE="param")


def _json_bodies(dockhand: respx.MockRouter) -> list[Any]:
    return [
        json.loads(c.request.content)
        for c in dockhand.calls
        if c.request.method != "GET" and c.request.content
    ]


def _fields(value: Any) -> set[str]:
    """Every object key anywhere in a JSON body."""
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _fields(v)}
    if isinstance(value, list):
        return {k for v in value for k in _fields(v)}
    return set()


@pytest.mark.parametrize("tool", sorted(STACK_TOOLS))
async def test_stack_tools_never_send_the_pull_fields(
    tool: str, dockhand: respx.MockRouter, admin: None
) -> None:
    """Regression guard: DockHand's defaults for `pullBase`/`respectPullPolicy` must apply."""
    assert STACK_TOOLS[tool] in next(t for t in REGISTRY.all() if t.name == tool).endpoints
    args, routes = OPERATOR_CASES[tool]
    mount(dockhand, routes)
    envelope = await destructive_call(tool, args, human=never_asked)
    assert envelope.ok is True, envelope.error
    sent = [
        c
        for c in dockhand.calls
        if c.request.method != "GET"
        and re.fullmatch(r"/api/stacks(/[^/]+/(compose|deploy))?", c.request.url.path)
    ]
    assert sent, "the stack write was not sent"
    for body in _json_bodies(dockhand):
        assert not set(NEW_FIELDS) & _fields(body)
