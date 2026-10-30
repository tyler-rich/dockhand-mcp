# SPDX-License-Identifier: Apache-2.0
"""`dockhand_get_stack_stats` (#18): per-stack CPU, memory, network and block I/O totals.

The fixture is invented (tests/fixtures/dockhand/stacks/stats.json); its structure matches what
live DockHand 1.0.55 answered.
"""

import respx
from conftest import ENV, SetEnv, load_fixture
from test_read_tools import Called, call, declared

from dockhand_mcp.tools.base import READ_ANNOTATIONS
from dockhand_mcp.tools.registry import REGISTRY, Profile, Tier

TOOL = "dockhand_get_stack_stats"
E = {"environment_id": ENV}
ENDPOINTS = {("GET", "/api/stack-stats")}


def names(env_data: dict) -> list[str]:  # type: ignore[type-arg]
    return [i["name"] for i in env_data["items"]]


async def test_populated_environment_sorted_by_cpu(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    body = load_fixture("stacks", "stats")
    dockhand.get("/api/stack-stats").respond(200, json=body)
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.environment_id == ENV
    assert env.warnings is None
    assert env.data["sort_by"] == "cpu"
    assert (env.data["count"], env.data["total"], env.data["has_more"]) == (3, 3, False)
    assert names(env.data) == ["stack-b", "stack-a", "stack-c"]
    assert env.data["items"][0] == body[1]  # every spec field is kept


async def test_empty_environment(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/stack-stats").respond(200, json=[])
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.data["items"] == []
    assert (env.data["count"], env.data["total"], env.data["has_more"]) == (0, 0, False)


async def test_sort_by_each_measure(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/stack-stats").respond(200, json=load_fixture("stacks", "stats"))
    expected = {
        "cpu": ["stack-b", "stack-a", "stack-c"],
        "memory": ["stack-c", "stack-a", "stack-b"],
        "network": ["stack-b", "stack-a", "stack-c"],
        "block_io": ["stack-c", "stack-a", "stack-b"],
        "name": ["stack-a", "stack-b", "stack-c"],
    }
    for sort_by, order in expected.items():
        env, _, _ = await call(TOOL, {**E, "sort_by": sort_by})
        assert env.ok is True, env.error
        assert env.data["sort_by"] == sort_by
        assert names(env.data) == order, sort_by


async def test_ties_break_by_name(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    row = load_fixture("stacks", "stats")[0]
    dockhand.get("/api/stack-stats").respond(
        200, json=[{**row, "name": "stack-z"}, {**row, "name": "stack-m"}]
    )
    env, _, _ = await call(TOOL, E)
    assert names(env.data) == ["stack-m", "stack-z"]


async def test_limit_applies_after_sorting(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/stack-stats").respond(200, json=load_fixture("stacks", "stats"))
    env, _, _ = await call(TOOL, {**E, "limit": 1})
    assert names(env.data) == ["stack-b"]
    assert (env.data["count"], env.data["total"], env.data["has_more"]) == (1, 3, True)


async def test_limit_is_bounded(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/stack-stats").respond(200, json=[])
    for bad in ({"limit": 0}, {"limit": 501}, {"sort_by": "bogus"}):
        env, _, _ = await call(TOOL, {**E, **bad})
        assert env.error is not None
        assert env.error.code == "validation_error"
    assert route.call_count == 0


async def test_env_sent(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    route = dockhand.get("/api/stack-stats").respond(200, json=[])
    await call(TOOL, E)
    assert route.calls.last.request.url.params["env"] == str(ENV)


async def test_env_sent_when_defaulted(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env(DOCKHAND_DEFAULT_ENVIRONMENT_ID=str(ENV))
    route = dockhand.get("/api/stack-stats").respond(200, json=[])
    env, _, _ = await call(TOOL, {})
    assert env.ok is True, env.error
    assert route.calls.last.request.url.params["env"] == str(ENV)


async def test_only_the_declared_endpoints_are_called(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/stack-stats").respond(200, json=load_fixture("stacks", "stats"))
    called = Called()
    await call(TOOL, E, called)
    assert set(called.endpoints) == ENDPOINTS
    # Plus GET /api/environments, which only F-09 defaulting calls (environment_id omitted).
    assert declared(TOOL) == ENDPOINTS | {("GET", "/api/environments")}


async def test_a_non_array_body_is_an_empty_list(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/stack-stats").respond(200, json={})
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.data["items"] == []


def test_registered_read_tier_in_all_three_profiles() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == TOOL)
    assert entry.tier is Tier.READ
    for profile in Profile:
        assert TOOL in {t.name for t in REGISTRY.tools_for_profile(profile)}, profile


def test_metadata() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == TOOL)
    mcp_tool = entry.tool.to_mcp()  # type: ignore[attr-defined]
    assert mcp_tool.title
    assert mcp_tool.annotations == READ_ANNOTATIONS
    assert mcp_tool.annotations.read_only_hint is True
    assert mcp_tool.output_schema is not None
