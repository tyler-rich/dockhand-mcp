# SPDX-License-Identifier: Apache-2.0
"""`dockhand_list_tags` (#3): the tag catalogue plus which containers and stacks carry each tag.

Fixtures are invented (tests/fixtures/dockhand/tags/): live DockHand 1.0.49 had no tags, so the
populated shapes come from the spec's descriptions.
"""

from typing import Any

import respx
from conftest import ENV, SetEnv, load_fixture
from test_read_tools import Called, call, declared

from dockhand_mcp.tools.base import READ_ANNOTATIONS
from dockhand_mcp.tools.registry import REGISTRY, Profile, Tier

TOOL = "dockhand_list_tags"
E = {"environment_id": ENV}
TAG_ENDPOINTS = {
    ("GET", "/api/tags"),
    ("GET", "/api/container-tags"),
    ("GET", "/api/stack-tags"),
}


def mount(
    dockhand: respx.MockRouter,
    catalogue: Any = None,
    containers: Any = None,
    stacks: Any = None,
) -> tuple[respx.Route, respx.Route, respx.Route]:
    return (
        dockhand.get("/api/tags").respond(
            200, json=load_fixture("tags", "catalogue") if catalogue is None else catalogue
        ),
        dockhand.get("/api/container-tags").respond(
            200, json=load_fixture("tags", "containers") if containers is None else containers
        ),
        dockhand.get("/api/stack-tags").respond(
            200, json=load_fixture("tags", "stacks") if stacks is None else stacks
        ),
    )


async def test_ids_resolved_to_names(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand)
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.environment_id == ENV
    assert env.warnings is None
    assert env.data == {
        "tags": [
            {"id": 1, "name": "tag-x", "color": "green"},
            {"id": 2, "name": "tag-y", "color": "blue"},
            {"id": 3, "name": "tag-z", "color": "red"},
        ],
        # Untagged resources (db-1, stack-b) are omitted.
        "containers": {"web-1": ["tag-x", "tag-y"], "worker-1": ["tag-z"]},
        "stacks": {"stack-a": ["tag-x"]},
    }


async def test_missing_id_is_shown_as_hash_id_with_a_warning(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, containers={"web-1": [1, 9]}, stacks={"stack-a": [9, 12]})
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.data["containers"] == {"web-1": ["tag-x", "#9"]}
    assert env.data["stacks"] == {"stack-a": ["#9", "#12"]}
    assert env.warnings is not None
    assert len(env.warnings) == 1
    assert "9, 12" in env.warnings[0]
    assert "catalogue" in env.warnings[0]


async def test_empty_environment(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    # The live 1.0.49 shapes with no tags defined.
    mount(dockhand, catalogue={"tags": []}, containers={}, stacks={})
    env, _, _ = await call(TOOL, E)
    assert env.ok is True, env.error
    assert env.data == {"tags": [], "containers": {}, "stacks": {}}
    assert env.warnings is None


async def test_env_sent_on_both_per_environment_reads(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    catalogue, containers, stacks = mount(dockhand)
    await call(TOOL, E)
    assert containers.calls.last.request.url.params["env"] == str(ENV)
    assert stacks.calls.last.request.url.params["env"] == str(ENV)
    # The catalogue is global: the spec gives it no parameters.
    assert not catalogue.calls.last.request.url.params


async def test_env_sent_when_defaulted(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env(DOCKHAND_DEFAULT_ENVIRONMENT_ID=str(ENV))
    _, containers, stacks = mount(dockhand)
    env, _, _ = await call(TOOL, {})
    assert env.ok is True, env.error
    assert containers.calls.last.request.url.params["env"] == str(ENV)
    assert stacks.calls.last.request.url.params["env"] == str(ENV)


async def test_only_the_three_tag_endpoints_are_called(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand)
    called = Called()
    await call(TOOL, E, called)
    assert set(called.endpoints) == TAG_ENDPOINTS
    assert len(called.endpoints) == 3
    # Plus GET /api/environments, which only F-09 defaulting calls (environment_id omitted).
    assert declared(TOOL) == TAG_ENDPOINTS | {("GET", "/api/environments")}


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
    data = mcp_tool.output_schema["properties"]["data"]["anyOf"][0]
    assert set(data["required"]) == {"tags", "containers", "stacks"}
