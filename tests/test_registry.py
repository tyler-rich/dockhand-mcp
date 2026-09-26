# SPDX-License-Identifier: Apache-2.0
"""Tool registry: tiers, profiles, ordering and endpoint declarations (ARCHITECTURE §2)."""

from dataclasses import dataclass

import pytest
from conftest import destructive_tool_names, operator_tool_names, read_tool_names

import dockhand_mcp.tools  # noqa: F401 - registers every tool
from dockhand_mcp.tools.registry import (
    NO_ENDPOINTS,
    REGISTRY,
    Profile,
    RegistrationError,
    Tier,
    ToolRegistry,
)

GET_HEALTH = (("GET", "/api/health"),)


@dataclass(frozen=True)
class FakeTool:
    name: str


def names(
    registry: ToolRegistry, profile: Profile, disabled: frozenset[str] = frozenset()
) -> list[str]:
    return [t.name for t in registry.tools_for_profile(profile, disabled)]


@pytest.fixture
def populated() -> ToolRegistry:
    r = ToolRegistry()
    r.register(FakeTool("dockhand_read_b"), Tier.READ, GET_HEALTH)
    r.register(FakeTool("dockhand_destroy"), Tier.DESTRUCTIVE, (("DELETE", "/api/images/{id}"),))
    r.register(FakeTool("dockhand_admin_thing"), Tier.ADMIN, (("PUT", "/api/settings/general"),))
    r.register(
        FakeTool("dockhand_operate"), Tier.OPERATOR, (("POST", "/api/containers/{id}/start"),)
    )
    r.register(FakeTool("dockhand_read_a"), Tier.READ, GET_HEALTH)
    return r


def test_default_registry_holds_the_read_operator_and_destructive_tiers() -> None:
    read, operator, destructive = read_tool_names(), operator_tool_names(), destructive_tool_names()
    everything = sorted(read + operator + destructive)
    assert [t.name for t in REGISTRY.all()] == everything
    assert [t.name for t in REGISTRY.tools_for_profile(Profile.READ_ONLY)] == read
    assert [t.name for t in REGISTRY.tools_for_profile(Profile.OPERATOR)] == sorted(read + operator)
    assert [t.name for t in REGISTRY.tools_for_profile(Profile.ADMIN)] == everything
    assert {t.tier for t in REGISTRY.all()} == {Tier.READ, Tier.OPERATOR, Tier.DESTRUCTIVE}


def test_read_only_profile_gets_read_tier_only(populated: ToolRegistry) -> None:
    assert names(populated, Profile.READ_ONLY) == ["dockhand_read_a", "dockhand_read_b"]


def test_operator_profile_gets_read_and_operator(populated: ToolRegistry) -> None:
    assert names(populated, Profile.OPERATOR) == [
        "dockhand_operate",
        "dockhand_read_a",
        "dockhand_read_b",
    ]


def test_admin_profile_gets_destructive_but_never_admin_tier(populated: ToolRegistry) -> None:
    got = names(populated, Profile.ADMIN)
    assert got == ["dockhand_destroy", "dockhand_operate", "dockhand_read_a", "dockhand_read_b"]
    assert "dockhand_admin_thing" not in got


def test_admin_tier_never_exposed_by_any_profile(populated: ToolRegistry) -> None:
    for profile in Profile:
        assert all(t.tier is not Tier.ADMIN for t in populated.tools_for_profile(profile))


def test_disabled_tools_are_removed(populated: ToolRegistry) -> None:
    got = names(populated, Profile.ADMIN, frozenset({"dockhand_read_a", "dockhand_destroy"}))
    assert got == ["dockhand_operate", "dockhand_read_b"]


def test_ordering_is_deterministic() -> None:
    a, b = ToolRegistry(), ToolRegistry()
    tool_names = ["dockhand_c", "dockhand_a", "dockhand_b"]
    for n in tool_names:
        a.register(FakeTool(n), Tier.READ, GET_HEALTH)
    for n in reversed(tool_names):
        b.register(FakeTool(n), Tier.READ, GET_HEALTH)
    assert names(a, Profile.READ_ONLY) == names(b, Profile.READ_ONLY) == sorted(tool_names)
    assert a.catalogue() == b.catalogue()


def test_register_rejects_empty_endpoints() -> None:
    r = ToolRegistry()
    with pytest.raises(RegistrationError, match="NO_ENDPOINTS"):
        r.register(FakeTool("dockhand_x"), Tier.READ, ())
    assert r.all() == ()


def test_register_accepts_explicit_no_endpoints() -> None:
    r = ToolRegistry()
    entry = r.register(FakeTool("dockhand_get_operation"), Tier.READ, NO_ENDPOINTS)
    assert entry.endpoints == ()
    assert names(r, Profile.READ_ONLY) == ["dockhand_get_operation"]


@pytest.mark.parametrize(
    "endpoints",
    [
        (("get", "/api/health"),),
        (("GET", "api/health"),),
        (("TRACE", "/api/health"),),
        (("GET",),),
        ("GET /api/health",),
        (("GET", "/api/health"), ("GET", "/api/health")),
    ],
)
def test_register_rejects_malformed_endpoints(endpoints: object) -> None:
    with pytest.raises(RegistrationError):
        ToolRegistry().register(FakeTool("dockhand_x"), Tier.READ, endpoints)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["list_stacks", "dockhand_ListStacks", "dockhand_", "dockhand-x"])
def test_register_rejects_bad_names(name: str) -> None:
    with pytest.raises(RegistrationError):
        ToolRegistry().register(FakeTool(name), Tier.READ, GET_HEALTH)


def test_register_rejects_duplicates() -> None:
    r = ToolRegistry()
    r.register(FakeTool("dockhand_x"), Tier.READ, GET_HEALTH)
    with pytest.raises(RegistrationError):
        r.register(FakeTool("dockhand_x"), Tier.OPERATOR, GET_HEALTH)


def test_register_requires_a_tier() -> None:
    with pytest.raises(RegistrationError):
        ToolRegistry().register(FakeTool("dockhand_x"), "read", GET_HEALTH)  # type: ignore[arg-type]
