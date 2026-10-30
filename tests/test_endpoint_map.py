# SPDX-License-Identifier: Apache-2.0
"""Every registered tool declares only endpoints its tier permits (docs/api/ENDPOINT-MAP.md).

Passes vacuously until tools exist; it gates S1-S3b.
"""

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import conftest
import pytest
from conftest import reference_spec

import dockhand_mcp.tools
from dockhand_mcp.tools.registry import REGISTRY, Profile, RegisteredTool, Tier

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT_MAP = ROOT / "docs" / "api" / "ENDPOINT-MAP.md"
GENERATOR = ROOT / "scripts" / "gen-endpoint-map.py"
ENV_REQUIRED_MODULE = ROOT / "src" / "dockhand_mcp" / "client" / "env_required.py"
ROW = re.compile(r"^\| `(?P<method>[A-Z]+)` \| `(?P<path>[^`]+)` \| \*\*(?P<tier>[a-z]+)\*\* \|")
MAP_TIERS = {"read", "operator", "destructive", "admin", "split", "excluded"}

# Endpoint tiers each tool tier may declare. `excluded` and `admin` are never allowed.
ALLOWED: dict[Tier, frozenset[str]] = {
    Tier.READ: frozenset({"read"}),
    Tier.OPERATOR: frozenset({"read", "operator", "split"}),
    Tier.DESTRUCTIVE: frozenset({"read", "operator", "split", "destructive"}),
    Tier.ADMIN: frozenset(),
}


def parse_endpoint_map(text: str) -> dict[tuple[str, str], str]:
    emap: dict[tuple[str, str], str] = {}
    for line in text.splitlines():
        m = ROW.match(line)
        if m:
            key = (m["method"], m["path"])
            assert key not in emap, f"duplicate row {key}"
            emap[key] = m["tier"]
    return emap


def violations(tool: RegisteredTool, emap: dict[tuple[str, str], str]) -> list[str]:
    found = []
    for endpoint in tool.endpoints:
        tier = emap.get(endpoint)
        if tier is None:
            found.append(f"{tool.name}: {endpoint} is not in ENDPOINT-MAP.md")
        elif tier not in ALLOWED[tool.tier]:
            found.append(f"{tool.name} ({tool.tier}): {endpoint} is {tier}")
    return found


@pytest.fixture(scope="module")
def emap() -> dict[tuple[str, str], str]:
    return parse_endpoint_map(ENDPOINT_MAP.read_text(encoding="utf-8"))


def test_map_parses_completely(emap: dict[tuple[str, str], str]) -> None:
    header = re.search(r"(\d+) operations", ENDPOINT_MAP.read_text(encoding="utf-8"))
    assert header is not None
    assert len(emap) == int(header[1])
    assert set(emap.values()) <= MAP_TIERS


def _generator() -> Any:
    loader = importlib.util.spec_from_file_location("gen_endpoint_map", GENERATOR)
    assert loader is not None and loader.loader is not None
    generator = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(generator)
    return generator


def test_map_is_generated_from_the_reference_spec(capsys: pytest.CaptureFixture[str]) -> None:
    """The committed map is the generator's output for the local, git-ignored reference spec."""
    spec = reference_spec()
    if not spec.exists():
        pytest.skip(f"{spec.name} is not present (git-ignored; set DOCKHAND_MCP_SPEC_PATH)")
    _generator().main(str(spec))
    assert capsys.readouterr().out == ENDPOINT_MAP.read_text(encoding="utf-8")


def test_env_required_is_generated_from_the_reference_spec(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The client's list of env-required operations is the generator's output for the spec (#5)."""
    spec = reference_spec()
    if not spec.exists():
        pytest.skip(f"{spec.name} is not present (git-ignored; set DOCKHAND_MCP_SPEC_PATH)")
    _generator().main(str(spec), env_required=True)
    assert capsys.readouterr().out == ENV_REQUIRED_MODULE.read_text(encoding="utf-8")


def test_registered_tools_respect_the_map(emap: dict[tuple[str, str], str]) -> None:
    assert dockhand_mcp.tools  # imported so every tool module has registered
    problems = [v for tool in REGISTRY.all() for v in violations(tool, emap)]
    assert problems == []


@dataclass(frozen=True)
class _Tool:
    name: str


def _entry(tier: Tier, *endpoints: tuple[str, str]) -> RegisteredTool:
    return RegisteredTool(
        name="dockhand_t", tier=tier, endpoints=endpoints, tool=_Tool("dockhand_t")
    )


@pytest.mark.parametrize(
    ("tier", "endpoint", "ok"),
    [
        (Tier.READ, ("GET", "/api/containers"), True),
        (Tier.READ, ("POST", "/api/containers/{id}/start"), False),  # operator
        (Tier.READ, ("POST", "/api/batch"), False),  # split
        (Tier.OPERATOR, ("POST", "/api/containers/{id}/start"), True),
        (Tier.OPERATOR, ("POST", "/api/batch"), True),
        (Tier.OPERATOR, ("DELETE", "/api/activity"), False),  # destructive
        (Tier.DESTRUCTIVE, ("DELETE", "/api/activity"), True),
        (Tier.DESTRUCTIVE, ("POST", "/api/containers/{id}/exec"), False),  # excluded
        (Tier.DESTRUCTIVE, ("GET", "/api/auth/tokens"), False),  # excluded
        (Tier.DESTRUCTIVE, ("GET", "/api/not-a-real-endpoint"), False),  # absent
    ],
)
def test_checker_itself(
    emap: dict[tuple[str, str], str], tier: Tier, endpoint: tuple[str, str], ok: bool
) -> None:
    assert (violations(_entry(tier, endpoint), emap) == []) is ok


def test_checker_rejects_admin_endpoints(emap: dict[tuple[str, str], str]) -> None:
    admin = next(k for k, v in emap.items() if v == "admin")
    for tier in (Tier.READ, Tier.OPERATOR, Tier.DESTRUCTIVE):
        assert violations(_entry(tier, admin), emap) != []


# The operations DockHand 1.0.49 added, with the tier each was given (ARCHIVE §14, 1.0.49).
NEW_IN_1_0_49: dict[tuple[str, str], str] = {
    ("POST", "/api/containers/{id}/exec/run"): "excluded",
    ("POST", "/api/containers/{id}/files/chown"): "excluded",
    ("GET", "/api/tags"): "read",
    ("POST", "/api/tags"): "admin",
    ("PUT", "/api/tags/{id}"): "admin",
    ("DELETE", "/api/tags/{id}"): "admin",
    ("GET", "/api/stack-tags"): "read",
    ("GET", "/api/container-tags"): "read",
    ("GET", "/api/container-tags/{name}"): "read",
    ("PUT", "/api/container-tags/{name}"): "operator",
    ("GET", "/api/stacks/{name}/tags"): "read",
    ("PUT", "/api/stacks/{name}/tags"): "operator",
}
EXEC_AND_CHOWN = (
    ("POST", "/api/containers/{id}/exec/run"),
    ("POST", "/api/containers/{id}/files/chown"),
)


def test_operations_new_in_1_0_49_are_classified(emap: dict[tuple[str, str], str]) -> None:
    assert {k: emap.get(k) for k in NEW_IN_1_0_49} == NEW_IN_1_0_49


def test_chown_has_the_tier_of_chmod(emap: dict[tuple[str, str], str]) -> None:
    assert emap[("POST", "/api/containers/{id}/files/chmod")] == "excluded"
    assert emap[("POST", "/api/containers/{id}/files/chown")] == "excluded"


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize("endpoint", EXEC_AND_CHOWN)
def test_exec_run_and_chown_are_unreachable(
    emap: dict[tuple[str, str], str], profile: Profile, endpoint: tuple[str, str]
) -> None:
    assert emap.get(endpoint) == "excluded"
    for tool in REGISTRY.tools_for_profile(profile):
        assert endpoint not in tool.endpoints, tool.name
    # No tool tier may declare it, so a tool that tried would fail registration's map check.
    for tier in Tier:
        assert violations(_entry(tier, endpoint), emap) != []


# The operations DockHand 1.0.55 added, with the tier each was given (ARCHIVE §14, 1.0.55).
NEW_EXCLUDED_IN_1_0_55: tuple[tuple[str, str], ...] = (
    # passkey sign-in and registration (auth) and the user's own passkeys (profile)
    ("POST", "/api/auth/passkeys/login/options"),
    ("POST", "/api/auth/passkeys/login/verify"),
    ("POST", "/api/auth/passkeys/register/options"),
    ("POST", "/api/auth/passkeys/register/verify"),
    ("GET", "/api/profile/passkeys"),
    ("DELETE", "/api/profile/passkeys/{id}"),
    # UI preferences
    ("GET", "/api/preferences/environment-order"),
    ("POST", "/api/preferences/environment-order"),
    ("DELETE", "/api/preferences/environment-order"),
    ("GET", "/api/preferences/language"),
    ("PUT", "/api/preferences/language"),
    ("GET", "/api/preferences/tag-order"),
    ("POST", "/api/preferences/tag-order"),
    ("DELETE", "/api/preferences/tag-order"),
    # the global default secret provider
    ("GET", "/api/secret-providers/default"),
    ("PUT", "/api/secret-providers/default"),
    # environment state reports: the export and the scheduled-report configuration
    ("GET", "/api/environments/report"),
    ("GET", "/api/environments/{id}/report"),
    ("POST", "/api/environments/{id}/report"),
)
NEW_IN_1_0_55: dict[tuple[str, str], str] = {
    **dict.fromkeys(NEW_EXCLUDED_IN_1_0_55, "excluded"),
    ("GET", "/api/stack-stats"): "read",
    ("GET", "/api/scheduled-actions/{containerName}"): "read",
    ("PUT", "/api/scheduled-actions/{containerName}"): "operator",
    ("GET", "/api/settings/minimum-release-age"): "read",
    ("POST", "/api/settings/minimum-release-age"): "admin",
    ("GET", "/api/settings/pinned-digest-report"): "read",
    ("POST", "/api/settings/pinned-digest-report"): "admin",
}


def test_operations_new_in_1_0_55_are_classified(emap: dict[tuple[str, str], str]) -> None:
    assert len(NEW_IN_1_0_55) == 26
    assert {k: emap.get(k) for k in NEW_IN_1_0_55} == NEW_IN_1_0_55


def test_new_settings_operations_have_the_tiers_of_existing_settings_operations(
    emap: dict[tuple[str, str], str],
) -> None:
    assert emap[("GET", "/api/settings/semver")] == "read"
    assert emap[("POST", "/api/settings/semver")] == "admin"
    for name in ("minimum-release-age", "pinned-digest-report"):
        assert emap[("GET", f"/api/settings/{name}")] == emap[("GET", "/api/settings/semver")]
        assert emap[("POST", f"/api/settings/{name}")] == emap[("POST", "/api/settings/semver")]


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize("endpoint", NEW_EXCLUDED_IN_1_0_55)
def test_operations_excluded_in_1_0_55_are_unreachable(
    emap: dict[tuple[str, str], str], profile: Profile, endpoint: tuple[str, str]
) -> None:
    assert emap.get(endpoint) == "excluded"
    for tool in REGISTRY.tools_for_profile(profile):
        assert endpoint not in tool.endpoints, tool.name
    # No tool tier may declare it, so a tool that tried would fail registration's map check.
    for tier in Tier:
        assert violations(_entry(tier, endpoint), emap) != []


@pytest.mark.parametrize("endpoint", list(NEW_IN_1_0_55))
def test_only_the_adopted_operations_new_in_1_0_55_have_a_tool(endpoint: tuple[str, str]) -> None:
    adopted = {("GET", "/api/stack-stats"): {"dockhand_get_stack_stats"}}  # #18
    callers = {tool.name for tool in REGISTRY.all() if endpoint in tool.endpoints}
    assert callers == adopted.get(endpoint, set())


def test_spec_path_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DOCKHAND_MCP_SPEC_PATH locates the spec, so a worktree needs no copy of it."""
    spec = tmp_path / "spec-copy.json"
    spec.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("DOCKHAND_MCP_SPEC_PATH", str(spec))
    assert reference_spec() == spec
    monkeypatch.delenv("DOCKHAND_MCP_SPEC_PATH")
    monkeypatch.setattr(conftest, "_SPEC_PATH_AT_IMPORT", None)  # as if unset at pytest start
    assert reference_spec() == ROOT / "docs" / "api" / "dockhand-openapi-1.0.55.json"
