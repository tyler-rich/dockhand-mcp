# SPDX-License-Identifier: Apache-2.0
"""Tool registry: tiers, profiles and the DockHand endpoints each tool may call.

Every tool is registered with an explicit tier and the ``(method, path-template)`` pairs it calls,
checked against ``docs/api/ENDPOINT-MAP.md`` by the test suite. At startup the server exposes only
``tools_for_profile(profile, disabled)``; there is no runtime elevation path.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, final, runtime_checkable


class Tier(StrEnum):
    READ = "read"
    OPERATOR = "operator"
    DESTRUCTIVE = "destructive"
    ADMIN = "admin"


class Profile(StrEnum):
    READ_ONLY = "read-only"
    OPERATOR = "operator"
    ADMIN = "admin"


# The `admin` tier is not exposed by any profile in v1 (plan §3).
PROFILE_TIERS: Final[dict[Profile, frozenset[Tier]]] = {
    Profile.READ_ONLY: frozenset({Tier.READ}),
    Profile.OPERATOR: frozenset({Tier.READ, Tier.OPERATOR}),
    Profile.ADMIN: frozenset({Tier.READ, Tier.OPERATOR, Tier.DESTRUCTIVE}),
}

Endpoint = tuple[str, str]

HTTP_METHODS: Final = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
TOOL_NAME: Final = re.compile(r"^dockhand_[a-z][a-z0-9_]*$")


@final
class _NoEndpoints:
    """Marker for a tool that calls no DockHand endpoint."""

    def __repr__(self) -> str:
        return "NO_ENDPOINTS"


NO_ENDPOINTS: Final = _NoEndpoints()


class RegistrationError(ValueError):
    pass


class NamedTool(Protocol):
    @property
    def name(self) -> str: ...


@runtime_checkable
class DescribedTool(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def title(self) -> str: ...
    @property
    def description(self) -> str: ...
    def input_schema(self) -> dict[str, Any]: ...
    def output_schema(self) -> dict[str, Any]: ...


def _sha256(schema: dict[str, Any]) -> str:
    text = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    tier: Tier
    endpoints: tuple[Endpoint, ...]
    tool: NamedTool


def _check_endpoints(name: str, endpoints: object) -> tuple[Endpoint, ...]:
    if endpoints is NO_ENDPOINTS:
        return ()
    if not isinstance(endpoints, tuple) or not endpoints:
        raise RegistrationError(
            f"{name}: endpoints must be a non-empty tuple of (method, path) pairs, "
            "or NO_ENDPOINTS for a tool that calls no DockHand endpoint"
        )
    checked: list[Endpoint] = []
    for endpoint in endpoints:
        if (
            not isinstance(endpoint, tuple)
            or len(endpoint) != 2
            or endpoint[0] not in HTTP_METHODS
            or not isinstance(endpoint[1], str)
            or not endpoint[1].startswith("/")
        ):
            raise RegistrationError(f"{name}: malformed endpoint {endpoint!r}")
        if endpoint in checked:
            raise RegistrationError(f"{name}: duplicate endpoint {endpoint!r}")
        checked.append((endpoint[0], endpoint[1]))
    return tuple(checked)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self, tool: NamedTool, tier: Tier, endpoints: tuple[Endpoint, ...] | _NoEndpoints
    ) -> RegisteredTool:
        name = tool.name
        if not TOOL_NAME.match(name):
            raise RegistrationError(f"tool name {name!r} must match {TOOL_NAME.pattern}")
        if not isinstance(tier, Tier):
            raise RegistrationError(f"{name}: tier must be a Tier, got {tier!r}")
        if name in self._tools:
            raise RegistrationError(f"{name}: already registered")
        entry = RegisteredTool(name, tier, _check_endpoints(name, endpoints), tool)
        self._tools[name] = entry
        return entry

    def all(self) -> tuple[RegisteredTool, ...]:
        return tuple(self._tools[n] for n in sorted(self._tools))

    def tools_for_profile(
        self, profile: Profile, disabled: frozenset[str] = frozenset()
    ) -> tuple[RegisteredTool, ...]:
        tiers = PROFILE_TIERS[profile]
        return tuple(t for t in self.all() if t.tier in tiers and t.name not in disabled)

    def catalogue(self) -> list[dict[str, Any]]:
        """The deterministic catalogue `dockhand-mcp tools` prints (rug-pull detection aid)."""
        out: list[dict[str, Any]] = []
        for t in self.all():
            entry: dict[str, Any] = {"name": t.name}
            if isinstance(t.tool, DescribedTool):
                entry["title"] = t.tool.title
            entry["tier"] = t.tier.value
            entry["endpoints"] = [list(e) for e in t.endpoints]
            if isinstance(t.tool, DescribedTool):
                entry["description"] = t.tool.description
                entry["input_schema_sha256"] = _sha256(t.tool.input_schema())
                entry["output_schema_sha256"] = _sha256(t.tool.output_schema())
            out.append(entry)
        return out


REGISTRY: Final = ToolRegistry()
register = REGISTRY.register
tools_for_profile = REGISTRY.tools_for_profile
