# SPDX-License-Identifier: Apache-2.0
"""The SECURITY §6 checks that need DockHand: used by `serve` (fail closed) and `check` (report).

Two excluded-tier endpoints are called from here and nowhere else (SECURITY §4):
`GET /api/auth/settings` (public; reads `authEnabled`) and `GET /api/roles` (edition probe; only
the HTTP status is used, the body is never read). Per the spec, `/api/roles` is "available in
setup mode or with an enterprise license" and answers 403 "Enterprise license required"
otherwise.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Final

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.config import ConfigError, Settings

log = logging.getLogger(__name__)

TIMEOUT_S: Final = 10.0
AUTH_DISABLED_WARNING: Final = (
    "DockHand authentication is disabled: the MCP profile is the only control over what "
    "this server can do"
)
AUTH_REQUIRED_REASON: Final = "DOCKHAND_TOKEN is required: DockHand reports authentication enabled"
# Values of DockhandReport.token.
ACCEPTED: Final = "accepted"
REJECTED: Final = "rejected"
NOT_CONFIGURED: Final = "not configured"
# One representative list per domain the read tools cover (SECURITY §6: best effort).
PERMISSION_PROBES: Final = ("containers", "stacks", "images", "volumes", "networks")
# A read-tier list, with stopped containers (`all`), for the shared-daemon comparison.
CONTAINERS: Final = "/api/containers"


async def auth_enabled(client: DockhandClient) -> bool:
    """Whether DockHand requires authentication, from the public GET /api/auth/settings.

    Its 401 ("auth is enabled and the caller is not authenticated") and 403 (authenticated but
    missing settings:view) both imply authentication is on.
    """
    try:
        body = await client.get_json("/api/auth/settings", read_timeout=TIMEOUT_S)
    except DockhandError as e:
        if e.status in (401, 403):
            return True
        raise
    enabled = body.get("authEnabled") if isinstance(body, dict) else None
    if not isinstance(enabled, bool):
        raise DockhandError(
            None, "dockhand_http_error", "GET /api/auth/settings did not return authEnabled"
        )
    return enabled


async def verify_serve_preconditions(settings: Settings, client: DockhandClient) -> None:
    """Fail closed when no DockHand token is configured and DockHand requires one."""
    if settings.dockhand_token is not None:
        return
    try:
        enabled = await auth_enabled(client)
    except DockhandError as e:
        raise ConfigError(
            "DOCKHAND_TOKEN is not set and the server cannot confirm DockHand authentication "
            f"is disabled: {e.message}"
        ) from None
    if enabled:
        raise ConfigError(AUTH_REQUIRED_REASON)
    log.warning(AUTH_DISABLED_WARNING)


@dataclass
class DockhandReport:
    health: str = "unknown"
    database_healthy: bool | None = None
    auth_enabled: bool | None = None
    token: str = NOT_CONFIGURED
    edition: str = "unknown"
    environments: int | None = None
    permissions: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        del out["problems"], out["warnings"]
        return out


def _outcome(e: DockhandError) -> str:
    if e.status in (401, 403):
        return f"denied ({e.status})"
    return f"error ({e.status if e.status is not None else e.code})"


def _label(environment: Mapping[str, Any]) -> str:
    """`id (name)`, the name DockHand's, whitespace-collapsed and cut to 64 characters."""
    name = environment.get("name")
    text = " ".join(name.split())[:64] if isinstance(name, str) else "?"
    return f"{environment['id']} ({text})"


async def shared_daemon_warnings(client: DockhandClient, environments: Sequence[Any]) -> list[str]:
    """A warning for each pair of environments whose container lists share an id: they point at
    one Docker daemon, where stacks collide across them (#19, #21). Only ids and names are
    reported, never container details."""
    warnings: list[str] = []
    seen: list[tuple[Mapping[str, Any], frozenset[str]]] = []
    for environment in environments:
        if not isinstance(environment, dict) or not isinstance(environment.get("id"), int):
            continue
        try:
            body = await client.get_json(
                CONTAINERS,
                params={"env": environment["id"], "all": True},
                read_timeout=TIMEOUT_S,
            )
        except DockhandError as e:
            warnings.append(
                f"cannot compare environment {_label(environment)} with the others for a shared "
                f"Docker daemon: {e.message}"
            )
            continue
        ids = frozenset(
            item["id"]
            for item in (body if isinstance(body, list) else [])
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]
        )
        for other, other_ids in seen:
            if ids & other_ids:
                warnings.append(
                    f"Environments {_label(other)} and {_label(environment)} appear to share one "
                    "Docker daemon. Stacks can collide across them. Point each environment at "
                    "its own daemon."
                )
        seen.append((environment, ids))
    return warnings


async def run_checks(settings: Settings, client: DockhandClient) -> DockhandReport:
    report = DockhandReport()
    try:
        api = await client.get_json("/api/health", read_timeout=TIMEOUT_S)
    except DockhandError as e:
        report.health = "unreachable" if e.status is None else f"error ({e.status})"
        report.problems.append(f"DockHand health check failed at DOCKHAND_URL: {e.message}")
        return report
    report.health = str(api.get("status", "ok")) if isinstance(api, dict) else "ok"
    try:
        db = await client.get_json(
            "/api/health/database", read_timeout=TIMEOUT_S, allow_status={503}
        )
        if isinstance(db, dict) and isinstance(db.get("healthy"), bool):
            report.database_healthy = db["healthy"]
    except DockhandError as e:
        report.warnings.append(f"database health unavailable: {e.message}")

    try:
        report.auth_enabled = await auth_enabled(client)
    except DockhandError as e:
        report.problems.append(f"cannot read DockHand's authentication setting: {e.message}")
    token_set = settings.dockhand_token is not None
    if not token_set and report.auth_enabled:
        report.problems.append(AUTH_REQUIRED_REASON)
    if report.auth_enabled is False:
        report.warnings.append(AUTH_DISABLED_WARNING)

    environments: list[Any] = []
    if token_set or report.auth_enabled is False:
        try:
            body = await client.get_json("/api/environments", read_timeout=TIMEOUT_S)
            environments = body if isinstance(body, list) else []
            report.environments = len(environments)
            if token_set:
                report.token = ACCEPTED
        except DockhandError as e:
            if e.status == 401:
                report.token = REJECTED if token_set else report.token
                report.problems.append(
                    "DockHand rejected the configured token (DOCKHAND_TOKEN, HTTP 401)"
                )
            elif token_set and e.status == 403:
                report.token = ACCEPTED
                report.warnings.append("the token's user cannot list environments (HTTP 403)")
            else:
                report.problems.append(f"cannot list environments: {e.message}")

    try:
        status = await client.probe_status("GET", "/api/roles")
        if status == 403:
            report.edition = "free"
        elif status == 200 and report.auth_enabled:
            report.edition = "enterprise"
    except DockhandError as e:
        report.warnings.append(f"edition probe failed: {e.message}")

    if len(environments) > 1:
        report.warnings += await shared_daemon_warnings(client, environments)

    env_id = settings.dockhand_default_environment_id
    if env_id is None and environments and isinstance(environments[0], dict):
        first = environments[0].get("id")
        env_id = first if isinstance(first, int) else None
    if env_id is not None:
        for domain in PERMISSION_PROBES:
            try:
                await client.get_json(
                    f"/api/{domain}", params={"env": env_id}, read_timeout=TIMEOUT_S
                )
                report.permissions[domain] = "ok"
            except DockhandError as e:
                report.permissions[domain] = _outcome(e)
    return report
