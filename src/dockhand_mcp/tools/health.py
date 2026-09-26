# SPDX-License-Identifier: Apache-2.0
"""`dockhand_health`: DockHand liveness and database health (both public endpoints)."""

from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from dockhand_mcp.client.envelope import Envelope, from_error, ok
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import Tier, register

TIMEOUT_S: Final = 10.0
API_FIELDS: Final = ("status", "timestamp")
# The spec's documented schema. Authenticated settings:view callers also get connection details,
# which are deliberately not passed through.
DATABASE_FIELDS: Final = (
    "healthy",
    "database",
    "migrationsTable",
    "appliedMigrations",
    "pendingMigrations",
    "tables",
    "timestamp",
)


class HealthInput(BaseModel):
    model_config = ConfigDict(extra="forbid", title="dockhand_health")


def _pick(body: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: body[k] for k in fields if k in body} if isinstance(body, dict) else {}


async def health(ctx: ToolContext, args: HealthInput) -> Envelope:
    try:
        api = await ctx.client.get_json("/api/health", read_timeout=TIMEOUT_S)
    except DockhandError as e:
        return from_error(e)
    warnings: list[str] = []
    database: dict[str, Any] | None = None
    try:
        # An unhealthy database answers 503 with the same body.
        body = await ctx.client.get_json(
            "/api/health/database", read_timeout=TIMEOUT_S, allow_status={503}
        )
        database = _pick(body, DATABASE_FIELDS)
    except DockhandError as e:
        warnings.append(f"database health unavailable: {e.message}")
    return ok({"dockhand": _pick(api, API_FIELDS), "database": database}, warnings=warnings)


SPEC: Final = ToolSpec(
    name="dockhand_health",
    title="DockHand health",
    description=(
        "Check that DockHand is up and its database is healthy. Returns the API status and the "
        "database schema and migration status."
    ),
    input_model=HealthInput,
    handler=health,
    annotations=READ_ANNOTATIONS,
)

register(SPEC, Tier.READ, (("GET", "/api/health"), ("GET", "/api/health/database")))
