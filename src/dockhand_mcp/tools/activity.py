# SPDX-License-Identifier: Apache-2.0
"""Container activity and audit log tools, and clearing the activity log (destructive).

These routes name their filters differently: `/api/activity` takes `environmentId`,
`/api/activity/stats` takes `environment_id`, `/api/audit` takes `environmentId`. Each call
sends exactly the spec's name.
"""

from typing import Any, Final

from pydantic import Field

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.guardrails.names import DOCKER_NAME, HEX_ID, MAX_ENV_ID
from dockhand_mcp.tools._common import (
    PAGE_SCHEMA,
    DestructiveInputs,
    IsoDate,
    ListValue,
    ToolInput,
    add_warnings,
    as_dict,
    destructive_tool,
    dockhand_success,
    limit_field,
    list_body,
    offset_field,
    remote_page,
    run_async_pattern,
    write_budget,
)
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import Tier, register

AUDIT_NOT_AVAILABLE: Final = "Audit log requires DockHand Enterprise"
OPTIONAL_ENV: Final = "Only this environment; all environments when omitted."


def _env_field() -> Any:
    return Field(default=None, ge=1, le=MAX_ENV_ID, description=OPTIONAL_ENV)


def _joined(values: list[str] | None) -> str | None:
    return ",".join(values) if values else None


# --- activity ---------------------------------------------------------------------------------


class ActivityInput(ToolInput):
    environment_id: int | None = _env_field()
    container: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=DOCKER_NAME.pattern,
        description="Only events of this container (ID or name; not resolved).",
    )
    actions: list[ListValue] | None = Field(
        default=None, min_length=1, max_length=20, description="Only these event actions."
    )
    from_date: IsoDate | None = Field(default=None, description="Start of the range (ISO 8601).")
    to_date: IsoDate | None = Field(default=None, description="End of the range (ISO 8601).")
    limit: int = limit_field(50)
    offset: int = offset_field()


async def get_activity(ctx: ToolContext, args: ActivityInput) -> Envelope:
    container_id = container_name = None
    if args.container is not None:
        if HEX_ID.match(args.container):
            container_id = args.container
        else:
            container_name = args.container
    body = await ctx.client.get_json(
        "/api/activity",
        params={
            "environmentId": args.environment_id,
            "containerId": container_id,
            "containerName": container_name,
            "actions": _joined(args.actions),
            "fromDate": args.from_date,
            "toDate": args.to_date,
            "limit": args.limit,
            "offset": args.offset,
        },
    )
    body = body if isinstance(body, dict) else {}
    events = list_body(body.get("events"))
    return ok(
        remote_page(events, body.get("total"), args.offset), environment_id=args.environment_id
    )


register(
    ToolSpec(
        name="dockhand_get_activity",
        title="Get container activity",
        description=(
            "Get container lifecycle events (start, stop, die, health changes and others), "
            "newest first, filtered by environment, container, action or date range."
        ),
        input_model=ActivityInput,
        handler=get_activity,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "container"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/activity"),),
)


class ActivityStatsInput(ToolInput):
    environment_id: int | None = _env_field()


async def get_activity_stats(ctx: ToolContext, args: ActivityStatsInput) -> Envelope:
    body = await ctx.client.get_json(
        "/api/activity/stats", params={"environment_id": args.environment_id}
    )
    return ok(body, environment_id=args.environment_id)


register(
    ToolSpec(
        name="dockhand_get_activity_stats",
        title="Get activity stats",
        description="Get container activity totals: all-time, today, and counts per action.",
        input_model=ActivityStatsInput,
        handler=get_activity_stats,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (("GET", "/api/activity/stats"),),
)

# --- audit ------------------------------------------------------------------------------------


class AuditInput(ToolInput):
    environment_id: int | None = _env_field()
    usernames: list[ListValue] | None = Field(
        default=None, min_length=1, max_length=20, description="Only entries by these users."
    )
    entity_types: list[ListValue] | None = Field(
        default=None, min_length=1, max_length=20, description="Only these entity types."
    )
    actions: list[ListValue] | None = Field(
        default=None, min_length=1, max_length=20, description="Only these actions."
    )
    from_date: IsoDate | None = Field(default=None, description="Start of the range (ISO 8601).")
    to_date: IsoDate | None = Field(default=None, description="End of the range (ISO 8601).")
    limit: int = limit_field(50)
    offset: int = offset_field()


def is_enterprise_required(e: DockhandError) -> bool:
    # The spec's 403 is "Enterprise required, or permission denied"; DockHand's body says which,
    # e.g. {"error":"Enterprise license required","status":403}.
    return e.status == 403 and "enterprise" in (e.body_excerpt or "").lower()


async def get_audit_log(ctx: ToolContext, args: AuditInput) -> Envelope:
    try:
        body = await ctx.client.get_json(
            "/api/audit",
            params={
                "environmentId": args.environment_id,
                "usernames": _joined(args.usernames),
                "entityTypes": _joined(args.entity_types),
                "actions": _joined(args.actions),
                "fromDate": args.from_date,
                "toDate": args.to_date,
                "limit": args.limit,
                "offset": args.offset,
            },
        )
    except DockhandError as e:
        if is_enterprise_required(e):
            return err("not_available", AUDIT_NOT_AVAILABLE, dockhand_status=403)
        raise
    body = body if isinstance(body, dict) else {}
    logs = list_body(body.get("logs"))
    return ok(remote_page(logs, body.get("total"), args.offset), environment_id=args.environment_id)


register(
    ToolSpec(
        name="dockhand_get_audit_log",
        title="Get audit log",
        description=(
            "Get DockHand's audit log of user actions, filtered by user, entity type, action, "
            "environment or date range. Available on DockHand Enterprise only."
        ),
        input_model=AuditInput,
        handler=get_audit_log,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/audit"),),
)


# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.


class ClearActivityInput(DestructiveInputs):
    pass


async def clear_activity_preview(
    ctx: ToolContext, args: ClearActivityInput, env: int | None
) -> Preview:
    stats = as_dict(await ctx.client.get_json("/api/activity/stats"))
    total = stats.get("total")
    return Preview(
        summary=f"Delete every stored container activity event, in all environments: {total} "
        f"event(s), {stats.get('today')} of them from today.",
        data={"activity_stats": stats},
        counts={"events": total if isinstance(total, int) else 0},
        target={},
    )


async def clear_activity_log(
    ctx: ToolContext,
    args: ClearActivityInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def work() -> Envelope:
        answer = await ctx.client.delete_json("/api/activity")
        return dockhand_success(answer, {"cleared": True}, "activity log deletion")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "clear_activity"},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_clear_activity_log",
        title="Clear activity log",
        description=(
            "Delete every stored container activity event, in all environments, after a human "
            "approves. Returns DockHand's answer."
        ),
        input_model=ClearActivityInput,
        preview=clear_activity_preview,
        execute=clear_activity_log,
        audit_args=("wait",),
        env_scoped=False,
    ),
    Tier.DESTRUCTIVE,
    (("GET", "/api/activity/stats"), ("DELETE", "/api/activity")),
)
