# SPDX-License-Identifier: Apache-2.0
"""Schedule tools: the schedule list, execution history, one execution with its log; run and
toggle (operator, limited to non-destructive schedule types).

Execution logs appear only in `dockhand_get_schedule_execution`, size-capped; the list tools drop
them (live DockHand embeds each execution's full log in the lists).
"""

from typing import Any, Final, Literal

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.guardrails.names import MAX_ENV_ID
from dockhand_mcp.tools._common import (
    PAGE_SCHEMA,
    IsoDate,
    ToolInput,
    WriteInputs,
    add_warnings,
    cap_text,
    fail,
    limit_field,
    list_body,
    max_bytes_field,
    offset_field,
    page,
    remote_page,
    run_async_pattern,
    text_schema,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.registry import Tier, register

LOG_KEYS: Final = ("log", "logs")


def without_logs(execution: Any) -> Any:
    if not isinstance(execution, dict):
        return execution
    return {k: v for k, v in execution.items() if k not in LOG_KEYS}


def _schedule(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    out = dict(item)
    if "lastExecution" in out:
        out["lastExecution"] = without_logs(out["lastExecution"])
    if isinstance(out.get("recentExecutions"), list):
        out["recentExecutions"] = [without_logs(e) for e in out["recentExecutions"]]
    return out


class ListSchedulesInput(ToolInput):
    pass


async def list_schedules(ctx: ToolContext, args: ListSchedulesInput) -> Envelope:
    body = await ctx.client.get_json("/api/schedules")
    items = body.get("schedules") if isinstance(body, dict) else None
    rows = [_schedule(i) for i in list_body(items)]
    return ok(page(rows, max(len(rows), 1), 0))


register(
    ToolSpec(
        name="dockhand_list_schedules",
        title="List schedules",
        description=(
            "List DockHand's schedules (auto-updates, git syncs, image prunes, system jobs) with "
            "their cron expression, next run and recent execution status."
        ),
        input_model=ListSchedulesInput,
        handler=list_schedules,
        annotations=READ_ANNOTATIONS,
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/schedules"),),
)


class ListExecutionsInput(ToolInput):
    schedule_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        description="Only this schedule type, e.g. container_update or git_stack_sync.",
    )
    schedule_id: int | None = Field(
        default=None, ge=1, le=2**31 - 1, description="Only this schedule."
    )
    environment_id: int | None = Field(
        default=None, ge=1, le=MAX_ENV_ID, description="Only this environment."
    )
    status: Literal["queued", "running", "success", "warning", "failed", "skipped"] | None = Field(
        default=None, description="Only executions with this status."
    )
    triggered_by: Literal["cron", "webhook", "manual"] | None = Field(
        default=None, description="Only executions started this way."
    )
    from_date: IsoDate | None = Field(default=None, description="Start of the range (ISO 8601).")
    to_date: IsoDate | None = Field(default=None, description="End of the range (ISO 8601).")
    limit: int = limit_field(50, 200)
    offset: int = offset_field()


async def list_schedule_executions(ctx: ToolContext, args: ListExecutionsInput) -> Envelope:
    body = await ctx.client.get_json(
        "/api/schedules/executions",
        params={
            "scheduleType": args.schedule_type,
            "scheduleId": args.schedule_id,
            "environmentId": args.environment_id,
            "status": args.status,
            "triggeredBy": args.triggered_by,
            "fromDate": args.from_date,
            "toDate": args.to_date,
            "limit": args.limit,
            "offset": args.offset,
        },
    )
    body = body if isinstance(body, dict) else {}
    rows = [without_logs(e) for e in list_body(body.get("executions"))]
    return ok(remote_page(rows, body.get("total"), args.offset), environment_id=args.environment_id)


register(
    ToolSpec(
        name="dockhand_list_schedule_executions",
        title="List schedule executions",
        description=(
            "List schedule execution history, newest first, filtered by schedule, environment, "
            "status, trigger or date range. Logs are omitted."
        ),
        input_model=ListExecutionsInput,
        handler=list_schedule_executions,
        annotations=READ_ANNOTATIONS,
        audit_args=("schedule_type", "schedule_id", "environment_id"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/schedules/executions"),),
)


class GetExecutionInput(ToolInput):
    execution_id: int = Field(ge=1, le=2**31 - 1, description="Execution id, as listed.")
    max_bytes: int = max_bytes_field("log text")


async def get_schedule_execution(ctx: ToolContext, args: GetExecutionInput) -> Envelope:
    body = await ctx.client.get_json(
        "/api/schedules/executions/{id}", path_params={"id": args.execution_id}
    )
    body = body if isinstance(body, dict) else {}
    # The spec names the field `log`; live list responses use `logs`.
    text = next((body[k] for k in LOG_KEYS if isinstance(body.get(k), str)), "")
    return ok({"execution": without_logs(body), **cap_text(text, args.max_bytes, key="log")})


register(
    ToolSpec(
        name="dockhand_get_schedule_execution",
        title="Get schedule execution",
        description=(
            "Get one schedule execution with its status, timing and log text, capped in size, "
            "with a flag when the start of the log was dropped."
        ),
        input_model=GetExecutionInput,
        handler=get_schedule_execution,
        annotations=READ_ANNOTATIONS,
        audit_args=("execution_id",),
        data_schema=text_schema("log"),
    ),
    Tier.READ,
    (("GET", "/api/schedules/executions/{id}"),),
)

# --- operator tier ----------------------------------------------------------------------------
# Only schedule types whose run is an operator-level action. `image_prune` and `repo_prune`
# delete data (the destructive tier's business); the backup family (`backup`, `repo_check`,
# `repo_verify`) is not in v1; `system_cleanup` and `deploy_log_reconcile` delete old records.
# System cleanup jobs are toggled through their own route.

RunnableType = Literal["container_update", "git_stack_sync", "env_update_check"]
ToggleType = Literal["container_update", "git_stack_sync", "env_update_check", "system"]
SYSTEM_SCHEDULE_IDS: Final = frozenset({1, 2, 4})


class RunScheduleInput(WriteInputs):
    schedule_type: RunnableType = Field(description="Schedule type, as listed.")
    schedule_id: int = Field(ge=1, le=MAX_ENV_ID, description="Schedule id, as listed.")


async def run_schedule_now(ctx: ToolContext, args: RunScheduleInput) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def work() -> Any:
        return await ctx.client.post_json(
            "/api/schedules/{type}/{id}/run",
            path_params={"type": args.schedule_type, "id": args.schedule_id},
            read_timeout=float(ctx.settings.max_timeout) + 5.0,
        )

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "run_schedule", "type": args.schedule_type, "id": args.schedule_id},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_run_schedule_now",
        title="Run schedule now",
        description=(
            "Run one container-update, git-stack-sync or environment-update-check schedule once, "
            "outside its cron. Returns DockHand's result message."
        ),
        input_model=RunScheduleInput,
        handler=run_schedule_now,
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("schedule_type", "schedule_id", "wait"),
    ),
    Tier.OPERATOR,
    (("POST", "/api/schedules/{type}/{id}/run"),),
)


class ToggleScheduleInput(WriteInputs):
    schedule_type: ToggleType = Field(
        description="Schedule type, as listed; system for the built-in cleanup jobs."
    )
    schedule_id: int = Field(ge=1, le=MAX_ENV_ID, description="Schedule id, as listed.")


async def toggle_schedule(ctx: ToolContext, args: ToggleScheduleInput) -> Envelope:
    if args.schedule_type == "system" and args.schedule_id not in SYSTEM_SCHEDULE_IDS:
        raise fail("validation_error", "system schedule ids are 1, 2 and 4")
    budget, warnings = write_budget(ctx, args)

    async def work() -> Any:
        if args.schedule_type == "system":
            return await ctx.client.post_json(
                "/api/schedules/system/{id}/toggle", path_params={"id": args.schedule_id}
            )
        return await ctx.client.post_json(
            "/api/schedules/{type}/{id}/toggle",
            path_params={"type": args.schedule_type, "id": args.schedule_id},
        )

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "toggle_schedule", "type": args.schedule_type, "id": args.schedule_id},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_toggle_schedule",
        title="Toggle schedule",
        description=(
            "Enable a disabled schedule or disable an enabled one. Returns whether it is now "
            "enabled."
        ),
        input_model=ToggleScheduleInput,
        handler=toggle_schedule,
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("schedule_type", "schedule_id", "wait"),
    ),
    Tier.OPERATOR,
    (
        ("POST", "/api/schedules/{type}/{id}/toggle"),
        ("POST", "/api/schedules/system/{id}/toggle"),
    ),
)
