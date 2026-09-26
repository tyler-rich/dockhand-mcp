# SPDX-License-Identifier: Apache-2.0
"""`POST /api/batch` (a `split` endpoint): `dockhand_batch_containers` is its operator half,
`dockhand_batch_remove_containers` its destructive half.

The operator tool is limited to start/stop/restart/pause/unpause; the destructive tool sends only
`remove`, and only through run_destructive (D-006). The entity type is fixed to `containers` (the
spec's example value), and `down` is not exposed. The operation is validated before any request,
so a disallowed one never reaches DockHand. DockHand answers a request that accepts
`text/event-stream` with a job id, polled via `GET /api/jobs/{id}`. Both halves read the finished
job through `client/batch.py`: the operator tool is `ok` only when every item succeeded.
"""

from typing import Annotated, Any, Final, Literal, get_args

from pydantic import Field, StringConstraints

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.batch import batch_summary, interpret_batch
from dockhand_mcp.client.envelope import Envelope, ErrorInfo, OperationInfo, ok
from dockhand_mcp.guardrails.names import resolve_containers
from dockhand_mcp.tools._common import (
    JOB_ACCEPT,
    JOB_STATUS,
    EnvDestructiveInputs,
    EnvWriteInputs,
    JobFinish,
    add_warnings,
    cap_json,
    destructive_tool,
    env_tool,
    fail,
    list_body,
    names_text,
    run_async_pattern,
    scoped,
    write_budget,
)
from dockhand_mcp.tools.base import OPERATOR_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

BatchOperation = Literal["start", "stop", "restart", "pause", "unpause"]
OPERATOR_OPERATIONS: Final = frozenset(get_args(BatchOperation))
ENTITY_TYPE: Final = "containers"
MAX_ITEMS: Final = 50


class BatchContainersInput(EnvWriteInputs):
    operation: BatchOperation = Field(description="What to do to every container.")
    refs: list[Annotated[str, StringConstraints(min_length=1, max_length=255)]] = Field(
        min_length=1, max_length=MAX_ITEMS, description="Container IDs or exact names."
    )


def _batch_finish(operation: str, sent: list[dict[str, str]]) -> JobFinish:
    """`ok` only when DockHand's summary shows every sent item succeeded (issue #6)."""

    def finish(status: str, result: Any, lines: list[Any], info: OperationInfo) -> Envelope:
        outcome = interpret_batch(status, result, lines, sent)
        # `items` replaces the progress tail: it covers every item (the tail covers at most 9),
        # with the same per-item messages, redacted like every job line.
        data = {"result": cap_json(result), "summary": outcome.summary, "items": outcome.items}
        if outcome.problem is None:
            return ok(data, operation=info)
        return Envelope(
            ok=False,
            data=data,
            operation=info,
            error=ErrorInfo(
                code=outcome.code or "operation_failed",
                message=f"Batch {operation}: {outcome.problem}; see data.items",
            ),
        )

    return finish


async def batch_containers(ctx: ToolContext, args: BatchContainersInput, env: int) -> Envelope:
    # The input model already refuses anything else; checked again before any request.
    if args.operation not in OPERATOR_OPERATIONS:
        raise fail("validation_error", f"operation must be one of {sorted(OPERATOR_OPERATIONS)}")
    refs = await resolve_containers(ctx.client, env, args.refs)
    budget, warnings = write_budget(ctx, args)
    items = [{"id": r.id, "name": r.name} for r in refs]
    body = {"operation": args.operation, "entityType": ENTITY_TYPE, "items": items}

    async def start() -> Any:
        return await ctx.client.post_json(
            "/api/batch", params={"env": env}, json=body, accept=JOB_ACCEPT
        )

    envelope = await run_async_pattern(
        "job",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": f"batch_{args.operation}", "environment_id": env},
        start=start,
        on_job_finish=_batch_finish(args.operation, items),
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_batch_containers",
        title="Batch container operation",
        description=(
            "Start, stop, restart, pause or unpause several containers as one DockHand job. "
            "Returns the job's status, succeeded and failed counts, and each container's outcome."
        ),
        input_model=BatchContainersInput,
        handler=env_tool(batch_containers),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "operation", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("GET", "/api/containers"), ("POST", "/api/batch"), JOB_STATUS),
)


# --- destructive half -----------------------------------------------------------------------------

REMOVE_OPERATION: Final = "remove"
RUNNING_STATES: Final = frozenset({"running", "paused", "restarting"})


class BatchRemoveInput(EnvDestructiveInputs):
    refs: list[Annotated[str, StringConstraints(min_length=1, max_length=255)]] = Field(
        min_length=1, max_length=MAX_ITEMS, description="Container IDs or exact names."
    )
    force: bool = Field(default=False, description="Remove running containers too.")


async def batch_remove_preview(
    ctx: ToolContext, args: BatchRemoveInput, env: int | None
) -> Preview:
    env = scoped(env)
    refs = await resolve_containers(ctx.client, env, args.refs)
    listed = list_body(
        await ctx.client.get_json("/api/containers", params={"env": env, "all": True})
    )
    by_id = {i.get("id"): i for i in listed if isinstance(i, dict)}
    rows = [
        {
            "id": r.id,
            "name": r.name,
            "image": by_id.get(r.id, {}).get("image"),
            "state": by_id.get(r.id, {}).get("state"),
        }
        for r in refs
    ]
    running = [r.name for r in refs if by_id.get(r.id, {}).get("state") in RUNNING_STATES]
    names = names_text([r.name for r in refs])
    summary = f"Remove {len(rows)} container(s) in environment {env}: {names}."
    if running:
        summary += f" {len(running)} still run(s): {names_text(running)}; " + (
            "they are removed by force." if args.force else "without force they will fail."
        )
    return Preview(
        summary=summary,
        data={"containers": rows, "running": running, "force": args.force},
        counts={"containers": len(rows), "running": len(running)},
        target={"items": [{"id": r.id, "name": r.name} for r in refs]},
    )


def _failed_items(envelope: Envelope) -> Envelope:
    """A finished batch job whose summary counts failed items is an error.

    Live DockHand 1.0.46 ends a batch job with `{type, summary: {total, success, failed}}`, with
    no `success` key for the generic job check to see.
    """
    data = envelope.data if isinstance(envelope.data, dict) else {}
    summary = batch_summary(data.get("result"))
    failed = summary.get("failed") if summary is not None else None
    if not envelope.ok or not isinstance(failed, int) or isinstance(failed, bool) or failed < 1:
        return envelope
    total = summary.get("total") if summary is not None else None
    return envelope.model_copy(
        update={
            "ok": False,
            "error": ErrorInfo(
                code="operation_failed",
                message=f"{failed} of {total} containers were not removed; see data.result",
            ),
        }
    )


async def batch_remove(
    ctx: ToolContext,
    args: BatchRemoveInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    body = {
        "operation": REMOVE_OPERATION,
        "entityType": ENTITY_TYPE,
        "items": list(preview.target["items"]),
        "options": {"force": args.force},
    }

    async def start() -> Any:
        return await ctx.client.post_json(
            "/api/batch", params={"env": env}, json=body, accept=JOB_ACCEPT
        )

    envelope = await run_async_pattern(
        "job",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "batch_remove", "environment_id": env},
        start=start,
    )
    return add_warnings(_failed_items(envelope), warnings)


register(
    destructive_tool(
        name="dockhand_batch_remove_containers",
        title="Batch remove containers",
        description=(
            "Remove several containers as one DockHand job after a human approves. Returns the "
            "job's status and per-container result."
        ),
        input_model=BatchRemoveInput,
        preview=batch_remove_preview,
        execute=batch_remove,
        audit_args=("environment_id", "force", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (ENVIRONMENTS, ("GET", "/api/containers"), ("POST", "/api/batch"), JOB_STATUS),
)
