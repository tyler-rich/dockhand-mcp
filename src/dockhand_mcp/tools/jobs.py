# SPDX-License-Identifier: Apache-2.0
"""DockHand background jobs: `dockhand_get_job` (status and output) and `dockhand_cancel_job`.

A job's lines and result are operation output: `dockhand_get_job` returns them through the same
redaction as every job and stream tool (`client/redaction.py`). It has no stack context, so a
stack's own variable values are not masked here.
"""

from typing import Any, Final

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.client.jobs import redact_job
from dockhand_mcp.tools._common import (
    ToolInput,
    WriteInputs,
    add_warnings,
    run_async_pattern,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.registry import Tier, register

MAX_LINES: Final = 500
UUID: Final = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class GetJobInput(ToolInput):
    job_id: str = Field(min_length=36, max_length=36, pattern=UUID, description="DockHand job id.")


async def get_job(ctx: ToolContext, args: GetJobInput) -> Envelope:
    body = await ctx.client.get_json("/api/jobs/{id}", path_params={"id": args.job_id})
    warnings: list[str] = []
    if isinstance(body, dict) and isinstance(body.get("lines"), list):
        lines = body["lines"]
        if len(lines) > MAX_LINES:
            warnings.append(f"showing the last {MAX_LINES} of {len(lines)} output lines")
            body = {**body, "lines": lines[-MAX_LINES:], "lines_dropped": len(lines) - MAX_LINES}
    return ok(redact_job(body), warnings=warnings)


register(
    ToolSpec(
        name="dockhand_get_job",
        title="Get job",
        description=(
            "Get a DockHand background job's status, its most recent output lines and, once "
            "finished, its result."
        ),
        input_model=GetJobInput,
        handler=get_job,
        annotations=READ_ANNOTATIONS,
        audit_args=("job_id",),
    ),
    Tier.READ,
    (("GET", "/api/jobs/{id}"),),
)


class CancelJobInput(WriteInputs):
    job_id: str = Field(min_length=36, max_length=36, pattern=UUID, description="DockHand job id.")


async def cancel_job(ctx: ToolContext, args: CancelJobInput) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def work() -> Any:
        return await ctx.client.delete_json("/api/jobs/{id}", path_params={"id": args.job_id})

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "cancel_job", "job_id": args.job_id},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_cancel_job",
        title="Cancel job",
        description="Ask DockHand to cancel a running background job. Returns whether it was.",
        input_model=CancelJobInput,
        handler=cancel_job,
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("job_id", "wait"),
    ),
    Tier.OPERATOR,
    (("DELETE", "/api/jobs/{id}"),),
)
