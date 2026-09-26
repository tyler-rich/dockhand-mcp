# SPDX-License-Identifier: Apache-2.0
"""`dockhand_get_operation`: status of a detached operation in this server's registry.

Calls no DockHand endpoint. Another principal's operation id answers exactly like an unknown one.
"""

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from dockhand_mcp.client.envelope import Envelope, OperationInfo, OperationKind, err, ok
from dockhand_mcp.client.operations import OperationUnknownError
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import NO_ENDPOINTS, Tier, register

KINDS: Final[dict[str, OperationKind]] = {"job": "job", "sse": "sse", "detached": "detached"}
UUID4: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
UNKNOWN: Final = (
    "No such operation for this caller. Operations are kept for 1 hour after they finish and "
    "are lost when the server restarts."
)


class GetOperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", title="dockhand_get_operation")

    op_id: str = Field(
        min_length=36,
        max_length=36,
        pattern=UUID4,
        description="Operation id returned when the operation was started.",
    )


async def get_operation(ctx: ToolContext, args: GetOperationInput) -> Envelope:
    try:
        op = ctx.operations.get(args.op_id, ctx.principal)
    except OperationUnknownError:
        return err("operation_unknown", UNKNOWN)
    kind = KINDS.get(op.kind, "detached")
    result = op.result
    # A write tool's operation finishes with its own envelope (ok, verified, warnings).
    inner = result if isinstance(result, Envelope) else None
    info = OperationInfo(
        kind=kind,
        id=op.id,
        status=op.status,
        waited_seconds=0.0,
        timed_out=bool(inner and inner.operation and inner.operation.timed_out),
    )
    data = {
        "meta": op.meta,
        "elapsed_seconds": round(ctx.operations.elapsed(op), 1),
        "result": inner.data if inner is not None else result,
    }
    if op.error is not None:
        return Envelope(ok=False, data=data, error=op.error, operation=info)
    if inner is not None:
        return inner.model_copy(update={"data": data, "operation": info})
    return ok(data, operation=info)


SPEC: Final = ToolSpec(
    name="dockhand_get_operation",
    title="Get operation status",
    description=(
        "Get the status of a long-running operation started earlier by this server. Returns its "
        "status and, once finished, its result or error."
    ),
    input_model=GetOperationInput,
    handler=get_operation,
    # In-process only: no external system is touched.
    annotations=READ_ANNOTATIONS.model_copy(update={"open_world_hint": False}),
    audit_args=("op_id",),
)

register(SPEC, Tier.READ, NO_ENDPOINTS)
