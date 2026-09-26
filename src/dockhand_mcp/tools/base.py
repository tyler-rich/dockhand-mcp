# SPDX-License-Identifier: Apache-2.0
"""What a tool is: a validated input model, a handler returning an envelope, and MCP metadata."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from mcp import types
from pydantic import BaseModel

from dockhand_mcp.client.envelope import OUTPUT_SCHEMA, Envelope

if TYPE_CHECKING:
    from dockhand_mcp.auth.approval import ApprovalContext
    from dockhand_mcp.auth.principal import Principal
    from dockhand_mcp.client.dockhand import DockhandClient
    from dockhand_mcp.client.operations import OperationRegistry
    from dockhand_mcp.config import Settings

# docs/TOOLS.md: annotations per tier. Hints for clients, not security.
READ_ANNOTATIONS: Final = types.ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)
OPERATOR_ANNOTATIONS: Final = types.ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
# Operator tools whose repeat is a no-op (start/stop/pause/unpause).
OPERATOR_IDEMPOTENT_ANNOTATIONS: Final = OPERATOR_ANNOTATIONS.model_copy(
    update={"idempotent_hint": True}
)
DESTRUCTIVE_ANNOTATIONS: Final = types.ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True
)

# Report progress with our own text (phase, elapsed); never DockHand output.
ProgressFn = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class ToolContext:
    principal: Principal
    client: DockhandClient
    operations: OperationRegistry
    settings: Settings
    progress: ProgressFn
    # Destructive tools only (auth/approval.py); None where the server has no approval state.
    approval: ApprovalContext | None = None


Handler = Callable[[ToolContext, Any], Awaitable[Envelope]]


@dataclass(frozen=True)
class ToolSpec:
    """A tool. Register it with `tools.registry.register(spec, tier, endpoints)`.

    `audit_args` names the arguments safe to write to the audit log (IDs and names only).
    `data_schema`, when set, specialises the envelope's `data` in the output schema (it stays
    nullable, since error results carry no data).
    """

    name: str
    title: str
    description: str
    input_model: type[BaseModel]
    handler: Handler
    annotations: types.ToolAnnotations
    audit_args: tuple[str, ...] = ()
    data_schema: dict[str, Any] | None = None

    def input_schema(self) -> dict[str, Any]:
        return self.input_model.model_json_schema()

    def output_schema(self) -> dict[str, Any]:
        if self.data_schema is None:
            return OUTPUT_SCHEMA
        properties = dict(OUTPUT_SCHEMA["properties"])
        properties["data"] = {
            "anyOf": [self.data_schema, {"type": "null"}],
            "description": properties["data"].get("description", "The result payload."),
        }
        return {**OUTPUT_SCHEMA, "properties": properties}

    def to_mcp(self) -> types.Tool:
        return types.Tool(
            name=self.name,
            title=self.title,
            description=self.description,
            input_schema=self.input_schema(),
            output_schema=self.output_schema(),
            annotations=self.annotations,
        )
