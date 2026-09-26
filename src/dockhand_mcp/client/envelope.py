# SPDX-License-Identifier: Apache-2.0
"""The uniform result envelope (ARCHITECTURE §6) and its MCP rendering.

Every tool returns an `Envelope`. `render()` turns it into a `CallToolResult` whose
`structuredContent` is the envelope and whose text content is a compact JSON rendering of it
(or, above 32 KiB, a pointer to the structured content). `OUTPUT_SCHEMA` is every tool's
`outputSchema`.
"""

import json
from typing import Any, Final, Literal

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict, Field

from dockhand_mcp.client.errors import ERROR_CODES, DockhandError, ErrorCode

__all__ = [
    "ERROR_CODES",
    "MAX_TEXT_BYTES",
    "OUTPUT_SCHEMA",
    "Envelope",
    "ErrorInfo",
    "OperationInfo",
    "async_op",
    "err",
    "from_error",
    "ok",
    "render",
]

MAX_TEXT_BYTES: Final = 32 * 1024
TRUNCATED_NOTE: Final = "truncated, see structured content"

OperationKind = Literal["job", "sse", "detached"]


class ErrorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ErrorCode = Field(description="Error code from a closed set.")
    message: str = Field(description="What went wrong and, where possible, what to do.")
    dockhand_status: int | None = Field(
        default=None, description="HTTP status DockHand answered with, if any."
    )
    retry_after: int | None = Field(
        default=None, description="Seconds DockHand asked the client to wait (HTTP 429)."
    )
    detail: str | None = Field(
        default=None, description="DockHand's error body, truncated to 2 KiB and redacted."
    )


class OperationInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: OperationKind = Field(description="job, sse or detached (ARCHITECTURE §4).")
    id: str = Field(description="DockHand job id, or this server's op_id for detached work.")
    status: str = Field(description="Last known status.")
    waited_seconds: float = Field(description="How long this call waited.")
    timed_out: bool = Field(description="True if the wait ended before the operation did.")


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", title="DockhandResult")

    ok: bool = Field(description="True if the call did what was asked.")
    environment_id: int | None = Field(default=None, description="DockHand environment used.")
    data: Any = Field(default=None, description="The result payload.")
    error: ErrorInfo | None = Field(default=None, description="Set when ok is false.")
    operation: OperationInfo | None = Field(
        default=None, description="Set for long-running operations."
    )
    verified: bool | None = Field(
        default=None, description="Read-back verification result for writes that persist content."
    )
    warnings: list[str] | None = Field(default=None, description="Non-fatal notes.")


OUTPUT_SCHEMA: Final[dict[str, Any]] = Envelope.model_json_schema()


def ok(
    data: Any = None,
    *,
    environment_id: int | None = None,
    warnings: list[str] | None = None,
    verified: bool | None = None,
    operation: OperationInfo | None = None,
) -> Envelope:
    return Envelope(
        ok=True,
        environment_id=environment_id,
        data=data,
        warnings=warnings or None,
        verified=verified,
        operation=operation,
    )


def err(
    code: ErrorCode,
    message: str,
    *,
    dockhand_status: int | None = None,
    retry_after: int | None = None,
    detail: str | None = None,
    environment_id: int | None = None,
    operation: OperationInfo | None = None,
) -> Envelope:
    return Envelope(
        ok=False,
        environment_id=environment_id,
        error=ErrorInfo(
            code=code,
            message=message,
            dockhand_status=dockhand_status,
            retry_after=retry_after,
            detail=detail,
        ),
        operation=operation,
    )


def async_op(
    kind: OperationKind,
    op_id: str,
    status: str,
    waited_seconds: float,
    timed_out: bool,
    *,
    data: Any = None,
    ok: bool = True,
    environment_id: int | None = None,
    warnings: list[str] | None = None,
) -> Envelope:
    return Envelope(
        ok=ok,
        environment_id=environment_id,
        data=data,
        operation=OperationInfo(
            kind=kind,
            id=op_id,
            status=status,
            waited_seconds=round(waited_seconds, 1),
            timed_out=timed_out,
        ),
        warnings=warnings or None,
    )


def error_info(e: DockhandError) -> ErrorInfo:
    return ErrorInfo(
        code=e.code,
        message=e.message,
        dockhand_status=e.status,
        retry_after=e.retry_after,
        detail=e.body_excerpt,
    )


def from_error(e: DockhandError, *, environment_id: int | None = None) -> Envelope:
    return Envelope(ok=False, environment_id=environment_id, error=error_info(e))


def render(envelope: Envelope) -> CallToolResult:
    structured = envelope.model_dump(mode="json", exclude_none=True)
    text = json.dumps(structured, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        text = json.dumps({"ok": envelope.ok, "note": TRUNCATED_NOTE}, separators=(",", ":"))
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=not envelope.ok,
    )
