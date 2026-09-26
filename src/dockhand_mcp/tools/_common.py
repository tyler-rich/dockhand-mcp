# SPDX-License-Identifier: Apache-2.0
"""Shared pieces of the DockHand tools: input bases, environment defaulting (F-09), pagination
(F-11), text size caps, per-section fan-out, the value-level env redactions (S-06), for writes
the async patterns (F-10), read-back verification and the placeholder write-back guard (S3a), and
for destructive tools the approval gate `run_destructive` (S3b, D-006).
"""

import asyncio
import copy
import json
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Annotated, Any, Final, Literal, final

import yaml
from mcp_types import InputRequiredResult
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from dockhand_mcp.auth.approval import (
    Approved,
    InputRequired,
    Preview,
    Refused,
    approve_or_request,
)
from dockhand_mcp.client.dockhand import JSON_BODY_EVENT, Params, read_only_phase
from dockhand_mcp.client.envelope import (
    Envelope,
    ErrorInfo,
    OperationInfo,
    OperationKind,
    err,
    from_error,
    ok,
)
from dockhand_mcp.client.errors import DockhandError, ErrorCode
from dockhand_mcp.client.jobs import (
    JobResult,
    ProgressCallback,
    job_id_of,
    job_label,
    poll_job,
    synchronous_answer,
)
from dockhand_mcp.client.operations import RegistryFullError
from dockhand_mcp.client.redaction import PLAIN, OutputRedactor, current_redactor, redacting
from dockhand_mcp.client.sse import MAX_PROGRESS, EventObserver, SseResult, consume
from dockhand_mcp.guardrails.names import MAX_ENV_ID
from dockhand_mcp.guardrails.secrets import REDACTED, placeholders_in
from dockhand_mcp.logging import audit_log, truncate
from dockhand_mcp.tools.base import DESTRUCTIVE_ANNOTATIONS, ToolContext, ToolSpec

MAX_LIMIT: Final = 500
MAX_OFFSET: Final = 1_000_000
MAX_TEXT_BYTES: Final = 1024 * 1024  # SECURITY §2 DoS cap
DEFAULT_TEXT_BYTES: Final = 256 * 1024
MIN_TEXT_BYTES: Final = 1024
# Where to look for a line break to start a tail-truncated text on a whole line.
LINE_ALIGN_WINDOW: Final = 4096
MAX_NAME_IN_MESSAGE: Final = 64


class ToolInput(BaseModel):
    """Base for every tool's arguments: unknown fields refused, strings stripped."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


ENV_DESCRIPTION: Final = (
    "DockHand environment id. Optional when the server has a default environment or DockHand "
    "has exactly one."
)


class EnvScoped(ToolInput):
    environment_id: int | None = Field(
        default=None, ge=1, le=MAX_ENV_ID, description=ENV_DESCRIPTION
    )


def _iso_8601(value: str) -> str:
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(
            "must be an ISO 8601 date or date-time, e.g. 2026-01-31T12:00:00Z"
        ) from None
    return value


IsoDate = Annotated[str, StringConstraints(min_length=10, max_length=40), AfterValidator(_iso_8601)]
# A value DockHand takes in a comma-separated list: no commas, bounded, printable.
ListValue = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_:. /-]{1,64}$")]


def limit_field(default: int, maximum: int = MAX_LIMIT) -> Any:
    return Field(default=default, ge=1, le=maximum, description="Maximum items to return.")


def offset_field() -> Any:
    return Field(default=0, ge=0, le=MAX_OFFSET, description="Items to skip (pagination).")


def max_bytes_field(what: str) -> Any:
    return Field(
        default=DEFAULT_TEXT_BYTES,
        ge=MIN_TEXT_BYTES,
        le=MAX_TEXT_BYTES,
        description=f"Cap on the returned {what} in bytes; the oldest part is dropped first.",
    )


def fail(code: ErrorCode, message: str) -> DockhandError:
    """An error raised inside a tool that becomes an error envelope (no DockHand status)."""
    return DockhandError(None, code, message)


# --- environment defaulting (F-09) ------------------------------------------------------------


def _env_label(item: Any) -> str | None:
    if not isinstance(item, dict) or not isinstance(item.get("id"), int):
        return None
    name = truncate(str(item.get("name", "")), MAX_NAME_IN_MESSAGE)
    return f"{item['id']} ({name})"


async def resolve_env(ctx: ToolContext, requested: int | None) -> tuple[int, list[str]]:
    """The environment to use and any warning to report.

    Explicit argument, else DOCKHAND_DEFAULT_ENVIRONMENT_ID, else the only environment DockHand
    has (reported in a warning). With several and no default the call is refused, listing them.
    """
    if requested is not None:
        return requested, []
    default = ctx.settings.dockhand_default_environment_id
    if default is not None:
        return default, []
    body = await ctx.client.get_json("/api/environments")
    items = body if isinstance(body, list) else []
    labels = [label for label in map(_env_label, items) if label is not None]
    if len(labels) == 1:
        only = items[0]["id"] if isinstance(items[0], dict) else None
        if isinstance(only, int):
            return only, [f"environment_id not given; used the only environment, {labels[0]}"]
    if not labels:
        raise fail("validation_error", "DockHand has no environments this token can see")
    raise fail(
        "validation_error",
        "environment_id is required: DockHand has several environments and the server has no "
        f"default. Environments: {', '.join(labels)}",
    )


EnvBody = Callable[[ToolContext, Any, int], Awaitable[Any]]
Handler = Callable[[ToolContext, Any], Awaitable[Envelope]]


def env_tool(body: EnvBody) -> Handler:
    """Wrap an environment-scoped tool body: resolve the environment, then build the envelope.

    `body(ctx, args, env)` returns `data`, or a complete `Envelope`. DockHand errors become an
    error envelope carrying the environment id. Environment warnings are prepended.
    """

    async def handler(ctx: ToolContext, args: Any) -> Envelope:
        env, env_warnings = await resolve_env(ctx, args.environment_id)
        try:
            result = await body(ctx, args, env)
        except DockhandError as e:
            envelope = from_error(e, environment_id=env)
        else:
            envelope = result if isinstance(result, Envelope) else ok(result)
        warnings = env_warnings + (envelope.warnings or [])
        return envelope.model_copy(
            update={
                "environment_id": envelope.environment_id or env,
                "warnings": warnings or None,
            }
        )

    return handler


# --- pagination (F-11) ------------------------------------------------------------------------

PAGE_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "items": {"type": "array", "description": "This page of results."},
        "count": {"type": "integer", "description": "Number of items on this page."},
        "total": {"type": "integer", "description": "Total matching items, when known."},
        "has_more": {"type": "boolean", "description": "True if more items follow."},
    },
    "required": ["items", "count", "has_more"],
}


def page(items: Sequence[Any], limit: int, offset: int, **extra: Any) -> dict[str, Any]:
    """Slice a complete, already filtered list."""
    chunk = list(items[offset : offset + limit])
    return {
        "items": chunk,
        "count": len(chunk),
        "total": len(items),
        "has_more": offset + len(chunk) < len(items),
        **extra,
    }


def remote_page(items: Sequence[Any], total: Any, offset: int, **extra: Any) -> dict[str, Any]:
    """A page DockHand already sliced; `total` is its count of all matches."""
    out: dict[str, Any] = {"items": list(items), "count": len(items)}
    if isinstance(total, int) and not isinstance(total, bool):
        out["total"] = total
        out["has_more"] = offset + len(items) < total
    else:
        out["has_more"] = False
    return {**out, **extra}


def list_body(body: Any) -> list[Any]:
    return body if isinstance(body, list) else []


def as_dict(body: Any) -> dict[str, Any]:
    return body if isinstance(body, dict) else {}


def text_schema(key: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            key: {"type": "string"},
            "bytes": {"type": "integer", "description": "Size of the full text in bytes."},
            "truncated": {"type": "boolean"},
            "dropped_bytes": {"type": "integer"},
        },
        "required": [key, "truncated", "dropped_bytes"],
    }


def cap_text(text: str, max_bytes: int, key: str = "text") -> dict[str, Any]:
    """Keep the last `max_bytes` of `text` (the newest log lines), starting on a whole line."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return {key: text, "bytes": len(raw), "truncated": False, "dropped_bytes": 0}
    kept = raw[-max_bytes:].decode("utf-8", errors="ignore")
    newline = kept.find("\n", 0, LINE_ALIGN_WINDOW)
    if 0 <= newline < len(kept) - 1:
        kept = kept[newline + 1 :]
    kept_bytes = len(kept.encode("utf-8"))
    return {
        key: kept,
        "bytes": len(raw),
        "truncated": True,
        "dropped_bytes": len(raw) - kept_bytes,
    }


# --- fan-out ----------------------------------------------------------------------------------


def section_error(e: DockhandError) -> dict[str, Any]:
    out: dict[str, Any] = {"code": e.code, "message": e.message}
    if e.status is not None:
        out["dockhand_status"] = e.status
    return out


async def gather_sections(
    calls: Mapping[str, Awaitable[Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Run the calls concurrently. Returns (results, errors) keyed by section name.

    A DockHand error fails only its own section; anything else propagates.
    """
    names = list(calls)
    outcomes = await asyncio.gather(*calls.values(), return_exceptions=True)
    results: dict[str, Any] = {}
    errors: dict[str, dict[str, Any]] = {}
    for name, outcome in zip(names, outcomes, strict=True):
        if isinstance(outcome, DockhandError):
            errors[name] = section_error(outcome)
        elif isinstance(outcome, BaseException):
            raise outcome
        else:
            results[name] = outcome
    return results, errors


def section_warnings(errors: Mapping[str, Mapping[str, Any]]) -> list[str]:
    return [f"{name} unavailable: {error['message']}" for name, error in errors.items()]


# --- value-level env redaction (S-06) ---------------------------------------------------------

_ENV_ITEM: Final = re.compile(r"^([^=]*)=(.*)$", re.DOTALL)


def _redact_env_item(item: Any) -> Any:
    if not isinstance(item, str):
        return item
    m = _ENV_ITEM.match(item)
    return f"{m[1]}={REDACTED}" if m else item


def redact_env(inspect: Any) -> Any:
    """A copy of a container inspect payload with each `Config.Env` value redacted (keys kept)."""
    if not isinstance(inspect, dict):
        return inspect
    out = dict(inspect)
    config = out.get("Config")
    if isinstance(config, dict) and isinstance(config.get("Env"), list):
        out["Config"] = {**config, "Env": [_redact_env_item(i) for i in config["Env"]]}
    return out


class ComposeRedactionError(DockhandError):
    def __init__(self, message: str) -> None:
        super().__init__(None, "guardrail_blocked", message)


def redact_compose_env(text: str) -> str:
    """Re-emit a compose document with every service's `environment:` values redacted.

    Handles the map form (`KEY: value`) and the list form (`- KEY=value`; a bare `- KEY` stays).
    Keys are kept; `KEY:` with no value stays empty. A document that does not parse as a YAML
    mapping is refused rather than returned unredacted.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ComposeRedactionError(
            "the generated compose could not be parsed, so its environment values could not be "
            "redacted; it was not returned"
        ) from None
    if doc is None:
        return ""
    if not isinstance(doc, dict):
        raise ComposeRedactionError(
            "the generated compose is not a YAML mapping, so its environment values could not be "
            "redacted; it was not returned"
        )
    doc = copy.deepcopy(doc)
    services = doc.get("services")
    if isinstance(services, dict):
        for service in services.values():
            if not isinstance(service, dict):
                continue
            env = service.get("environment")
            if isinstance(env, dict):
                service["environment"] = {
                    k: (REDACTED if v is not None else None) for k, v in env.items()
                }
            elif isinstance(env, list):
                service["environment"] = [_redact_env_item(i) for i in env]
    return str(yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True))


# --- writes (S3a) -------------------------------------------------------------------------------

MAX_TIMEOUT: Final = 300  # SECURITY §2 cap; DOCKHAND_MCP_MAX_TIMEOUT can only lower it
JOB_ACCEPT: Final = "application/json, text/event-stream"  # without text/event-stream: blocks
# Job-based tools poll this; they declare it with the endpoint that starts the job.
JOB_STATUS: Final = ("GET", "/api/jobs/{id}")
MAX_RESULT_BYTES: Final = 64 * 1024
TAIL_LINES: Final = 20
DETACHED_NOTE: Final = (
    "Operation status is kept in this server's memory for 1 hour after it finishes and is lost "
    "if the server restarts."
)
ENV_RECREATE_WARNING: Final = (
    "Running containers keep their old environment until the stack is recreated "
    "(dockhand_restart_stack mode=recreate or dockhand_deploy_stack force_recreate=true)"
)
PLACEHOLDER_MESSAGE: Final = (
    "{fields} contain{s} the placeholder {markers}. Redacted or masked output can't be written "
    "back: it would replace the real values with placeholder text. For targeted .env changes use "
    "dockhand_modify_stack_env."
)


class WriteInputs(ToolInput):
    wait: bool = Field(
        default=True,
        description="Wait for the operation to finish, up to timeout_seconds. When false, "
        "return its id at once.",
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=1,
        le=MAX_TIMEOUT,
        description="How long to wait, in seconds; the server's default when omitted.",
    )


class EnvWriteInputs(EnvScoped, WriteInputs):
    pass


def write_budget(ctx: ToolContext, args: WriteInputs) -> tuple[float, list[str]]:
    """Seconds to wait for this call, capped at DOCKHAND_MCP_MAX_TIMEOUT, and any warning."""
    limit = ctx.settings.max_timeout
    requested = args.timeout_seconds or ctx.settings.default_timeout
    if requested > limit:
        return float(limit), [f"timeout_seconds lowered to the server's maximum of {limit}"]
    return float(requested), []


def refuse_placeholders(fields: Mapping[str, str | None]) -> None:
    """Refuse content carrying `<redacted>` or `***` before any request reaches DockHand."""
    found = placeholders_in(fields)
    if not found:
        return
    names = list(dict.fromkeys(name for name, _ in found))
    markers = " and ".join(repr(m) for m in dict.fromkeys(marker for _, marker in found))
    raise fail(
        "guardrail_blocked",
        PLACEHOLDER_MESSAGE.format(
            fields=", ".join(names[:10]), s="s" if len(names) == 1 else "", markers=markers
        ),
    )


def cap_json(value: Any, max_bytes: int = MAX_RESULT_BYTES) -> Any:
    """`value`, or a size note in its place when its JSON exceeds `max_bytes`."""
    size = len(json.dumps(value, default=str).encode("utf-8"))
    if size <= max_bytes:
        return value
    return {"truncated": True, "bytes": size}


def _progress_callback(ctx: ToolContext) -> ProgressCallback:
    async def report(message: str, elapsed: float) -> None:
        await ctx.progress(message)

    return report


def _tail(lines: Sequence[Any]) -> list[str]:
    """The last output lines as text. `lines` come redacted from the client modules; formatting
    them redacts again (idempotent) and applies the per-line cap."""
    return [PLAIN.line(x) for x in lines[-TAIL_LINES:]]


def _failure(
    message: str,
    data: Any,
    operation: OperationInfo | None = None,
    code: ErrorCode = "operation_failed",
) -> Envelope:
    """An operation DockHand reported as failed (or, with `code`, an unexpected answer)."""
    return Envelope(
        ok=False, data=data, operation=operation, error=ErrorInfo(code=code, message=message)
    )


def _reported_failure(status: str, result: Any) -> bool:
    """A job DockHand ended as failed, or whose result says `success: false`."""
    failed = isinstance(result, dict) and result.get("success") is False
    return status in ("failed", "cancelled", "error") or failed


def _failed_message(status: str) -> str:
    shown = "failed" if status in ("done", "completed", "") else status
    return f"DockHand reports the operation {shown}; see data.result"


# --- job-poll (ARCHITECTURE §4.1) ---------------------------------------------------------------


# How a finished job becomes an envelope: (status, result, lines, operation info).
JobFinish = Callable[[str, Any, list[Any], OperationInfo], Envelope]


def _job_envelope(status: str, result: Any, lines: list[Any], info: OperationInfo) -> Envelope:
    data = {"result": cap_json(result), "progress": _tail(lines)}
    if _reported_failure(status, result):
        return _failure(_failed_message(status), data, info)
    return ok(data, operation=info)


async def run_job(
    ctx: ToolContext,
    start: Callable[[], Awaitable[Any]],
    *,
    wait: bool,
    budget_s: float,
    on_finish: JobFinish | None = None,
    redactor: OutputRedactor = PLAIN,
) -> Envelope:
    """Start a job-based operation and poll it (or return its job id when not waiting).

    `on_finish` reads a finished job (or DockHand's synchronous answer) in place of the generic
    check, for jobs whose result has a known shape. Either way it gets the lines and result
    redacted with `redactor`, which carries the call's context values, if any.
    """
    finish = on_finish or _job_envelope
    body = await start()
    job_id = job_id_of(body)
    if job_id is None:
        # DockHand answered with the final result instead of a job id.
        info = OperationInfo(
            kind="job", id="", status="completed", waited_seconds=0.0, timed_out=False
        )
        return finish("completed", synchronous_answer(body, redactor), [], info)
    if not wait:
        info = OperationInfo(
            kind="job", id=job_id, status="started", waited_seconds=0.0, timed_out=False
        )
        return ok({"job_id": job_id}, operation=info)
    job = await poll_job(
        ctx.client, job_id, budget_s, on_progress=_progress_callback(ctx), redactor=redactor
    )
    info = OperationInfo(
        kind="job",
        id=job_id,
        status=job.status,
        waited_seconds=round(job.waited_seconds, 1),
        timed_out=job.timed_out,
    )
    if job.timed_out:
        data = {"job_id": job_id, "progress": _tail(job.lines)}
        return ok(data, operation=info, warnings=["The job is still running in DockHand."])
    return finish(job.status, job.result, job.lines, info)


# --- detached and SSE (ARCHITECTURE §4.2, §4.3) -------------------------------------------------

Work = Callable[[], Coroutine[Any, Any, Any]]


async def run_registered(
    ctx: ToolContext,
    kind: OperationKind,
    work: Work,
    *,
    wait: bool,
    budget_s: float,
    meta: Mapping[str, Any],
    progress: deque[str] | None = None,
) -> Envelope:
    """Run `work` in the operation registry; wait up to `budget_s` when asked.

    `work` returns `data` or a complete `Envelope`. After a timeout (or with `wait=false`) the
    operation carries on and its `op_id` is returned for a later status check.
    """
    try:
        op_id = ctx.operations.start(work(), kind, meta, ctx.principal)
    except RegistryFullError:
        return err(
            "not_available",
            "Too many operations are running on this server; retry when some have finished.",
        )
    if not wait:
        info = OperationInfo(
            kind=kind, id=op_id, status="running", waited_seconds=0.0, timed_out=False
        )
        return ok({"op_id": op_id}, operation=info, warnings=[DETACHED_NOTE])
    started = time.monotonic()
    op, timed_out = await ctx.operations.wait(
        op_id, ctx.principal, budget_s, on_progress=_progress_callback(ctx)
    )
    waited = round(time.monotonic() - started, 1)
    if timed_out:
        info = OperationInfo(
            kind=kind, id=op_id, status=op.status, waited_seconds=waited, timed_out=True
        )
        data: dict[str, Any] = {"op_id": op_id}
        if progress is not None:
            data["progress"] = list(progress)
        return ok(data, operation=info, warnings=[DETACHED_NOTE])
    return finished_operation(op.result, op.error, kind, op_id, op.status, waited)


def finished_operation(
    result: Any,
    error: ErrorInfo | None,
    kind: OperationKind,
    op_id: str,
    status: str,
    waited: float,
) -> Envelope:
    """The envelope of a finished registry operation (also what a later status check returns)."""
    inner = result.operation if isinstance(result, Envelope) else None
    info = OperationInfo(
        kind=kind,
        id=op_id,
        status=status,
        waited_seconds=waited,
        timed_out=inner.timed_out if inner is not None else False,
    )
    if error is not None:
        return Envelope(ok=False, error=error, operation=info)
    if isinstance(result, Envelope):
        return result.model_copy(update={"operation": info})
    return ok(result, operation=info)


@dataclass(frozen=True)
class SseRequest:
    method: str
    template: str
    path_params: Mapping[str, str | int] | None = None
    params: Params | None = None
    json: Any = None


Finish = Callable[[Any], Awaitable[Any]]
# Judges a streaming operation's finished envelope with what `on_event` saw; runs inside the
# operation, so a later status check returns the same verdict.
Review = Callable[[Envelope], Envelope]


def _observe_job_line(on_event: EventObserver) -> Callable[[Any], None]:
    """A job line (`{event, data}`) passed to an SSE event observer."""

    def observe(line: Any) -> None:
        if isinstance(line, dict):
            on_event(str(line.get("event", "")), line.get("data"))

    return observe


async def _job_stream_envelope(job_id: str, job: JobResult, finish: Finish | None) -> Envelope:
    """A streaming operation DockHand ran as a job: its `lines` are the stream's events."""
    tail = _tail(job.lines)
    if job.timed_out:
        info = OperationInfo(
            kind="sse",
            id="",
            status=job.status or "running",
            waited_seconds=round(job.waited_seconds, 1),
            timed_out=True,
        )
        return ok(
            {"job_id": job_id, "progress": tail},
            operation=info,
            warnings=["The job is still running in DockHand."],
        )
    result = job.result
    if _reported_failure(job.status, result):
        return _failure(
            _failed_message(job.status),
            {"job_id": job_id, "result": cap_json(result), "progress": tail},
        )
    if finish is not None:
        data = await finish(result)
        return ok({**data, "job_id": job_id} if isinstance(data, dict) else data)
    return ok({"job_id": job_id, "result": cap_json(result), "progress": tail})


async def _sse_envelope(res: SseResult, finish: Finish | None) -> Envelope:
    tail = list(res.progress)[-TAIL_LINES:]
    if res.final_event == "result":
        result = res.final_data
        if isinstance(result, dict) and result.get("success") is False:
            return _failure(
                "DockHand reports the operation failed; see data.result",
                {"result": cap_json(result), "progress": tail},
            )
        if finish is not None:
            return ok(await finish(result))
        return ok({"result": cap_json(result), "progress": tail})
    if res.final_event == "error":
        return _failure(
            "DockHand reported an error on the event stream; see data.error",
            {"error": cap_json(res.final_data), "progress": tail},
        )
    if res.timed_out:
        info = OperationInfo(
            kind="sse",
            id="",
            status="running",
            waited_seconds=round(res.waited_seconds, 1),
            timed_out=True,
        )
        return ok(
            {"progress": list(res.progress)},
            operation=info,
            warnings=["DockHand's event stream was still running when this server stopped."],
        )
    return _failure(
        "DockHand's event stream ended without a result",
        {"progress": tail},
        code="dockhand_http_error",
    )


async def run_sse(
    ctx: ToolContext,
    request: SseRequest,
    *,
    wait: bool,
    budget_s: float,
    meta: Mapping[str, Any],
    finish: Finish | None = None,
    redactor: OutputRedactor = PLAIN,
    on_event: EventObserver | None = None,
    review: Review | None = None,
) -> Envelope:
    """Consume a DockHand event stream in the registry, waiting up to `budget_s` for it.

    The stream itself is read for at most DOCKHAND_MCP_MAX_TIMEOUT seconds; when a shorter wait
    times out, the last progress lines are returned with the `op_id`. Live DockHand 1.0.46
    answers its streaming endpoints with a `{jobId}` instead of a stream: that job is polled
    (its `lines` are the stream's events), so every SSE tool also declares `JOB_STATUS`.
    `on_event` sees every progress event (or job line) and `review` then judges the envelope.
    """
    progress: deque[str] = deque(maxlen=MAX_PROGRESS)
    stream_budget = float(ctx.settings.max_timeout)

    async def work() -> Envelope:
        envelope = await consumed()
        return review(envelope) if review is not None else envelope

    async def consumed() -> Envelope:
        res = await consume(
            ctx.client,
            request.method,
            request.template,
            budget_s=stream_budget,
            path_params=request.path_params,
            params=request.params,
            json=request.json,
            progress=progress,
            redactor=redactor,
            on_event=on_event,
        )
        if res.final_event != JSON_BODY_EVENT:
            return await _sse_envelope(res, finish)
        # DockHand answered with JSON instead of a stream: a job to poll, or the final result.
        job_id = res.job_id
        if job_id is None:
            return await _sse_envelope(replace(res, final_event="result"), finish)
        progress.append(f"job: {job_label(job_id)}")
        job = await poll_job(
            ctx.client,
            job_id,
            max(stream_budget - res.waited_seconds, 1.0),
            redactor=redactor,
            on_line=_observe_job_line(on_event) if on_event is not None else None,
        )
        return await _job_stream_envelope(job_id, job, finish)

    return await run_registered(
        ctx, "sse", work, wait=wait, budget_s=budget_s, meta=meta, progress=progress
    )


async def run_async_pattern(
    kind: OperationKind,
    ctx: ToolContext,
    *,
    wait: bool,
    budget_s: float,
    meta: Mapping[str, Any],
    start: Callable[[], Awaitable[Any]] | None = None,
    sse: SseRequest | None = None,
    work: Work | None = None,
    finish: Finish | None = None,
    on_job_finish: JobFinish | None = None,
    redactor: OutputRedactor | None = None,
    on_event: EventObserver | None = None,
    review: Review | None = None,
) -> Envelope:
    """Dispatch to job-poll (`start`, `on_job_finish`), SSE-consume (`sse`, `finish`,
    `on_event`, `review`) or detached (`work`).

    Job and stream output and DockHand's direct answers are always redacted, inside the client
    modules. `redactor` (else the one the caller bound) adds the call's context values, a
    stack's own variable values, and is bound for the whole operation, detached work included.
    """
    active = redactor if redactor is not None else current_redactor()
    with redacting(active):
        if kind == "job" and start is not None:
            return await run_job(
                ctx, start, wait=wait, budget_s=budget_s, on_finish=on_job_finish, redactor=active
            )
        if kind == "sse" and sse is not None:
            return await run_sse(
                ctx,
                sse,
                wait=wait,
                budget_s=budget_s,
                meta=meta,
                finish=finish,
                redactor=active,
                on_event=on_event,
                review=review,
            )
        if kind == "detached" and work is not None:
            return await run_registered(
                ctx, "detached", work, wait=wait, budget_s=budget_s, meta=meta
            )
    raise ValueError(f"run_async_pattern({kind!r}) is missing its callable")


# --- read-back verification ---------------------------------------------------------------------

MAX_DIFF_LINES: Final = 3


def diff_summary(expected: str, actual: str) -> dict[str, Any]:
    """Line counts, byte counts and the first differing line numbers; never content."""
    want, got = expected.splitlines(), actual.splitlines()
    differing = [
        n + 1
        for n in range(max(len(want), len(got)))
        if (want[n] if n < len(want) else None) != (got[n] if n < len(got) else None)
    ]
    return {
        "expected_lines": len(want),
        "actual_lines": len(got),
        "expected_bytes": len(expected.encode("utf-8")),
        "actual_bytes": len(actual.encode("utf-8")),
        "first_differing_lines": differing[:MAX_DIFF_LINES],
    }


async def read_back_verify(
    expected: str, fetch: Callable[[], Awaitable[str]]
) -> tuple[bool, dict[str, Any] | None]:
    """GET the content back and compare it byte for byte: `(verified, diff summary or None)`."""
    actual = await fetch()
    if actual == expected:
        return True, None
    return False, diff_summary(expected, actual)


def verification_failed(what: str, diff: Mapping[str, Any], data: Mapping[str, Any]) -> Envelope:
    """`ok: false, verified: false` with the diff summary: never a success with a warning."""
    return Envelope(
        ok=False,
        data={**data, "read_back": dict(diff)},
        verified=False,
        error=ErrorInfo(
            code="verification_failed",
            message=(
                f"DockHand accepted the {what}, but reading it back returned different content "
                f"({diff['expected_lines']} lines written, {diff['actual_lines']} read back); "
                "it may not have been saved"
            ),
        ),
    )


def add_warnings(envelope: Envelope, warnings: Sequence[str]) -> Envelope:
    """`envelope` with `warnings` put before its own."""
    if not warnings:
        return envelope
    return envelope.model_copy(update={"warnings": [*warnings, *(envelope.warnings or [])]})


# --- destructive tier (S3b, D-006) --------------------------------------------------------------

CONFIRM_DESCRIPTION: Final = (
    "Approval for clients that cannot show an approval form. Ignored when the server asks the "
    "human through the client."
)
RATE_LIMITED: Final = (
    "Destructive-call limit reached ({limit} per minute for this caller); nothing was done. "
    "Retry in {seconds} seconds."
)
NO_APPROVAL_STATE: Final = "Destructive tools are unavailable without the approval state."


def scoped(env: int | None) -> int:
    """The resolved environment of an environment-scoped destructive tool."""
    if env is None:
        raise fail("validation_error", "environment_id could not be resolved")
    return env


class DestructiveInputs(WriteInputs):
    confirm: bool = Field(default=False, description=CONFIRM_DESCRIPTION)


class EnvDestructiveInputs(EnvScoped, DestructiveInputs):
    pass


class ApprovalRequired(Exception):  # noqa: N818 - control flow, not an error
    """Carries a destructive tool's `input_required` result out to the dispatcher."""

    def __init__(self, result: InputRequiredResult) -> None:
        super().__init__("input_required")
        self.result = result


PreviewFn = Callable[[ToolContext, Any, int | None], Awaitable[Preview]]
# Acts on `preview.target`; returns `data` or a complete envelope. `Approved` is the proof it may.
ExecuteFn = Callable[[ToolContext, Any, int | None, Preview, Approved], Awaitable[Any]]


def _audit_destructive(
    ctx: ToolContext,
    tool: str,
    outcome: str,
    *,
    method: str | None = None,
    nonce: str | None = None,
    counts: Mapping[str, int] | None = None,
) -> None:
    """The WARN audit line of a destructive call: never argument values, never the MAC."""
    audit_log.warning(
        "destructive_call",
        extra={
            "tool": tool,
            "principal": ctx.principal.name,
            "approval_method": method,
            "challenge_nonce": nonce,
            "preview_counts": dict(counts or {}),
            "outcome": outcome,
        },
    )


def _with_approval(envelope: Envelope, approved: Approved) -> Envelope:
    """Every destructive result records the method that approved it."""
    record = {"method": approved.method}
    data = envelope.data
    if isinstance(data, dict):
        merged: Any = {**data, "approval": record}
    elif data is None:
        merged = {"approval": record}
    else:
        merged = {"result": data, "approval": record}
    return envelope.model_copy(update={"data": merged})


@final
class DestructiveHandler:
    """The handler of every destructive tool, and the only caller of its execute function.

    Per call: the per-principal destructive rate limit (S-11); the preview, with the DockHand
    client refusing anything but GETs; `approve_or_request`; and only for `Approved`, the execute
    function, which also takes that `Approved` (only `auth/approval.py` can create one). The
    registry refuses a destructive tool whose handler is anything else.
    """

    __slots__ = ("_env_scoped", "_execute", "_preview", "_title", "_tool")

    def __init__(
        self, tool: str, title: str, preview: PreviewFn, execute: ExecuteFn, env_scoped: bool
    ) -> None:
        self._tool = tool
        self._title = title
        self._preview = preview
        self._execute = execute
        self._env_scoped = env_scoped

    @property
    def tool(self) -> str:
        return self._tool

    async def __call__(self, ctx: ToolContext, args: Any) -> Envelope:
        env: int | None = None
        env_warnings: list[str] = []
        if self._env_scoped:
            env, env_warnings = await resolve_env(ctx, args.environment_id)
        try:
            envelope = await self._run(ctx, args, env)
        except DockhandError as e:
            envelope = from_error(e, environment_id=env)
        warnings = env_warnings + (envelope.warnings or [])
        return envelope.model_copy(
            update={
                "environment_id": envelope.environment_id or env,
                "warnings": warnings or None,
            }
        )

    async def _run(self, ctx: ToolContext, args: Any, env: int | None) -> Envelope:
        approval = ctx.approval
        if approval is None:
            raise fail("confirmation_required", NO_APPROVAL_STATE)
        retry_in = approval.state.limiter.acquire(ctx.principal)
        if retry_in is not None:
            _audit_destructive(ctx, self._tool, "rate_limited")
            return err(
                "not_available",
                RATE_LIMITED.format(
                    limit=ctx.settings.destructive_per_min, seconds=max(1, round(retry_in))
                ),
            )
        canonical: dict[str, Any] = args.model_dump(mode="json")
        if self._env_scoped:
            canonical["environment_id"] = env
        try:
            with read_only_phase():
                preview = await self._preview(ctx, args, env)
        except DockhandError as e:
            _audit_destructive(ctx, self._tool, e.code)  # refused (or failed) before asking
            raise
        decision = approve_or_request(approval, self._tool, canonical, preview, title=self._title)
        if isinstance(decision, InputRequired):
            _audit_destructive(
                ctx, self._tool, "input_required", nonce=decision.nonce, counts=preview.counts
            )
            raise ApprovalRequired(decision.result)
        if isinstance(decision, Refused):
            _audit_destructive(
                ctx, self._tool, decision.code, nonce=decision.nonce, counts=preview.counts
            )
            return Envelope(
                ok=False,
                data={"preview": dict(preview.data)} if decision.with_preview else None,
                error=ErrorInfo(code=decision.code, message=decision.message),
            )
        try:
            result = await self._execute(ctx, args, env, preview, decision)
        except DockhandError as e:
            _audit_destructive(
                ctx,
                self._tool,
                e.code,
                method=decision.method,
                nonce=decision.nonce,
                counts=preview.counts,
            )
            raise
        envelope = _with_approval(result if isinstance(result, Envelope) else ok(result), decision)
        outcome = "ok" if envelope.ok or envelope.error is None else envelope.error.code
        _audit_destructive(
            ctx,
            self._tool,
            outcome,
            method=decision.method,
            nonce=decision.nonce,
            counts=preview.counts,
        )
        return envelope


def run_destructive(
    tool: str,
    title: str,
    preview_fn: PreviewFn,
    execute_fn: ExecuteFn,
    *,
    env_scoped: bool = True,
) -> DestructiveHandler:
    """The handler for a destructive tool: `execute_fn` runs only after approval (D-006)."""
    return DestructiveHandler(tool, title, preview_fn, execute_fn, env_scoped)


def destructive_tool(
    *,
    name: str,
    title: str,
    description: str,
    input_model: type[BaseModel],
    preview: PreviewFn,
    execute: ExecuteFn,
    audit_args: tuple[str, ...],
    env_scoped: bool = True,
) -> ToolSpec:
    """A destructive tool's spec: handler `run_destructive`, destructive annotations."""
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=run_destructive(name, title.lower(), preview, execute, env_scoped=env_scoped),
        annotations=DESTRUCTIVE_ANNOTATIONS,
        audit_args=audit_args,
    )


def dockhand_success(answer: Any, data: Mapping[str, Any], what: str) -> Envelope:
    """`data` plus DockHand's answer; an answer of `success: false` is an error."""
    out = {**data, "result": cap_json(answer)}
    if isinstance(answer, dict) and answer.get("success") is False:
        return Envelope(
            ok=False,
            data=out,
            error=ErrorInfo(
                code="operation_failed",
                message=f"DockHand reports the {what} failed; see data.result",
            ),
        )
    return ok(out)


# --- compound writes ----------------------------------------------------------------------------
# One DockHand request that persists content and then starts or redeploys it. Live DockHand
# 1.0.46 answers HTTP 200 with `success: false` (and its message under `error`) when the write
# happened and the deploy did not.


def answer_failed(answer: Any) -> bool:
    """DockHand's answer reports `success: false`."""
    return isinstance(answer, dict) and answer.get("success") is False


def answer_message(answer: Any) -> str | None:
    """DockHand's own message in an answer, redacted with the call's redactor and capped."""
    if not isinstance(answer, dict):
        return None
    for key in ("error", "message"):
        value = answer.get(key)
        if isinstance(value, str) and value.strip():
            return current_redactor().text(value)
    return None


def step(
    name: str, succeeded: bool | None, message: str | None = None, **extra: Any
) -> dict[str, Any]:
    """One step of a compound write: its name, outcome (`None`: unknown) and DockHand's
    redacted message."""
    outcome = "unknown" if succeeded is None else "succeeded" if succeeded else "failed"
    return {"step": name, "outcome": outcome, **extra, "message": message}


def partial_failure(message: str, data: Mapping[str, Any], *, verified: bool) -> Envelope:
    """A compound write whose first step happened and a later one failed: never a success."""
    return Envelope(
        ok=False,
        data=dict(data),
        verified=verified,
        error=ErrorInfo(code="operation_failed", message=message),
    )


# --- a content write that failed after it was sent (#17) ---------------------------------------
# A 5xx, or a connection lost once the request went out, does not mean nothing was written: the
# spec says every accepted `PUT …/compose` persists the content, and its 500 reads "Failed to save
# or deploy". Such a write is read back once, and the result says whether the content was saved.

Saved = bool | Literal["unknown"]
SAVED_AFTER_ERROR: Final = "DockHand reported an error, but the content was saved."


def may_have_written(e: DockhandError) -> bool:
    """A write that failed where DockHand may still have carried it out: a 5xx, or a request
    that was sent and got no answer. A 4xx (refused) and a connection never made did not."""
    if e.status is not None:
        return e.status >= 500
    return e.sent


@dataclass(frozen=True)
class SaveCheck:
    """The read-back after a failed write: `saved`, the diff summary when the content differs,
    and the error when the read-back itself failed."""

    saved: Saved
    diff: dict[str, Any] | None = None
    read_error: DockhandError | None = None


async def check_saved(
    expected: str,
    fetch: Callable[[], Awaitable[str]],
    *,
    absent: Saved = "unknown",
    differs: Saved = False,
) -> SaveCheck:
    """Read the content back once after a failed write.

    Byte-equal to `expected` → saved. Different → `differs` (for an update, what was sent is not
    what is stored). A 404 → `absent` (for a create, no stack means nothing was created). Any
    other failure to read → unknown.
    """
    try:
        actual = await fetch()
    except DockhandError as e:
        if e.code == "not_found" and absent != "unknown":
            return SaveCheck(absent)
        return SaveCheck("unknown", read_error=e)
    if actual == expected:
        return SaveCheck(True)
    return SaveCheck(differs, diff=diff_summary(expected, actual))


def read_back_step(check: SaveCheck) -> dict[str, Any]:
    """The read-back as a compound write's last step."""
    if check.read_error is None:
        return step("read_back", True)
    return step("read_back", False, current_redactor().text(check.read_error.message))


def write_error(
    error: DockhandError, check: SaveCheck, data: Mapping[str, Any], what: str, saved_next: str
) -> Envelope:
    """The result of a write that failed after it was sent, from its read-back.

    Saved → `operation_failed`, `verified: true`: the write happened, so saying it did not would
    invite a second one. Not saved, or unknown → `dockhand_http_error` with DockHand's status.
    `saved_next` tells the model what to do instead of writing again.
    """
    out: dict[str, Any] = {**data, "saved": check.saved}
    if check.diff is not None:
        out["read_back"] = check.diff
    if check.saved is True:
        code: ErrorCode = "operation_failed"
        message = f"{SAVED_AFTER_ERROR} The {what} reads back as sent; {saved_next}"
    elif check.saved is False:
        code = "dockhand_http_error"
        message = f"{error.message}; reading the {what} back showed it was not saved"
    else:
        code = "dockhand_http_error"
        cause = (
            f"reading the {what} back failed ({check.read_error.message})"
            if check.read_error is not None
            else f"the {what} reads back different from what was sent"
        )
        message = (
            f"{error.message}; {cause}, so whether it was saved is unknown. Read it before "
            "retrying."
        )
    return Envelope(
        ok=False,
        data=out,
        verified=True if check.saved is True else None,
        error=ErrorInfo(
            code=code,
            message=message,
            dockhand_status=error.status,
            retry_after=error.retry_after,
            detail=error.body_excerpt,
        ),
    )


MAX_NAMES_SHOWN: Final = 20


def names_text(names: Sequence[str], limit: int = MAX_NAMES_SHOWN) -> str:
    """`a, b, c and 7 more` (or `none`), each name truncated, for a preview summary."""
    if not names:
        return "none"
    shown = ", ".join(truncate(n, MAX_NAME_IN_MESSAGE) for n in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")
