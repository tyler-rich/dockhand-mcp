# SPDX-License-Identifier: Apache-2.0
"""Job polling (ARCHITECTURE §4.1): take a DockHand `{jobId}` and poll GET /api/jobs/{id}.

The spec gives the job shape (`{id, status, lines[], result?}`) but does not enumerate statuses.
`done` (what live DockHand 1.0.46 finishes jobs with; success or failure is in `result`),
`completed`, `failed`, `cancelled` and `error` are terminal. Anything else counts as still
running; values other than the expected running ones are logged once each as
`unknown_job_status`. Polling never cancels the job: when the budget runs out we stop waiting and
the job carries on in DockHand.

Everything a job says is operation output: its lines and result are redacted here
(`client/redaction.py`) before they are returned, with the caller's context values if any.
Only the first `MAX_LINES` lines are returned; `on_line` sees every line of a finished job,
redacted, for a caller that reads a status near the end of a long job.
"""

import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

import anyio

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.redaction import PLAIN, OutputRedactor
from dockhand_mcp.logging import truncate

log = logging.getLogger(__name__)

TERMINAL_STATUSES: Final = frozenset({"done", "completed", "failed", "cancelled", "error"})
RUNNING_STATUSES: Final = frozenset({"running", "pending", "queued"})
MAX_LINES: Final = 500
DEFAULT_INTERVAL_S: Final = 2.0
_MAX_REMEMBERED_UNKNOWN: Final = 100
_SAFE_ID: Final = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Progress callback: (our own message, elapsed seconds). Never carries DockHand output.
ProgressCallback = Callable[[str, float], Awaitable[None]]

_unknown_seen: set[str] = set()


@dataclass(frozen=True)
class JobResult:
    """A polled job; `lines` and `result` are already redacted."""

    status: str
    lines: list[Any]
    result: Any
    waited_seconds: float
    timed_out: bool


def job_id_of(body: Any) -> str | None:
    """The job id of DockHand's answer to a job-starting request, if it is one."""
    job_id = body.get("jobId") if isinstance(body, dict) else None
    return job_id if isinstance(job_id, str) and job_id else None


def synchronous_answer(body: Any, redactor: OutputRedactor = PLAIN) -> Any:
    """DockHand's final result given instead of a job id, redacted like a job's result."""
    return redactor(body)


def redact_job(body: Any, redactor: OutputRedactor = PLAIN) -> Any:
    """A `GET /api/jobs/{id}` body as a tool may return it: lines and result redacted."""
    return redactor(body)


def _note_unknown(status: str) -> None:
    if status in RUNNING_STATUSES or status in _unknown_seen:
        return
    if len(_unknown_seen) < _MAX_REMEMBERED_UNKNOWN:
        _unknown_seen.add(status)
    log.warning("unknown_job_status", extra={"job_status": truncate(status, 64)})


def job_label(job_id: str) -> str:
    """The job id for our own messages, withheld if DockHand sent something odd."""
    return job_id if _SAFE_ID.match(job_id) else "(id withheld)"


async def poll_job(
    client: DockhandClient,
    job_id: str,
    budget_s: float,
    interval_s: float = DEFAULT_INTERVAL_S,
    on_progress: ProgressCallback | None = None,
    *,
    redactor: OutputRedactor = PLAIN,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    on_line: Callable[[Any], None] | None = None,
) -> JobResult:
    started = clock()
    label = job_label(job_id)
    while True:
        body = await client.get_json("/api/jobs/{id}", path_params={"id": job_id})
        job = body if isinstance(body, dict) else {}
        status = str(job.get("status", ""))
        raw_lines = job.get("lines")
        elapsed = clock() - started
        terminal = status in TERMINAL_STATUSES
        if not terminal:
            _note_unknown(status)
        remaining = budget_s - elapsed
        if terminal or remaining <= 0:
            lines = raw_lines[:MAX_LINES] if isinstance(raw_lines, list) else []
            if terminal and on_line is not None and isinstance(raw_lines, list):
                for line in raw_lines:
                    on_line(redactor(line))
            return JobResult(
                status, redactor(lines), redactor(job.get("result")), elapsed, not terminal
            )
        if on_progress is not None:
            await on_progress(f"waiting for DockHand job {label}: {elapsed:.0f}s elapsed", elapsed)
        await sleep(min(interval_s, remaining))
