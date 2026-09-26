# SPDX-License-Identifier: Apache-2.0
"""SSE consumption (ARCHITECTURE §4.2): read a DockHand event stream to its terminal event.

The spec's streaming endpoints emit `progress` events and a final `result` event; `error` is
treated as terminal too, and so is a JSON answer (`JSON_BODY_EVENT`, e.g. a job id). Other
events are kept as progress, the last 50, each at most 512 characters. Progress entries and the
terminal payload are operation output, redacted here (`client/redaction.py`) before anything is
kept; a JSON answer's job id is read before that and returned as `job_id`. If the budget runs out
the stream is closed and the result says `timed_out`; the operation carries on in DockHand. A
stream that ends without a terminal event gives `final_event="eof"`. A caller may pass its own
`progress` buffer to read the lines while the stream is still being consumed (a detached
consumption, ARCHITECTURE §4.3), and an `on_event` observer that sees every progress event's
data, parsed and redacted but not capped (a tool reading a status the tail may not hold).
"""

import time
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any, Final

import anyio

from dockhand_mcp.client.dockhand import JSON_BODY_EVENT, DockhandClient, Params
from dockhand_mcp.client.jobs import ProgressCallback, job_id_of
from dockhand_mcp.client.redaction import MAX_ENTRY_CHARS, PLAIN, OutputRedactor, parse_data

__all__ = ["MAX_ENTRY_CHARS", "MAX_PROGRESS", "EventObserver", "SseResult", "consume"]

MAX_PROGRESS: Final = 50
TERMINAL_EVENTS: Final = frozenset({"result", "error", JSON_BODY_EVENT})
PROGRESS_REPORT_INTERVAL_S: Final = 1.0
# Extra read-timeout headroom so the budget, not httpx, decides when we stop.
_READ_TIMEOUT_MARGIN_S: Final = 5.0

# Sees each progress event: (event name, its data parsed and redacted).
EventObserver = Callable[[str, Any], None]


@dataclass(frozen=True)
class SseResult:
    final_event: str | None
    final_data: Any
    progress: deque[str]
    waited_seconds: float
    timed_out: bool
    job_id: str | None = None


async def consume(
    client: DockhandClient,
    method: str,
    template: str,
    *,
    budget_s: float,
    path_params: Mapping[str, str | int] | None = None,
    params: Params | None = None,
    json: Any = None,
    on_progress: ProgressCallback | None = None,
    progress: deque[str] | None = None,
    redactor: OutputRedactor = PLAIN,
    clock: Callable[[], float] = time.monotonic,
    on_event: EventObserver | None = None,
) -> SseResult:
    if progress is None:
        progress = deque(maxlen=MAX_PROGRESS)
    final_event: str | None = None
    final_data: Any = None
    job_id: str | None = None
    started = clock()
    last_report = float("-inf")
    events_seen = 0
    with anyio.move_on_after(budget_s) as scope:
        stream = client.stream_sse(
            method,
            template,
            path_params=path_params,
            params=params,
            json=json,
            read_timeout=budget_s + _READ_TIMEOUT_MARGIN_S,
        )
        async with aclosing(stream) as events:
            async for event, data in events:
                if event in TERMINAL_EVENTS:
                    parsed = parse_data(data)
                    if event == JSON_BODY_EVENT:
                        job_id = job_id_of(parsed)
                    final_event, final_data = event, redactor(parsed)
                    break
                progress.append(redactor.event(event, data))
                if on_event is not None:
                    on_event(event, redactor(parse_data(data)))
                events_seen += 1
                now = clock()
                if on_progress is not None and now - last_report >= PROGRESS_REPORT_INTERVAL_S:
                    last_report = now
                    elapsed = now - started
                    await on_progress(
                        f"streaming: {events_seen} progress events, {elapsed:.0f}s elapsed",
                        elapsed,
                    )
            else:
                final_event = "eof"
    return SseResult(
        final_event=final_event,
        final_data=final_data,
        progress=progress,
        waited_seconds=clock() - started,
        timed_out=scope.cancelled_caught,
        job_id=job_id,
    )
