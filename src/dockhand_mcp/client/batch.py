# SPDX-License-Identifier: Apache-2.0
"""What a finished `POST /api/batch` job says about each item (issue #6).

Live DockHand 1.0.46 ends a batch job with status `done` and a `result` of
`{type: "complete", summary: {total, success, failed}}`: there is no `success` key for the
generic job check to see. The job's `lines` are `{data}` records (no `event` key): one
`{type: "start", total}`, then per item `{type: "progress", id, name, status, current, total}`
with `status` `processing`, then `success` or `error` (with an `error` message), and finally
`{type: "complete", summary}`. The spec's synchronous answer is the summary alone, with no lines.

The summary decides success; the lines give each item's outcome. A result that is missing, not in
that shape, or contradicted by the lines is never read as success. A job that failed, or any item
that failed, is `operation_failed` (DockHand answered; the operation did not succeed); a result
that can't be read is an unexpected response, `dockhand_http_error`. Per-item messages go through
the operation-output redaction (`client/redaction.py`), then the 512-character cap.

`interpret_update` reads `POST /api/containers/batch-update`'s synchronous answer the same way:
any failure it reports, including a top-level `success: false` that names no failed container,
is `operation_failed`, with each container's outcome from `results`. A container is `succeeded`
only on `success: true` with nothing that says otherwise (issue #20). DockHand 1.0.55's route
(read in its public source) reports its one skip, the `dockhand.update=false` label, as
`success: true` with an `error` starting `Skipped`: that is `skipped`. Each result may carry
`warnings: [{status, message}]`; the only status that route sends, `warning`, is a
minimum-release-age advisory for a pull that goes ahead, so it is informational. Any other
error on a success, any other warning status and any unreadable warning are `unverified`. Every
container that is not `succeeded` (an `unknown` one included) is `operation_failed`.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from dockhand_mcp.client.errors import ErrorCode
from dockhand_mcp.client.redaction import PLAIN, OutputRedactor

__all__ = [
    "UPDATE_OUTCOMES",
    "BatchOutcome",
    "batch_summary",
    "interpret_batch",
    "interpret_update",
]

SUCCEEDED_STATUSES: Final = frozenset({"done", "completed"})
COUNT_KEYS: Final = ("total", "success", "failed")

Outcome = Literal["succeeded", "failed", "unknown"]
_ITEM_OUTCOMES: Final[Mapping[str, Outcome]] = {"success": "succeeded", "error": "failed"}

UpdateOutcome = Literal["succeeded", "failed", "skipped", "unverified", "unknown"]
UPDATE_OUTCOMES: Final[tuple[UpdateOutcome, ...]] = (
    "succeeded",
    "failed",
    "skipped",
    "unverified",
    "unknown",
)
# Batch-update warning statuses that leave the update itself untouched (DockHand 1.0.55 source).
INFORMATIONAL_WARNINGS: Final = frozenset({"warning"})
SKIPPED_PREFIX: Final = "Skipped"


@dataclass(frozen=True)
class BatchOutcome:
    """`problem` (and `code`) are None only when every item succeeded. `warnings` are
    informational notes for the envelope."""

    items: list[dict[str, Any]]
    summary: dict[str, int]
    problem: str | None
    code: ErrorCode | None = None
    warnings: list[str] = field(default_factory=list)


def batch_summary(result: Any) -> Mapping[str, Any] | None:
    """The `summary` object of a batch result, unchecked, or None when there is none."""
    summary = result.get("summary") if isinstance(result, Mapping) else None
    return summary if isinstance(summary, Mapping) else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _checked_counts(result: Any, sent: int) -> tuple[dict[str, int] | None, str | None]:
    """DockHand's `{total, succeeded, failed}`, or None and why the result can't be read."""
    if not isinstance(result, Mapping):
        return None, "the job has no result"
    if result.get("type") != "complete":
        return None, "the result is not a completion summary"
    summary = batch_summary(result)
    if summary is None:
        return None, "the result has no summary"
    counts = {key: _count(summary.get(key)) for key in COUNT_KEYS}
    total, success, failed = (counts[key] for key in COUNT_KEYS)
    if total is None or success is None or failed is None:
        return None, "the summary's counts are missing or not whole numbers"
    if success + failed != total:
        return None, f"the summary's counts do not add up ({success} + {failed} != {total})"
    if total != sent:
        return None, f"the summary counts {total} items, but {sent} were sent"
    return {"total": total, "succeeded": success, "failed": failed}, None


def _line_data(line: Any) -> Mapping[str, Any] | None:
    data = line.get("data") if isinstance(line, Mapping) else None
    return data if isinstance(data, Mapping) else None


def _message(value: Any, redactor: OutputRedactor) -> str | None:
    return redactor.text(value) if isinstance(value, str) and value else None


def _items(
    lines: Sequence[Any], sent: Sequence[Mapping[str, str]], redactor: OutputRedactor
) -> list[dict[str, Any]]:
    """Each sent item with its last reported outcome; names and ids are ours, not DockHand's."""
    outcomes: dict[str, tuple[Outcome, str | None]] = {}
    ids = {item["id"] for item in sent}
    for line in lines:
        data = _line_data(line)
        if data is None or data.get("type") != "progress" or data.get("id") not in ids:
            continue
        outcome = _ITEM_OUTCOMES.get(str(data.get("status")))
        if outcome is not None:
            outcomes[str(data["id"])] = (outcome, _message(data.get("error"), redactor))
    items = []
    for item in sent:
        outcome, message = outcomes.get(item["id"], ("unknown", None))
        row: dict[str, Any] = {"id": item["id"], "name": item["name"], "outcome": outcome}
        if message is not None:
            row["message"] = message
        items.append(row)
    return items


def interpret_batch(
    status: str,
    result: Any,
    lines: Sequence[Any],
    sent: Sequence[Mapping[str, str]],
    redactor: OutputRedactor = PLAIN,
) -> BatchOutcome:
    """Read a finished batch job (or the synchronous answer, with no lines) for the `sent` items."""
    items = _items(lines, sent, redactor)
    counts, unreadable = _checked_counts(result, len(sent))
    failed_items = sum(1 for i in items if i["outcome"] == "failed")
    if status not in SUCCEEDED_STATUSES:
        tally = counts or _tally(items, len(sent))
        problem = f"DockHand reports the batch job {status or 'failed'}"
        return BatchOutcome(items, tally, problem, "operation_failed")
    if counts is None:
        problem = f"DockHand's batch result can't be read: {unreadable}"
        return BatchOutcome(items, _tally(items, len(sent)), problem, "dockhand_http_error")
    if counts["failed"] > 0:
        problem = f"{counts['failed']} of {counts['total']} items failed"
        return BatchOutcome(items, counts, problem, "operation_failed")
    if failed_items:
        problem = f"DockHand's summary reports no failures, but {failed_items} item(s) failed"
        return BatchOutcome(items, counts, problem, "operation_failed")
    return BatchOutcome(items, counts, None)


def _update_warnings(
    raw: Any, redactor: OutputRedactor
) -> tuple[list[dict[str, str]], list[str], bool]:
    """A result's `warnings`: the readable ones (redacted, capped), the informational messages,
    and whether any is unclassified or unreadable."""
    if raw is None:
        return [], [], False
    if not isinstance(raw, list):
        return [], [], True
    kept: list[dict[str, str]] = []
    notes: list[str] = []
    doubtful = False
    for warning in raw:
        status = warning.get("status") if isinstance(warning, Mapping) else None
        message = warning.get("message") if isinstance(warning, Mapping) else None
        if not (isinstance(status, str) and status and isinstance(message, str)):
            doubtful = True
            continue
        text = redactor.text(message)
        kept.append({"status": redactor.text(status), "message": text})
        if status in INFORMATIONAL_WARNINGS:
            notes.append(text)
        else:
            doubtful = True
    return kept, notes, doubtful


def _update_row(
    item: Mapping[str, str], results: Sequence[Mapping[str, Any]], redactor: OutputRedactor
) -> tuple[dict[str, Any], list[str]]:
    """One sent container's outcome from DockHand's `results`, and its informational notes.

    Live DockHand 1.0.46 answers with the recreated container's new id (S3g), so an item is
    matched by id (short or full) or, failing that, by its unchanged name.
    """
    row: dict[str, Any] = {"id": item["id"], "name": item["name"], "outcome": "unknown"}
    notes: list[str] = []
    for result in results:
        cid = result.get("containerId")
        same_id = (
            isinstance(cid, str)
            and bool(cid)
            and (item["id"].startswith(cid) or cid.startswith(item["id"]))
        )
        if not (same_id or result.get("containerName") == item["name"]):
            continue
        row = {"id": item["id"], "name": item["name"], "outcome": "unknown"}
        success = result.get("success")
        error = result.get("error")
        message = _message(error, redactor)
        warnings, notes, doubtful = _update_warnings(result.get("warnings"), redactor)
        outcome: UpdateOutcome = "unknown"
        if success is False:
            outcome = "failed"
        elif success is True:
            if isinstance(error, str) and error.startswith(SKIPPED_PREFIX):
                outcome = "skipped"
            elif message is not None or doubtful:
                outcome = "unverified"
            else:
                outcome = "succeeded"
        row["outcome"] = outcome
        if message is not None and outcome != "succeeded":
            row["message"] = message
        if warnings:
            row["warnings"] = warnings
    return row, [f"{item['name']}: {note}" for note in notes]


def interpret_update(
    answer: Any, sent: Sequence[Mapping[str, str]], redactor: OutputRedactor = PLAIN
) -> BatchOutcome:
    """Read `POST /api/containers/batch-update`'s answer for the `sent` containers.

    The spec's answer is `{success, results: [{containerId, containerName, success, error?,
    warnings?}], summary: {total, success, failed}}`. Any failure indicator is
    `operation_failed`: a top-level `success: false`, a failed `results` item, or a non-zero
    `summary.failed`, even when the others disagree. So is any container whose outcome is not
    `succeeded` (#20).
    """
    body = answer if isinstance(answer, Mapping) else {}
    raw = body.get("results")
    results = [r for r in raw if isinstance(r, Mapping)] if isinstance(raw, list) else []
    rows = [_update_row(item, results, redactor) for item in sent]
    items = [row for row, _ in rows]
    notes = [note for _, row_notes in rows for note in row_notes]
    summary = batch_summary(body) or {}
    counted = _count(summary.get("failed"))
    reported = sum(1 for r in results if r.get("success") is False)
    tally = _update_tally(items, len(sent))
    problems = []
    if counted is not None and counted > 0:
        total = _count(summary.get("total")) or len(sent)
        problems.append(f"{counted} of {total} containers failed to update")
    elif reported:
        problems.append(f"{reported} of {len(sent)} containers failed to update")
    elif body.get("success") is False:
        problems.append("DockHand reports the update failed without naming a failed container")
    if any(tally[k] for k in ("skipped", "unverified", "unknown")):
        missed = {k: tally[k] for k in UPDATE_OUTCOMES if k != "succeeded" and tally[k]}
        breakdown = ", ".join(f"{n} {k}" for k, n in missed.items())
        problems.append(
            f"{sum(missed.values())} of {len(sent)} containers were not confirmed updated: "
            f"{breakdown}"
        )
    if not problems:
        return BatchOutcome(items, tally, None, warnings=notes)
    problem = f"{'; '.join(problems)}; see data.items"
    return BatchOutcome(items, tally, problem, "operation_failed", notes)


def _update_tally(items: Sequence[Mapping[str, Any]], sent: int) -> dict[str, int]:
    """Counts of each update outcome among the sent containers."""
    counts: dict[str, int] = {"total": sent}
    for outcome in UPDATE_OUTCOMES:
        counts[outcome] = sum(1 for i in items if i["outcome"] == outcome)
    return counts


def _tally(items: Sequence[Mapping[str, Any]], sent: int) -> dict[str, int]:
    """Counts from the per-item lines, for a result whose own counts can't be used."""
    return {
        "total": sent,
        "succeeded": sum(1 for i in items if i["outcome"] == "succeeded"),
        "failed": sum(1 for i in items if i["outcome"] == "failed"),
    }
