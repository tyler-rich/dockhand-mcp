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
is `operation_failed`, with each container's outcome from `results`.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from dockhand_mcp.client.errors import ErrorCode
from dockhand_mcp.client.redaction import PLAIN, OutputRedactor

__all__ = ["BatchOutcome", "batch_summary", "interpret_batch", "interpret_update"]

SUCCEEDED_STATUSES: Final = frozenset({"done", "completed"})
COUNT_KEYS: Final = ("total", "success", "failed")

Outcome = Literal["succeeded", "failed", "unknown"]
_ITEM_OUTCOMES: Final[Mapping[str, Outcome]] = {"success": "succeeded", "error": "failed"}


@dataclass(frozen=True)
class BatchOutcome:
    """`problem` (and `code`) are None only when every item succeeded."""

    items: list[dict[str, Any]]
    summary: dict[str, int]
    problem: str | None
    code: ErrorCode | None = None


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


def _update_row(
    item: Mapping[str, str], results: Sequence[Mapping[str, Any]], redactor: OutputRedactor
) -> dict[str, Any]:
    """One sent container's outcome from DockHand's `results`.

    Live DockHand 1.0.46 answers with the recreated container's new id (S3g), so an item is
    matched by id (short or full) or, failing that, by its unchanged name.
    """
    row: dict[str, Any] = {"id": item["id"], "name": item["name"], "outcome": "unknown"}
    for result in results:
        cid = result.get("containerId")
        same_id = (
            isinstance(cid, str)
            and bool(cid)
            and (item["id"].startswith(cid) or cid.startswith(item["id"]))
        )
        if same_id or result.get("containerName") == item["name"]:
            success = result.get("success")
            if isinstance(success, bool):
                row["outcome"] = "succeeded" if success else "failed"
            message = _message(result.get("error"), redactor)
            if message is not None and not success:
                row["message"] = message
    return row


def interpret_update(
    answer: Any, sent: Sequence[Mapping[str, str]], redactor: OutputRedactor = PLAIN
) -> BatchOutcome:
    """Read `POST /api/containers/batch-update`'s answer for the `sent` containers.

    The spec's answer is `{success, results: [{containerId, containerName, success, error?}],
    summary: {total, success, failed}}`. Any failure indicator is `operation_failed`: a top-level
    `success: false`, a failed `results` item, or a non-zero `summary.failed`, even when the
    others disagree. An answer carrying none of them is not a failure.
    """
    body = answer if isinstance(answer, Mapping) else {}
    raw = body.get("results")
    results = [r for r in raw if isinstance(r, Mapping)] if isinstance(raw, list) else []
    items = [_update_row(item, results, redactor) for item in sent]
    summary = batch_summary(body) or {}
    counted = _count(summary.get("failed"))
    reported = sum(1 for r in results if r.get("success") is False)
    tally = _tally(items, len(sent))
    if counted is not None and counted > 0:
        total = _count(summary.get("total")) or len(sent)
        problem = f"{counted} of {total} containers failed to update"
    elif reported:
        problem = f"{reported} of {len(sent)} containers failed to update"
    elif body.get("success") is False:
        problem = "DockHand reports the update failed without naming a failed container"
    else:
        return BatchOutcome(items, tally, None)
    return BatchOutcome(items, tally, f"{problem}; see data.items", "operation_failed")


def _tally(items: Sequence[Mapping[str, Any]], sent: int) -> dict[str, int]:
    """Counts from the per-item lines, for a result whose own counts can't be used."""
    return {
        "total": sent,
        "succeeded": sum(1 for i in items if i["outcome"] == "succeeded"),
        "failed": sum(1 for i in items if i["outcome"] == "failed"),
    }
