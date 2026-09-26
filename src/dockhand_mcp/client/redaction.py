# SPDX-License-Identifier: Apache-2.0
"""The one redaction path for what DockHand says: operation output (job lines, SSE progress
entries, final result and error payloads, batch per-item messages), direct answers to writes,
error bodies, and the free text of every tool result.

The layers, in order:

1. Structured values (mappings): the key-based pass of `guardrails/secrets.py`. A sensitive key's
   non-null, non-boolean value becomes `REDACTED`; everything else is walked.
2. Every string value and plain-text line:
   a. the call's context values (a stack's own variable values, longest first) → `REDACTED`;
   b. `logging.redact()`: credentials embedded in URLs (`scheme://userinfo@host` →
      `scheme://<redacted>@host`), the configured secrets, `token=`/`password=` pairs,
      `Authorization` values, bearer credentials and `dh_` tokens.
3. Lines and progress entries are then capped at `MAX_ENTRY_CHARS`, so a secret can never
   survive as a fragment cut at the cap. Result payloads keep their size cap (`cap_json`).

Where each part is enforced, so no tool can skip it:
- `client/jobs.py`, `client/sse.py` and `client/batch.py`: operation output;
- `client/dockhand.py`: every answer to a non-GET request (all layers; a job id is kept as sent,
  since it is what gets polled) and every error body (all layers, before the 2 KiB cap);
- the tool dispatcher (`server.py`), on every result: the string layers, without context values,
  on DockHand's free text (`free_text`: values under message, error, status, output, reason,
  detail, warning and hint keys). GET answers are not redacted in the client, because tools
  read them for names, variables, read-back and job status.

A call's redactor is bound with `redacting()` for its duration (stack tools bind one carrying
their stack's values); it is `PLAIN` otherwise. Context values are held only by the redactor
for one call and are never logged.
"""

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from dockhand_mcp.guardrails.secrets import MASKED, REDACTED, is_sensitive_key
from dockhand_mcp.logging import redact, truncate

__all__ = [
    "FREE_TEXT_KEYS",
    "MAX_ENTRY_CHARS",
    "MIN_CONTEXT_VALUE_CHARS",
    "PLAIN",
    "OutputRedactor",
    "context_values",
    "current_redactor",
    "is_free_text_key",
    "parse_data",
    "redacting",
]

MAX_ENTRY_CHARS: Final = 512
MIN_CONTEXT_VALUE_CHARS: Final = 8
"""Shorter values (ports, flags, `UTC`) would mask ordinary words all over the output."""

# DockHand's (and Docker's) free-text fields: messages, errors, status strings, command output.
# Compared case-insensitively, as whole names or suffixes (`errorMessage`, `lastError`, `Output`).
FREE_TEXT_KEYS: Final = (
    "message",
    "messages",
    "msg",
    "error",
    "errors",
    "status",
    "output",
    "stdout",
    "stderr",
    "reason",
    "detail",
    "details",
    "warning",
    "warnings",
    "hint",
)


def is_free_text_key(key: str) -> bool:
    return key.lower().endswith(FREE_TEXT_KEYS)


def context_values(values: Iterable[Any]) -> tuple[str, ...]:
    """The values worth masking: distinct strings of at least `MIN_CONTEXT_VALUE_CHARS`
    characters other than DockHand's own `***` mask, longest first (so a value containing
    another is masked whole)."""
    kept = {
        v
        for v in values
        if isinstance(v, str) and len(v) >= MIN_CONTEXT_VALUE_CHARS and v != MASKED
    }
    return tuple(sorted(kept, key=lambda v: (-len(v), v)))


def _text(text: str, values: Sequence[str]) -> str:
    for value in values:
        text = text.replace(value, REDACTED)
    return redact(text)


def _value(value: Any, values: Sequence[str]) -> Any:
    if isinstance(value, str):
        return _text(value, values)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if (
                isinstance(key, str)
                and is_sensitive_key(key)
                and item is not None
                and not isinstance(item, bool)
            ):
                out[key] = REDACTED
            else:
                out[key] = _value(item, values)
        return out
    if isinstance(value, list | tuple):
        return [_value(item, values) for item in value]
    return value


def _strings(value: Any, values: Sequence[str]) -> Any:
    """The string layers on every string in `value` (no key-based pass)."""
    if isinstance(value, str):
        return _text(value, values)
    if isinstance(value, Mapping):
        return {key: _strings(item, values) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_strings(item, values) for item in value]
    return value


def _free_text(value: Any, values: Sequence[str]) -> Any:
    """The string layers on everything under a free-text key; other values are walked."""
    if isinstance(value, Mapping):
        return {
            key: (
                _strings(item, values)
                if isinstance(key, str) and is_free_text_key(key)
                else _free_text(item, values)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_free_text(item, values) for item in value]
    return value


def _format_line(item: Any) -> str:
    """A job line as text: `{event, data}` records as `event: <data JSON>`, others as JSON."""
    if isinstance(item, Mapping) and "event" in item:
        return f"{item.get('event')}: {json.dumps(item.get('data'), default=str)}"
    return item if isinstance(item, str) else json.dumps(item, default=str)


def parse_data(data: str) -> Any:
    """SSE event data as JSON when it is JSON, else the text itself."""
    try:
        return json.loads(data)
    except ValueError:
        return data


@dataclass(frozen=True)
class OutputRedactor:
    """Redacts one call's DockHand output; `values` are that call's context values."""

    values: tuple[str, ...] = ()

    @classmethod
    def for_values(cls, values: Iterable[Any]) -> OutputRedactor:
        return cls(context_values(values))

    def __call__(self, value: Any) -> Any:
        """A redacted copy of a structured value or string (no length cap)."""
        return _value(value, self.values)

    def text(self, text: str) -> str:
        """Plain text, redacted, then capped at `MAX_ENTRY_CHARS`."""
        return truncate(_text(text, self.values), MAX_ENTRY_CHARS)

    def line(self, item: Any) -> str:
        """One job line (structured or text) as capped text, redacted first."""
        return self.text(_format_line(self(item)))

    def _structured(self, data: str) -> str:
        """JSON text with the structured pass applied, re-serialised only if that changed it;
        anything else as it is. A value JSON escapes (quotes, backslashes) is still matched."""
        parsed = parse_data(data)
        if isinstance(parsed, Mapping | list):
            redacted = self(parsed)
            if redacted != parsed:
                return json.dumps(redacted, separators=(",", ":"), default=str)
        return data

    def document(self, data: str) -> str:
        """Text that may be JSON (an error body), redacted: structured pass, then the string
        layers. Uncapped; the caller caps it."""
        return _text(self._structured(data), self.values)

    def event(self, event: str, data: str) -> str:
        """One SSE progress entry, `event: data`; JSON data gets the structured pass too."""
        return self.text(f"{event}: {self._structured(data)}")

    def free_text(self, value: Any) -> Any:
        """A copy with the string layers applied under every free-text key (`FREE_TEXT_KEYS`)."""
        return _free_text(value, self.values)


PLAIN: Final = OutputRedactor()
"""No context values: what every call gets unless a tool binds its own."""

_current: ContextVar[OutputRedactor] = ContextVar("output_redactor", default=PLAIN)


def current_redactor() -> OutputRedactor:
    """The redactor bound for this call (`PLAIN` unless a tool bound one)."""
    return _current.get()


@contextmanager
def redacting(redactor: OutputRedactor) -> Iterator[None]:
    """Bind `redactor` for the duration, including detached work started inside it."""
    token = _current.set(redactor)
    try:
        yield
    finally:
        _current.reset(token)
