# SPDX-License-Identifier: Apache-2.0
"""JSON-lines logging: redaction, request-scoped context and the audit line (D-009, S-10).

Logs always go to stderr: the stdio transport reserves stdout for the protocol, and one stream
keeps HTTP deployments simple.
"""

import json
import logging
import re
import sys
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from types import MappingProxyType
from typing import IO, Any, Final

from dockhand_mcp.guardrails.secrets import REDACTED

MAX_MESSAGE_CHARS: Final = 512

# The userinfo of a URL: a user, a token, or user:password. It cannot cross `/`, `?`, `#` or
# whitespace, so `https://host/a@b` and `ops@example.test` are left alone.
_URL_USERINFO: Final = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/?#@\"'<>]+@")
_DH_TOKEN: Final = re.compile(r"dh_[A-Za-z0-9_-]+")
# `Authorization: <scheme> <credentials>` in header, JSON or key=value form. The scheme is kept.
_AUTHORIZATION: Final = re.compile(
    r"""(?i)\b(authorization["']?\s*[:=]\s*["']?)(?:([a-z]+)\s+)?([^\s"',;]+)"""
)
_BEARER: Final = re.compile(r"(?i)\b(bearer)\s+\S+")
# token=… / password=… pairs, including compounds such as access_token= or DOCKHAND_TOKEN=.
_PAIR: Final = re.compile(r"(?i)\b([\w-]*(?:token|password)[\w-]*=)[^\s&,;]+")

# Attributes every LogRecord has; anything else came from `extra=` and is emitted as a field.
# `color_message` is uvicorn's ANSI-coloured duplicate of the message.
_RECORD_ATTRS: Final = frozenset(
    set(vars(logging.LogRecord("", 0, "", 0, "", None, None)))
    | {"message", "asctime", "taskName", "color_message"}
)

_secrets: tuple[str, ...] = ()
_secrets_lock = threading.Lock()

# Request-scoped fields (request id, principal, tool) added to every line logged in that scope.
_context: ContextVar[Mapping[str, Any]] = ContextVar(
    "dockhand_mcp_log_context", default=MappingProxyType({})
)

audit_log: Final = logging.getLogger("dockhand_mcp.audit")

# Third-party loggers that record full request URLs (query values included) or connection
# details at INFO/DEBUG. Our client logs one sanitised line per call instead.
_QUIET_LOGGERS: Final = ("httpx", "httpcore", "httpx2", "httpcore2")


def set_redaction_secrets(secrets: Iterable[str]) -> None:
    """Replace the process-wide secret values `redact()` masks."""
    global _secrets
    with _secrets_lock:
        _secrets = tuple(s for s in secrets if s)


def _authorization(match: re.Match[str]) -> str:
    prefix, scheme, _ = match.groups()
    return f"{prefix}{scheme} ***" if scheme else f"{prefix}***"


def redact_url_credentials(text: str) -> str:
    """`scheme://userinfo@host` → `scheme://<redacted>@host`; the scheme and host are kept.

    The one implementation of this rule: `redact()` applies it to log lines and error bodies, and
    through it `client/redaction.py` to tool output.
    """
    return _URL_USERINFO.sub(rf"\1{REDACTED}@", text)


def redact(text: str, secrets: Iterable[str] | None = None) -> str:
    """Mask secrets in `text`.

    Covers credentials embedded in URLs, DockHand `dh_` tokens anywhere, `Authorization` values,
    bearer credentials, `token=`/`password=` pairs, and the given secret values, or the process's
    configured ones (the MCP and DockHand tokens) when `secrets` is None.
    """
    text = redact_url_credentials(text)
    values = _secrets if secrets is None else tuple(secrets)
    for secret in sorted((s for s in values if s), key=len, reverse=True):
        text = text.replace(secret, "***")
    # Pairs first, so a key such as `dh_token=` is still recognised before `dh_…` is masked.
    text = _PAIR.sub(r"\1***", text)
    text = _AUTHORIZATION.sub(_authorization, text)
    text = _BEARER.sub(r"\1 ***", text)
    return _DH_TOKEN.sub("dh_***", text)


def truncate(text: str, limit: int = MAX_MESSAGE_CHARS) -> str:
    """Cap free text at `limit` characters, marking the cut with an ellipsis."""
    return text if len(text) <= limit else text[:limit] + "…"


def _clean(value: object) -> object:
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_clean(v) for v in value]
    text = value if isinstance(value, str) else repr(value)
    return truncate(redact(text))


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    """Add `fields` to every line logged in this (async) context."""
    token = _context.set({**_context.get(), **fields})
    try:
        yield
    finally:
        _context.reset(token)


def audit(
    *,
    tool: str,
    principal: str,
    args: Mapping[str, Any],
    outcome: str,
    duration_ms: float,
    dockhand_status: int | None,
    **extra: Any,
) -> None:
    """Emit the one-line audit record for a tool invocation (S-10).

    `args` must already be sanitised to IDs and names; values are still redacted and truncated.
    """
    audit_log.info(
        "tool_call",
        extra={
            "tool": tool,
            "principal": principal,
            "arguments": dict(args),
            "outcome": outcome,
            "duration_ms": round(duration_ms, 1),
            "dockhand_status": dockhand_status,
            **extra,
        },
    )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": truncate(redact(record.getMessage())),
        }
        for key, value in _context.get().items():
            out.setdefault(key, _clean(value))
        for key, value in vars(record).items():
            if key not in _RECORD_ATTRS and key not in out:
                out[key] = _clean(value)
        if record.exc_info and record.exc_info[0] is not None:
            out["exc_type"] = record.exc_info[0].__name__
        return json.dumps(out, ensure_ascii=True, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = truncate(redact(record.getMessage()))
        return f"{record.levelname.lower()} {record.name}: {json.dumps(message)[1:-1]}"


def configure_logging(
    level: str,
    fmt: str,
    *,
    stream: IO[str] | None = None,
    secrets: Iterable[str] = (),
) -> None:
    """Replace the root logger's handlers with one redacting handler on stderr (or `stream`)."""
    set_redaction_secrets(secrets)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
