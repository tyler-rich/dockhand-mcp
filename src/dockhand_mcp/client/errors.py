# SPDX-License-Identifier: Apache-2.0
"""DockHand failures mapped onto the envelope's closed set of error codes (F-12).

Status semantics are the spec's: 401 means DockHand did not authenticate the caller (token
missing, wrong, expired or revoked); 403 means an authenticated caller lacks a permission, has no
access to the environment, or hit an Enterprise-only feature. Neither is ever retried. Bodies are
redacted and truncated to 2 KiB before they go anywhere.

`dockhand_http_error` is for failures at the HTTP level (a 4xx/5xx, an unexpected or unreadable
answer). `operation_failed` is for an operation DockHand accepted and then reported as failed: a
failed job, a failed batch item, an SSE `error` event, a result of `success: false`.

`sent` says whether DockHand may have received the request: always for an answer, and for a
transport failure other than a connection that was never made (a dropped connection or a read
timeout after the request went out). A content write whose error was `sent` is read back.
"""

from typing import Final, Literal, get_args

import httpx

from dockhand_mcp.client.redaction import PLAIN, OutputRedactor
from dockhand_mcp.logging import truncate

ErrorCode = Literal[
    "validation_error",
    "not_found",
    "ambiguous_name",
    "dockhand_http_error",
    "dockhand_unreachable",
    "unexpected_redirect",
    "guardrail_blocked",
    "confirmation_required",
    "timeout",
    "operation_unknown",
    "profile_denied",
    "not_available",
    "verification_failed",
    "operation_failed",
]
ERROR_CODES: Final[tuple[ErrorCode, ...]] = get_args(ErrorCode)

MAX_BODY_EXCERPT: Final = 2048

HINT_401: Final = (
    "DockHand rejected the API token (HTTP 401): it is missing, wrong, expired or revoked. "
    "Create a new dh_ token for the MCP server's DockHand user."
)
HINT_403: Final = (
    "DockHand denied the request (HTTP 403): the token's user lacks the permission for this "
    "operation or has no access to this environment, or the feature needs DockHand Enterprise."
)


class DockhandError(Exception):
    def __init__(
        self,
        status: int | None,
        code: ErrorCode,
        message: str,
        body_excerpt: str | None = None,
        *,
        retry_after: int | None = None,
        sent: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code: ErrorCode = code
        self.message = message
        self.body_excerpt = body_excerpt
        self.retry_after = retry_after
        self.sent = sent or status is not None


def body_excerpt(body: bytes, redactor: OutputRedactor = PLAIN) -> str | None:
    """DockHand's error body as text, redacted (every layer of `client/redaction.py`, with the
    call's context values) before it is cut to 2 KiB, so no secret survives as a fragment."""
    if not body:
        return None
    text = body[: MAX_BODY_EXCERPT * 4].decode("utf-8", errors="replace")
    return truncate(redactor.document(text), MAX_BODY_EXCERPT)


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("retry-after", "").strip()
    return int(value) if value.isdigit() else None


def from_response(
    response: httpx.Response, body: bytes, redactor: OutputRedactor = PLAIN
) -> DockhandError:
    """The error for a non-2xx response whose (possibly partial) body is `body`."""
    status = response.status_code
    excerpt = body_excerpt(body, redactor)
    if 300 <= status < 400:
        return DockhandError(
            status,
            "unexpected_redirect",
            f"DockHand answered with a redirect (HTTP {status}); redirects are never followed. "
            "Check DOCKHAND_URL (scheme, host and path prefix).",
        )
    if status == 401:
        return DockhandError(status, "dockhand_http_error", HINT_401, excerpt)
    if status == 403:
        return DockhandError(status, "dockhand_http_error", HINT_403, excerpt)
    if status == 404:
        return DockhandError(status, "not_found", "DockHand: not found (HTTP 404)", excerpt)
    if status == 429:
        return DockhandError(
            status,
            "dockhand_http_error",
            "DockHand is rate limiting this client (HTTP 429)",
            excerpt,
            retry_after=_retry_after(response),
        )
    if status >= 500:
        return DockhandError(
            status, "dockhand_http_error", f"DockHand server error (HTTP {status})", excerpt
        )
    return DockhandError(
        status, "dockhand_http_error", f"DockHand rejected the request (HTTP {status})", excerpt
    )


def from_transport(exc: httpx.HTTPError) -> DockhandError:
    """The error for a request that got no response."""
    if isinstance(exc, httpx.ConnectTimeout | httpx.ConnectError):
        return DockhandError(
            None, "dockhand_unreachable", f"DockHand is unreachable ({type(exc).__name__})"
        )
    if isinstance(exc, httpx.TimeoutException):
        # A pool timeout never got a connection, so nothing was sent.
        return DockhandError(
            None,
            "timeout",
            f"DockHand did not answer in time ({type(exc).__name__})",
            sent=not isinstance(exc, httpx.PoolTimeout),
        )
    return DockhandError(
        None, "dockhand_unreachable", f"DockHand request failed ({type(exc).__name__})", sent=True
    )
