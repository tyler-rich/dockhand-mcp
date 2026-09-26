# SPDX-License-Identifier: Apache-2.0
"""Protocol-header integrity (S-12) for the requests the SDK does not check itself.

The SDK routes on `MCP-Protocol-Version`. For 2026-07-28 (and any unknown value) its modern
entry already rejects, with 400: an unsupported version, a version header that disagrees with
the body's `_meta`, a missing or mismatched `Mcp-Method`, a mismatched or missing `Mcp-Name` for
name-bearing methods, and duplicated routing headers. Requests with no version header or a
handshake-era version go to its legacy transport, which checks none of these headers. For those,
this middleware enforces the S-12 rule: `Mcp-Method` and `Mcp-Name`, when present, must match the
JSON-RPC body, and no routing header may appear twice. Mismatch is a 400 carrying a JSON-RPC
`HEADER_MISMATCH` error, the same shape the SDK uses on the modern path.
"""

import json
from collections import deque
from typing import Any, Final

from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    decode_header_value,
    find_duplicated_routing_header,
)
from mcp_types import HEADER_MISMATCH
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_ROUTING: Final = (MCP_METHOD_HEADER, MCP_NAME_HEADER)


def _mismatch(message: str, request_id: Any = None) -> Response:
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": HEADER_MISMATCH, "message": message},
    }
    return Response(
        json.dumps(body, separators=(",", ":")), status_code=400, media_type="application/json"
    )


def legacy_header_problem(headers: Headers, body: bytes) -> tuple[str, Any] | None:
    """Why a legacy-routed request's routing headers disagree with its body, or None."""
    raw = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers.raw]
    duplicated = find_duplicated_routing_header(raw)
    if duplicated is not None:
        return f"{duplicated} header appears more than once", None
    method_header = headers.get(MCP_METHOD_HEADER)
    name_header = headers.get(MCP_NAME_HEADER)
    if method_header is None and name_header is None:
        return None
    try:
        decoded = json.loads(body)
    except ValueError, RecursionError:
        return "routing headers present but the body is not a JSON-RPC message", None
    if not isinstance(decoded, dict):
        return "routing headers present but the body is not a single JSON-RPC message", None
    request_id = decoded.get("id")
    method = decoded.get("method")
    if method_header is not None and method_header != method:
        return f"{MCP_METHOD_HEADER} header does not match the request body's method", request_id
    if name_header is not None:
        name_key = NAME_BEARING_METHODS.get(method) if isinstance(method, str) else None
        params = decoded.get("params")
        value = params.get(name_key) if name_key and isinstance(params, dict) else None
        if value is None or decode_header_value(name_header) != value:
            return f"{MCP_NAME_HEADER} header does not match the request body", request_id
    return None


class ProtocolCheckMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        version = headers.get(MCP_PROTOCOL_VERSION_HEADER)
        if version is not None and version not in HANDSHAKE_PROTOCOL_VERSIONS:
            await self.app(scope, receive, send)  # modern entry: the SDK checks
            return

        # The body cap earlier in the pipeline already bounded and buffered the body.
        messages: deque[Message] = deque()
        body = bytearray()
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break

        problem = legacy_header_problem(headers, bytes(body))
        if problem is not None:
            await _mismatch(*problem)(scope, receive, send)
            return

        async def replay() -> Message:
            return messages.popleft() if messages else await receive()

        await self.app(scope, replay, send)
