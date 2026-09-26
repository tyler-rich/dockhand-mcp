# SPDX-License-Identifier: Apache-2.0
"""Static bearer-token authentication for the MCP endpoint (S-01, D-004).

The presented token is compared, as the raw bytes after `Bearer `, against every configured
token with `hmac.compare_digest`. Nothing is normalised first and there is no early exit, so
neither the length nor the content of a guess changes which comparisons run. The token is never
logged.
"""

import hmac
import json
from collections.abc import Iterable
from typing import TYPE_CHECKING, Final

from starlette.types import ASGIApp, Receive, Scope, Send

from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.tools.registry import Profile
from dockhand_mcp.transport.ratelimit import AuthFailureLimiter, scope_client_ip, too_many

if TYPE_CHECKING:
    from dockhand_mcp.config import Settings

PRINCIPAL_NAME: Final = "default"
REALM: Final = "dockhand-mcp"
_SCHEME: Final = b"bearer "


class BearerAuthenticator:
    def __init__(self, tokens: Iterable[str], profile: Profile) -> None:
        self._tokens = tuple(t.encode("utf-8") for t in tokens)
        if not self._tokens or not all(self._tokens):
            raise ValueError("at least one non-empty token is required")
        self._principal = Principal(PRINCIPAL_NAME, profile)

    @classmethod
    def from_settings(cls, settings: Settings) -> BearerAuthenticator:
        if settings.mcp_token is None:
            raise ValueError("bearer mode requires DOCKHAND_MCP_TOKEN")
        return cls([settings.mcp_token.get_secret_value()], settings.profile)

    def authenticate(self, authorization: bytes | None) -> Principal | None:
        """The principal for a raw `Authorization` header value, or None."""
        if authorization is None or authorization[: len(_SCHEME)].lower() != _SCHEME:
            return None
        presented = authorization[len(_SCHEME) :]
        if not presented:
            return None
        matched = False
        for token in self._tokens:
            matched |= hmac.compare_digest(presented, token)
        return self._principal if matched else None


def _authorization_header(scope: Scope) -> tuple[bytes | None, bool]:
    """The single `Authorization` header value, and whether any was sent."""
    values = [v for k, v in scope["headers"] if k == b"authorization"]
    if len(values) == 1:
        return values[0], True
    return None, bool(values)


_UNAUTHORIZED_BODY: Final = json.dumps({"error": "unauthorized"}, separators=(",", ":")).encode()


async def unauthorized(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_UNAUTHORIZED_BODY)).encode()),
                (b"www-authenticate", f'Bearer realm="{REALM}"'.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _UNAUTHORIZED_BODY})


def set_principal(scope: Scope, principal: Principal) -> None:
    """Attach the principal to the request; tools read it back from `request.state`."""
    scope["state"] = {**scope.get("state", {}), "principal": principal}


class BearerAuthMiddleware:
    """401 unless the request carries a configured token; 429 while its IP is blocked.

    Only wrong or malformed tokens count as failures: a request with no `Authorization` header
    is not a guess.
    """

    def __init__(
        self, app: ASGIApp, authenticator: BearerAuthenticator, failures: AuthFailureLimiter
    ) -> None:
        self.app = app
        self.authenticator = authenticator
        self.failures = failures

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = scope_client_ip(scope)
        retry_after = self.failures.blocked(ip)
        if retry_after is not None:
            await too_many(retry_after)(scope, receive, send)
            return
        header, sent = _authorization_header(scope)
        principal = self.authenticator.authenticate(header)
        if principal is None:
            if sent:
                self.failures.record_failure(ip)
            await unauthorized(send)
            return
        set_principal(scope, principal)
        await self.app(scope, receive, send)


class StaticPrincipalMiddleware:
    """`none` auth mode (loopback only, explicit opt-in): every request is the local principal."""

    def __init__(self, app: ASGIApp, principal: Principal) -> None:
        self.app = app
        self.principal = principal

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            set_principal(scope, self.principal)
        await self.app(scope, receive, send)
