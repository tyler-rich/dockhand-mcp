# SPDX-License-Identifier: Apache-2.0
"""HTTP application: `/healthz` plus the MCP endpoint behind the request pipeline.

The MCP endpoint's pipeline runs in ARCHITECTURE §3 order, each stage answering before the next
one runs:

1. body cap, 1 MiB -> 413
2. global rate limit per client IP -> 429
3. Host/Origin allow-list (the SDK's own check, run before auth) -> 421/403
4. bearer auth -> 401, or 429 while the IP is blocked for repeated failures
5. protocol-header checks the SDK does not do itself -> 400
6. the SDK's Streamable HTTP transport, stateless: 2026-07-28 per-request exchanges, plus the
   handshake-era revisions up to 2025-11-25 through its stateless legacy transport

`/healthz` sits outside all of it.
"""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Final

import httpx
from mcp.server.transport_security import (
    RequestBodyLimitMiddleware,
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from dockhand_mcp.auth.bearer import (
    BearerAuthenticator,
    BearerAuthMiddleware,
    StaticPrincipalMiddleware,
)
from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import Recorder
from dockhand_mcp.config import Settings
from dockhand_mcp.server import build_server
from dockhand_mcp.tools.registry import REGISTRY, ToolRegistry
from dockhand_mcp.transport.protocol import ProtocolCheckMiddleware
from dockhand_mcp.transport.ratelimit import (
    AuthFailureLimiter,
    RateLimitMiddleware,
    TokenBucketLimiter,
)

MAX_REQUEST_BODY_BYTES: Final = 1024 * 1024  # S-03
HEALTHZ_BODY: Final = b'{"status":"ok"}'
LOCAL_PRINCIPAL: Final = "local"


class StartupError(Exception):
    """The configuration is valid but this build cannot serve it."""


def transport_security(settings: Settings) -> TransportSecuritySettings:
    """Host/Origin allow-lists for DNS-rebinding protection (S-02).

    A configured host without a port matches that host on any port.
    """
    hosts: list[str] = []
    for host in settings.allowed_hosts:
        bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
        has_port = bracketed.rsplit("]", 1)[-1].count(":") == 1
        hosts.extend([bracketed] if has_port else [bracketed, f"{bracketed}:*"])
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=list(settings.allowed_origins),
    )


class HostOriginMiddleware:
    """The SDK's Host/Origin validation, run before authentication (ARCHITECTURE §3 step 3)."""

    def __init__(self, app: ASGIApp, settings: TransportSecuritySettings) -> None:
        self.app = app
        self.security = TransportSecurityMiddleware(settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            # Headers only; the SDK checks Content-Type itself where it applies.
            rejection = await self.security.validate_request(Request(scope), is_post=False)
            if rejection is not None:
                await rejection(scope, receive, send)
                return
        await self.app(scope, receive, send)


async def healthz(request: Request) -> Response:
    return Response(HEALTHZ_BODY, media_type="application/json")


def create_app(
    settings: Settings,
    *,
    registry: ToolRegistry = REGISTRY,
    dockhand_transport: httpx.AsyncBaseTransport | None = None,
    dockhand_recorder: Recorder | None = None,
) -> Starlette:
    if settings.auth_mode == "oauth":
        raise StartupError("oauth auth not implemented until Phase 5")

    security = transport_security(settings)
    server = build_server(
        settings,
        registry=registry,
        dockhand_transport=dockhand_transport,
        dockhand_recorder=dockhand_recorder,
    )
    sdk_app = server.streamable_http_app(
        streamable_http_path=settings.path,
        stateless_http=True,
        max_request_body_size=MAX_REQUEST_BODY_BYTES,
        transport_security=security,
        host=settings.bind,
    )

    authenticate: Callable[[ASGIApp], ASGIApp]
    if settings.auth_mode == "bearer":
        authenticator = BearerAuthenticator.from_settings(settings)
        failures = AuthFailureLimiter()

        def authenticate(app: ASGIApp) -> ASGIApp:
            return BearerAuthMiddleware(app, authenticator, failures)

    else:  # "none": validated at startup to be loopback-only with explicit opt-in
        principal = Principal(LOCAL_PRINCIPAL, settings.profile)

        def authenticate(app: ASGIApp) -> ASGIApp:
            return StaticPrincipalMiddleware(app, principal)

    pipeline: ASGIApp = ProtocolCheckMiddleware(sdk_app)
    pipeline = authenticate(pipeline)
    pipeline = HostOriginMiddleware(pipeline, security)
    pipeline = RateLimitMiddleware(
        pipeline, TokenBucketLimiter(settings.rate_limit_per_min), trust_proxy=settings.trust_proxy
    )
    pipeline = RequestBodyLimitMiddleware(pipeline, MAX_REQUEST_BODY_BYTES)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        # Runs the SDK session manager and, inside it, the server lifespan (DockHand client and
        # operation registry).
        async with sdk_app.router.lifespan_context(sdk_app):
            yield

    return Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route(settings.path, endpoint=pipeline),
        ],
        lifespan=lifespan,
    )
