# SPDX-License-Identifier: Apache-2.0
"""The MCP server: tools only, dispatched from the profile's registered tools.

Built on the SDK's low-level `Server`, which derives its advertised capabilities from the request
handlers registered on it. Registering only `tools/list` and `tools/call` makes both the
2026-07-28 `server/discover` result and the 2025-11-25 `initialize` result advertise `tools`
alone, with `listChanged` false (ARCHITECTURE §7). `MCPServer` is not used because it always
registers resource, prompt and `subscriptions/listen` handlers. `ToolsOnlyServer` removes the one
remaining extra, an empty `experimental` object in the handshake-era `initialize` result.

A destructive tool may answer `tools/call` with an MCP 2026-07-28 `input_required` result (a
form-mode elicitation asking the human to approve, auth/approval.py). Elicitation is a client
capability read from each request's `_meta`; the server advertises nothing for it.
"""

import itertools
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import anyio
import httpx
from mcp import types
from mcp.server import InitializationOptions, NotificationOptions, Server, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, INVALID_PARAMS, InputRequiredResult
from pydantic import ValidationError

from dockhand_mcp import __version__
from dockhand_mcp.auth.approval import ApprovalContext, ApprovalState, ClientView
from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import (
    DockhandClient,
    Recorder,
    declared_endpoints,
    track_status,
)
from dockhand_mcp.client.envelope import Envelope, err, from_error, render
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.operations import OperationRegistry
from dockhand_mcp.client.redaction import PLAIN
from dockhand_mcp.guardrails.secrets import redact_sensitive_keys
from dockhand_mcp.logging import audit, log_context, truncate
from dockhand_mcp.tools._common import ApprovalRequired, DestructiveHandler
from dockhand_mcp.tools.base import ToolContext, ToolSpec
from dockhand_mcp.tools.registry import REGISTRY, RegisteredTool, Tier, ToolRegistry

if TYPE_CHECKING:
    from dockhand_mcp.config import Settings

log = logging.getLogger(__name__)

SERVER_NAME: Final = "dockhand-mcp"
MAX_PROGRESS_MESSAGE: Final = 200

Report = Callable[[str], Awaitable[None]]
# A request that says nothing about its client: no elicitation, no approval responses.
NO_CLIENT_VIEW: Final = ClientView(modern=False, form_elicitation=False)


@dataclass(frozen=True)
class ServerState:
    """Process-wide dependencies, created in the server lifespan."""

    settings: Settings
    client: DockhandClient
    operations: OperationRegistry
    # Challenge key, replay cache and destructive rate limit; None only in tests of other tiers.
    approval: ApprovalState | None = None


def _validation_message(e: ValidationError) -> str:
    parts = []
    for error in e.errors(include_url=False, include_input=False, include_context=False):
        loc = ".".join(str(p) for p in error["loc"]) or "arguments"
        parts.append(f"{loc}: {error['msg']}")
    return truncate("invalid arguments: " + "; ".join(parts))


def _audit_args(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: arguments[k]
        for k in spec.audit_args
        if isinstance(arguments.get(k), str | int | bool) and k in arguments
    }


class ToolDispatcher:
    """Validates, runs and audits tool calls for a fixed set of registered tools."""

    def __init__(self, tools: Sequence[RegisteredTool]) -> None:
        self._tools: dict[str, tuple[ToolSpec, frozenset[tuple[str, str]]]] = {}
        for entry in tools:
            if not isinstance(entry.tool, ToolSpec):
                raise TypeError(f"{entry.name}: registered tools must be ToolSpec instances")
            if entry.tier is Tier.DESTRUCTIVE and not (
                isinstance(entry.tool.handler, DestructiveHandler)
                and entry.tool.handler.tool == entry.name
                and entry.tool.annotations.destructive_hint is True
            ):
                # The approval gate is not optional (D-006): refuse to serve such a tool at all.
                raise TypeError(f"{entry.name}: a destructive tool must use run_destructive")
            self._tools[entry.name] = (entry.tool, frozenset(entry.endpoints))
        self._listing = [spec.to_mcp() for spec, _ in self._tools.values()]

    def list_tools(self) -> list[types.Tool]:
        return [tool.model_copy() for tool in self._listing]

    async def call(
        self,
        state: ServerState,
        principal: Principal,
        name: str,
        arguments: Mapping[str, Any] | None,
        report: Report,
        client: ClientView = NO_CLIENT_VIEW,
    ) -> types.CallToolResult | InputRequiredResult:
        found = self._tools.get(name)
        if found is None:
            # Same answer for a tool outside the profile as for one that never existed.
            raise MCPError(INVALID_PARAMS, f"Unknown tool: {truncate(name, 100)}")
        spec, endpoints = found
        args_in = arguments or {}
        started = time.monotonic()
        outcome = "internal_error"
        with (
            log_context(request_id=str(uuid.uuid4()), principal=principal.name, tool=name),
            track_status() as status,
        ):
            try:
                envelope = await self._run(
                    state, principal, spec, endpoints, args_in, report, client
                )
                if isinstance(envelope, InputRequiredResult):
                    outcome = "input_required"
                    return envelope
                outcome = "ok" if envelope.ok or envelope.error is None else envelope.error.code
                return render(envelope)
            except anyio.get_cancelled_exc_class():
                outcome = "cancelled"
                raise
            except Exception as e:
                log.error("tool_failed", extra={"exc_type": type(e).__name__})
                raise MCPError(INTERNAL_ERROR, "Internal error") from None
            finally:
                audit(
                    tool=name,
                    principal=principal.name,
                    args=_audit_args(spec, args_in),
                    outcome=outcome,
                    duration_ms=(time.monotonic() - started) * 1000,
                    dockhand_status=status.status,
                )

    async def _run(
        self,
        state: ServerState,
        principal: Principal,
        spec: ToolSpec,
        endpoints: frozenset[tuple[str, str]],
        arguments: Mapping[str, Any],
        report: Report,
        client: ClientView,
    ) -> Envelope | InputRequiredResult:
        try:
            args = spec.input_model.model_validate(arguments)
        except ValidationError as e:
            return err("validation_error", _validation_message(e))
        approval = (
            ApprovalContext(state=state.approval, principal=principal.name, client=client)
            if state.approval is not None
            else None
        )
        ctx = ToolContext(
            principal=principal,
            client=state.client,
            operations=state.operations,
            settings=state.settings,
            progress=report,
            approval=approval,
        )
        with declared_endpoints(endpoints):
            try:
                envelope = await spec.handler(ctx, args)
            except DockhandError as e:
                return from_error(e)
            except ApprovalRequired as e:
                return e.result
        if envelope.data is None:
            return envelope
        # Every tool's data passes the key-based secret redaction (guardrails/secrets.py), then
        # the string layers on DockHand's free text: messages, errors, status strings, output
        # (client/redaction.py; GET answers reach tools unredacted, and this covers them).
        data = PLAIN.free_text(redact_sensitive_keys(envelope.data))
        return envelope.model_copy(update={"data": data})


class ToolsOnlyServer(Server[ServerState]):
    """The SDK server minus the empty `experimental` object in the handshake-era `initialize`.

    `Server.create_initialization_options()` always passes `experimental={}`, which the
    2025-11-25 `initialize` result then carries. Dropping it makes both revisions advertise
    exactly `{"tools": {"listChanged": false}}`. Nothing else is changed.
    """

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        options = super().create_initialization_options(
            notification_options, experimental_capabilities, extensions
        )
        if options.capabilities.experimental:
            return options
        capabilities = options.capabilities.model_copy(update={"experimental": None})
        return options.model_copy(update={"capabilities": capabilities})


def _principal(ctx: ServerRequestContext[Any, Any], default: Principal | None) -> Principal:
    """The caller, as authenticated by the HTTP pipeline; `default` only where there is none."""
    request = ctx.request
    if request is None:
        if default is not None:
            return default  # stdio: the client is the parent process
    else:
        principal = getattr(getattr(request, "state", None), "principal", None)
        if isinstance(principal, Principal):
            return principal
    # Unreachable behind the auth middleware; fail closed if it ever is not.
    raise MCPError(INTERNAL_ERROR, "Internal error")


def build_server(
    settings: Settings,
    *,
    registry: ToolRegistry = REGISTRY,
    default_principal: Principal | None = None,
    dockhand_transport: httpx.AsyncBaseTransport | None = None,
    dockhand_recorder: Recorder | None = None,
) -> ToolsOnlyServer:
    """The SDK server exposing the profile's tools. `default_principal` is for stdio only."""
    dispatcher = ToolDispatcher(
        registry.tools_for_profile(settings.profile, frozenset(settings.disable_tools))
    )

    @asynccontextmanager
    async def lifespan(_: Server[ServerState]) -> AsyncIterator[ServerState]:
        client = DockhandClient.from_settings(
            settings, transport=dockhand_transport, recorder=dockhand_recorder
        )
        operations = OperationRegistry()
        try:
            async with operations.running():
                yield ServerState(
                    settings=settings,
                    client=client,
                    operations=operations,
                    approval=ApprovalState.from_settings(settings),
                )
        finally:
            await client.aclose()

    async def list_tools(
        ctx: ServerRequestContext[ServerState, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=dispatcher.list_tools())

    async def call_tool(
        ctx: ServerRequestContext[ServerState, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult | InputRequiredResult:
        principal = _principal(ctx, default_principal)
        # Capabilities come from this request's `_meta` on 2026-07-28; the SDK's stateless
        # handshake-era transport reports none.
        client = ClientView.from_request(
            ctx.protocol_version,
            ctx.session.client_capabilities,
            params.input_responses,
            params.request_state,
        )
        step = itertools.count(1)

        async def report(message: str) -> None:
            # A no-op unless the request carried a progress token.
            await ctx.session.report_progress(
                float(next(step)), None, truncate(message, MAX_PROGRESS_MESSAGE)
            )

        return await dispatcher.call(
            ctx.lifespan_context, principal, params.name, params.arguments, report, client
        )

    return ToolsOnlyServer(
        SERVER_NAME,
        version=__version__,
        lifespan=lifespan,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
