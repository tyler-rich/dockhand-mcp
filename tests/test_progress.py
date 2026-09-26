# SPDX-License-Identifier: Apache-2.0
"""Progress notifications and cancellation on both served revisions (F-14, ARCHITECTURE §7).

Uses a private registry with test-only tools; nothing here is registered in the real server.
"""

import logging

import anyio
import pytest
import respx
from conftest import DOCKHAND_URL, MODERN, SetEnv, mcp_client
from pydantic import BaseModel, ConfigDict

from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.client.operations import OperationRegistry
from dockhand_mcp.config import load_settings
from dockhand_mcp.server import ServerState, ToolDispatcher
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import NO_ENDPOINTS, Profile, Tier, ToolRegistry
from dockhand_mcp.transport.app import create_app


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def two_phases(ctx: ToolContext, args: BaseModel) -> Envelope:
    await ctx.progress("phase one")
    await ctx.progress("phase two")
    return ok({"done": True})


async def forever(ctx: ToolContext, args: BaseModel) -> Envelope:
    await ctx.progress("waiting")
    await anyio.sleep_forever()
    raise AssertionError("unreachable")


def spec(name: str, handler: object) -> ToolSpec:
    return ToolSpec(
        name=name,
        title="Test tool",
        description="Test only.",
        input_model=NoArgs,
        handler=handler,  # type: ignore[arg-type]
        annotations=READ_ANNOTATIONS,
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(spec("dockhand_test_phases", two_phases), Tier.READ, NO_ENDPOINTS)
    reg.register(spec("dockhand_test_forever", forever), Tier.READ, NO_ENDPOINTS)
    return reg


@pytest.mark.parametrize("mode", [MODERN, "legacy"])
async def test_progress_reaches_the_client(
    base_env: SetEnv, registry: ToolRegistry, mode: str
) -> None:
    base_env()
    messages: list[str | None] = []
    progress: list[float] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        progress.append(value)
        messages.append(message)

    app = create_app(load_settings(), registry=registry)
    async with mcp_client(app, mode) as c:
        result = await c.call_tool("dockhand_test_phases", {}, progress_callback=on_progress)
    assert result.is_error is False
    assert messages == ["phase one", "phase two"]
    assert progress == sorted(progress) and len(set(progress)) == 2


async def test_no_progress_token_means_no_notifications(
    base_env: SetEnv, registry: ToolRegistry
) -> None:
    base_env()
    app = create_app(load_settings(), registry=registry)
    async with mcp_client(app) as c:
        result = await c.call_tool("dockhand_test_phases", {})
    assert result.is_error is False


async def test_cancellation_stops_the_wait_and_is_audited(
    base_env: SetEnv,
    registry: ToolRegistry,
    dockhand: respx.MockRouter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    base_env()
    settings = load_settings()
    dispatcher = ToolDispatcher(registry.tools_for_profile(Profile.READ_ONLY))
    state = ServerState(
        settings=settings, client=DockhandClient(DOCKHAND_URL), operations=OperationRegistry()
    )
    reported: list[str] = []

    async def report(message: str) -> None:
        reported.append(message)

    principal = Principal("default", Profile.READ_ONLY)
    with caplog.at_level(logging.INFO, logger="dockhand_mcp.audit"), anyio.fail_after(5):
        with anyio.move_on_after(0.2):
            await dispatcher.call(state, principal, "dockhand_test_forever", {}, report)
    assert reported == ["waiting"]
    audit = [r.__dict__ for r in caplog.records if r.name == "dockhand_mcp.audit"]
    assert [a["outcome"] for a in audit] == ["cancelled"]
    assert not dockhand.calls  # stopping our wait never touches DockHand
