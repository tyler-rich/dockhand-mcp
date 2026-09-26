# SPDX-License-Identifier: Apache-2.0
"""Detached-operation registry and `dockhand_get_operation` (ARCHITECTURE §4.3, SECURITY §2)."""

import functools
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
import anyio.lowlevel
import pytest
from conftest import DOCKHAND_URL, SetEnv

from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.operations import (
    OperationRegistry,
    OperationUnknownError,
    RegistryFullError,
)
from dockhand_mcp.config import load_settings
from dockhand_mcp.tools.base import ToolContext
from dockhand_mcp.tools.operations import GetOperationInput, get_operation
from dockhand_mcp.tools.registry import Profile

ALICE = Principal("alice", Profile.OPERATOR)
MALLORY = Principal("mallory", Profile.OPERATOR)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def registry(clock: FakeClock) -> OperationRegistry:
    return OperationRegistry(max_entries=3, ttl_s=3600, clock=clock)


def running(test: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
    """Run an async test inside its `registry` fixture's task group (entered in the test's task)."""

    @functools.wraps(test)
    async def wrapper(registry: OperationRegistry, *args: Any, **kwargs: Any) -> None:
        async with registry.running():
            await test(registry, *args, **kwargs)

    return wrapper


async def value(v: Any) -> Any:
    return v


async def fail() -> Any:
    raise DockhandError(500, "dockhand_http_error", "DockHand failed (HTTP 500)")


async def settle() -> None:
    for _ in range(5):
        await anyio.lowlevel.checkpoint()


@running
async def test_start_returns_a_uuid4_and_completes(registry: OperationRegistry) -> None:
    op_id = registry.start(value({"success": True}), "detached", {"container": "web"}, ALICE)
    assert uuid.UUID(op_id).version == 4
    await settle()
    op = registry.get(op_id, ALICE)
    assert op.status == "completed"
    assert op.result == {"success": True}
    assert op.meta == {"container": "web"}
    assert op.kind == "detached"


@running
async def test_running_then_completed(registry: OperationRegistry) -> None:
    gate = anyio.Event()

    async def slow() -> str:
        await gate.wait()
        return "done"

    op_id = registry.start(slow(), "detached", {}, ALICE)
    await settle()
    assert registry.get(op_id, ALICE).status == "running"
    gate.set()
    await settle()
    assert registry.get(op_id, ALICE).status == "completed"


@running
async def test_failure_is_recorded(registry: OperationRegistry) -> None:
    op_id = registry.start(fail(), "detached", {}, ALICE)
    await settle()
    op = registry.get(op_id, ALICE)
    assert op.status == "failed"
    assert op.error is not None
    assert op.error.code == "dockhand_http_error"
    assert op.error.dockhand_status == 500


@running
async def test_other_principal_gets_unknown(registry: OperationRegistry) -> None:
    op_id = registry.start(value(1), "detached", {}, ALICE)
    await settle()
    with pytest.raises(OperationUnknownError):
        registry.get(op_id, MALLORY)
    with pytest.raises(OperationUnknownError):
        registry.get(str(uuid.uuid4()), ALICE)


@running
async def test_completed_entries_expire_after_ttl(
    registry: OperationRegistry, clock: FakeClock
) -> None:
    op_id = registry.start(value(1), "detached", {}, ALICE)
    await settle()
    clock.now += 3599
    registry.get(op_id, ALICE)
    clock.now += 2
    with pytest.raises(OperationUnknownError):
        registry.get(op_id, ALICE)


@running
async def test_evicts_oldest_completed_never_running(
    registry: OperationRegistry, clock: FakeClock
) -> None:
    gate = anyio.Event()

    async def blocked() -> None:
        await gate.wait()

    running = registry.start(blocked(), "detached", {}, ALICE)
    clock.now += 1
    old = registry.start(value("old"), "detached", {}, ALICE)
    clock.now += 1
    newer = registry.start(value("newer"), "detached", {}, ALICE)
    await settle()
    clock.now += 1
    newest = registry.start(value("newest"), "detached", {}, ALICE)
    await settle()
    assert len(registry) == 3
    with pytest.raises(OperationUnknownError):
        registry.get(old, ALICE)
    for op_id in (running, newer, newest):
        registry.get(op_id, ALICE)
    gate.set()


@running
async def test_full_of_running_operations_refuses(registry: OperationRegistry) -> None:
    gate = anyio.Event()

    async def blocked() -> None:
        await gate.wait()

    for _ in range(3):
        registry.start(blocked(), "detached", {}, ALICE)
    coro = blocked()
    with pytest.raises(RegistryFullError):
        registry.start(coro, "detached", {}, ALICE)
    gate.set()


@running
async def test_wait_returns_on_completion_or_budget(registry: OperationRegistry) -> None:
    gate = anyio.Event()

    async def slow() -> str:
        await gate.wait()
        return "done"

    op_id = registry.start(slow(), "detached", {}, ALICE)
    progress: list[str] = []

    async def on_progress(message: str, elapsed: float) -> None:
        progress.append(message)

    op, timed_out = await registry.wait(op_id, ALICE, 0.3, on_progress=on_progress, interval_s=0.1)
    assert timed_out is True
    assert op.status == "running"
    assert progress
    assert all(op_id in m for m in progress)
    gate.set()
    op, timed_out = await registry.wait(op_id, ALICE, 5)
    assert (op.status, timed_out) == ("completed", False)


@running
async def test_wait_for_another_principals_operation_is_unknown(
    registry: OperationRegistry,
) -> None:
    op_id = registry.start(value(1), "detached", {}, ALICE)
    with pytest.raises(OperationUnknownError):
        await registry.wait(op_id, MALLORY, 1)


async def test_shutdown_cancels_running_operations() -> None:
    reg = OperationRegistry()
    cancelled = anyio.Event()

    async def forever() -> None:
        try:
            await anyio.sleep_forever()
        finally:
            cancelled.set()

    async with reg.running():
        reg.start(forever(), "detached", {}, ALICE)
        await settle()
        await reg.shutdown()
    assert cancelled.is_set()


# --- dockhand_get_operation -------------------------------------------------------------------


def context(principal: Principal, registry: OperationRegistry, base_env: SetEnv) -> ToolContext:
    base_env()
    settings = load_settings()

    async def progress(message: str) -> None:
        pass

    return ToolContext(
        principal=principal,
        client=DockhandClient(DOCKHAND_URL),
        operations=registry,
        settings=settings,
        progress=progress,
    )


@running
async def test_tool_reports_the_operation(registry: OperationRegistry, base_env: SetEnv) -> None:
    op_id = registry.start(value({"success": True}), "detached", {"container": "web"}, ALICE)
    await settle()
    env = await get_operation(context(ALICE, registry, base_env), GetOperationInput(op_id=op_id))
    assert env.ok is True
    assert env.operation is not None
    assert (env.operation.kind, env.operation.id, env.operation.status) == (
        "detached",
        op_id,
        "completed",
    )
    assert env.operation.timed_out is False
    assert env.data["result"] == {"success": True}


@running
async def test_tool_hides_other_principals_operations(
    registry: OperationRegistry, base_env: SetEnv
) -> None:
    op_id = registry.start(value(1), "detached", {}, ALICE)
    await settle()
    env = await get_operation(context(MALLORY, registry, base_env), GetOperationInput(op_id=op_id))
    unknown = await get_operation(
        context(MALLORY, registry, base_env), GetOperationInput(op_id=str(uuid.uuid4()))
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_unknown"
    assert unknown.error is not None
    assert env.error.message == unknown.error.message  # no oracle for other principals' ids


@running
async def test_tool_reports_failed_operations_as_errors(
    registry: OperationRegistry, base_env: SetEnv
) -> None:
    op_id = registry.start(fail(), "detached", {}, ALICE)
    await settle()
    env = await get_operation(context(ALICE, registry, base_env), GetOperationInput(op_id=op_id))
    assert env.ok is False
    assert env.error is not None
    assert (env.error.code, env.error.dockhand_status) == ("dockhand_http_error", 500)
    assert env.operation is not None
    assert env.operation.status == "failed"


@pytest.mark.parametrize(
    "bad", ["", "not-a-uuid", "7F1C1C2E-8F5A-4D7E-9A57-0D6F9B1F2A10x", "a" * 100]
)
def test_tool_input_is_validated(bad: str) -> None:
    with pytest.raises(ValueError):
        GetOperationInput(op_id=bad)
    with pytest.raises(ValueError):
        GetOperationInput.model_validate({"op_id": str(uuid.uuid4()), "extra": 1})
