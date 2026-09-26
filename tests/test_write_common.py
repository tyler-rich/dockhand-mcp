# SPDX-License-Identifier: Apache-2.0
"""Write helpers in tools/_common.py: timeout budget, placeholder guard, read-back verification,
and the three async patterns (ARCHITECTURE §4) run through S1's poller, consumer and registry.

DockHand job bodies and event streams here are invented from the spec's 200 descriptions.
"""

import functools
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import anyio
import httpx
import pytest
import respx
from conftest import DOCKHAND_TOKEN, DOCKHAND_URL, SetEnv

from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.operations import OperationRegistry
from dockhand_mcp.config import load_settings
from dockhand_mcp.guardrails.secrets import MASKED, REDACTED
from dockhand_mcp.tools._common import (
    SseRequest,
    WriteInputs,
    diff_summary,
    read_back_verify,
    refuse_placeholders,
    run_async_pattern,
    write_budget,
)
from dockhand_mcp.tools.base import ToolContext
from dockhand_mcp.tools.operations import GetOperationInput, get_operation
from dockhand_mcp.tools.registry import Profile

ALICE = Principal("alice", Profile.OPERATOR)
MALLORY = Principal("mallory", Profile.OPERATOR)
JOB = "0f8e7d6c-5b4a-4c3d-9e2f-1a0b9c8d7e6f"
SSE = {"content-type": "text/event-stream"}


def frames(*events: tuple[str, str]) -> bytes:
    return b"".join(f"event: {e}\ndata: {d}\n\n".encode() for e, d in events)


def context(principal: Principal, registry: OperationRegistry) -> ToolContext:
    async def progress(message: str) -> None:
        pass

    return ToolContext(
        principal=principal,
        client=DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN),
        operations=registry,
        settings=load_settings(),
        progress=progress,
    )


@pytest.fixture
def registry(base_env: SetEnv) -> OperationRegistry:
    base_env()
    return OperationRegistry(max_entries=2)


def running(test: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
    """Run an async test inside its `registry` fixture's task group (entered in the test's task)."""

    @functools.wraps(test)
    async def wrapper(registry: OperationRegistry, *args: Any, **kwargs: Any) -> None:
        async with registry.running():
            await test(registry, *args, **kwargs)

    return wrapper


async def finished(ctx: ToolContext, op_id: str) -> Envelope:
    for _ in range(200):
        env = await get_operation(ctx, GetOperationInput(op_id=op_id))
        if env.operation is None or env.operation.status != "running":
            return env
        await anyio.sleep(0.01)
    raise AssertionError("operation did not finish")


# --- budget and placeholders ------------------------------------------------------------------


def test_write_budget(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_DEFAULT_TIMEOUT="45", DOCKHAND_MCP_MAX_TIMEOUT="120")
    ctx = context(ALICE, OperationRegistry())
    assert write_budget(ctx, WriteInputs()) == (45.0, [])
    assert write_budget(ctx, WriteInputs(timeout_seconds=10)) == (10.0, [])
    budget, warnings = write_budget(ctx, WriteInputs(timeout_seconds=300))
    assert budget == 120.0
    assert warnings == ["timeout_seconds lowered to the server's maximum of 120"]
    with pytest.raises(ValueError):
        WriteInputs(timeout_seconds=301)


@pytest.mark.parametrize("marker", [REDACTED, MASKED])
def test_placeholders_are_refused(marker: str) -> None:
    with pytest.raises(DockhandError) as caught:
        refuse_placeholders({"content": f"KEY={marker}\n", "other": None})
    assert caught.value.code == "guardrail_blocked"
    assert "content" in caught.value.message
    assert repr(marker) in caught.value.message
    assert "dockhand_modify_stack_env" in caught.value.message


def test_clean_content_passes_the_placeholder_guard() -> None:
    refuse_placeholders({"content": "KEY=value\n# * one star is fine\n", "none": None})


# --- read-back --------------------------------------------------------------------------------


async def test_read_back_equal_is_verified() -> None:
    async def fetch() -> str:
        return "a\nb\n"

    assert await read_back_verify("a\nb\n", fetch) == (True, None)


async def test_read_back_mismatch_reports_counts_and_lines_only() -> None:
    old = "services:\n  web:\n    image: nginx:1.26\n"
    new = "services:\n  web:\n    image: nginx:1.27\n    restart: always\n"

    async def fetch() -> str:
        return old

    verified, diff = await read_back_verify(new, fetch)
    assert verified is False
    assert diff == {
        "expected_lines": 4,
        "actual_lines": 3,
        "expected_bytes": len(new),
        "actual_bytes": len(old),
        "first_differing_lines": [3, 4],
    }
    assert "nginx" not in json.dumps(diff)


def test_diff_summary_caps_line_numbers() -> None:
    assert diff_summary("a\nb\nc\nd\ne\n", "1\n2\n3\n4\n5\n")["first_differing_lines"] == [
        1,
        2,
        3,
    ]
    assert diff_summary("x\n", "x")["first_differing_lines"] == []


# --- job-poll ---------------------------------------------------------------------------------


def job_start(ctx: ToolContext) -> Any:
    async def start() -> Any:
        return await ctx.client.post_json("/api/stacks/{name}/start", path_params={"name": "s"})

    return start


@running
async def test_job_not_waiting_returns_the_job_id(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"jobId": JOB})
    ctx = context(ALICE, registry)
    env = await run_async_pattern("job", ctx, wait=False, budget_s=5, meta={}, start=job_start(ctx))
    assert env.ok is True
    assert env.operation is not None
    assert (env.operation.kind, env.operation.id, env.operation.timed_out) == ("job", JOB, False)


@running
async def test_job_completes(registry: OperationRegistry, dockhand: respx.MockRouter) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(
        200,
        json={
            "id": JOB,
            "status": "completed",
            "lines": [{"event": "progress", "data": {"line": "Started"}}],
            "result": {"success": True, "output": "done"},
        },
    )
    ctx = context(ALICE, registry)
    env = await run_async_pattern("job", ctx, wait=True, budget_s=5, meta={}, start=job_start(ctx))
    assert env.ok is True
    assert env.data["result"] == {"success": True, "output": "done"}
    assert env.data["progress"] == ['progress: {"line": "Started"}']
    assert env.operation is not None
    assert (env.operation.status, env.operation.timed_out) == ("completed", False)


@pytest.mark.parametrize(
    ("status", "result"),
    [("failed", {"success": False}), ("completed", {"success": False, "error": "x"})],
)
@running
async def test_job_failure_is_an_error(
    registry: OperationRegistry, dockhand: respx.MockRouter, status: str, result: Any
) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(
        200, json={"id": JOB, "status": status, "lines": [], "result": result}
    )
    ctx = context(ALICE, registry)
    env = await run_async_pattern("job", ctx, wait=True, budget_s=5, meta={}, start=job_start(ctx))
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"


@running
async def test_job_timeout_returns_the_id(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(
        200,
        json={"id": JOB, "status": "running", "lines": [{"event": "progress", "data": {"n": 1}}]},
    )
    ctx = context(ALICE, registry)
    env = await run_async_pattern(
        "job", ctx, wait=True, budget_s=0.05, meta={}, start=job_start(ctx)
    )
    assert env.ok is True
    assert env.operation is not None
    assert (env.operation.id, env.operation.status, env.operation.timed_out) == (
        JOB,
        "running",
        True,
    )
    assert env.data == {"job_id": JOB, "progress": ['progress: {"n": 1}']}


@running
async def test_job_answered_synchronously(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"success": True, "output": "up"})
    ctx = context(ALICE, registry)
    env = await run_async_pattern("job", ctx, wait=True, budget_s=5, meta={}, start=job_start(ctx))
    assert env.ok is True
    assert env.data["result"] == {"success": True, "output": "up"}


# --- SSE --------------------------------------------------------------------------------------


class HangingStream(httpx.AsyncByteStream):
    """Two progress events, then silence until the reader gives up."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield frames(("progress", '{"layer":"a","status":"Downloading"}'))
        yield frames(("progress", '{"layer":"a","status":"Extracting"}'))
        await anyio.sleep(3600)
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        pass


PULL = SseRequest("POST", "/api/images/pull", json={"image": "nginx:1.27"})


@running
async def test_sse_result(registry: OperationRegistry, dockhand: respx.MockRouter) -> None:
    body = frames(("progress", '{"n":1}'), ("result", '{"success":true,"image":"nginx:1.27"}'))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    env = await run_async_pattern(
        "sse", context(ALICE, registry), wait=True, budget_s=5, meta={}, sse=PULL
    )
    assert env.ok is True
    assert env.data == {
        "result": {"success": True, "image": "nginx:1.27"},
        "progress": ['progress: {"n":1}'],
    }
    assert env.operation is not None
    assert (env.operation.kind, env.operation.timed_out) == ("sse", False)


@running
async def test_sse_error_event_is_an_error(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    body = frames(("progress", "{}"), ("error", '{"message":"denied"}'))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    env = await run_async_pattern(
        "sse", context(ALICE, registry), wait=True, budget_s=5, meta={}, sse=PULL
    )
    assert env.ok is False
    assert env.data["error"] == {"message": "denied"}


@running
async def test_sse_timeout_keeps_the_last_progress_lines(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/images/pull").respond(200, stream=HangingStream(), headers=SSE)
    ctx = context(ALICE, registry)
    env = await run_async_pattern("sse", ctx, wait=True, budget_s=0.3, meta={}, sse=PULL)
    assert env.ok is True
    assert env.operation is not None
    assert env.operation.timed_out is True
    assert env.operation.kind == "sse"
    assert env.data["progress"] == [
        'progress: {"layer":"a","status":"Downloading"}',
        'progress: {"layer":"a","status":"Extracting"}',
    ]
    assert env.data["op_id"] == env.operation.id


@running
async def test_sse_answered_with_a_job_is_polled(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    # Live DockHand 1.0.46 answers its streaming endpoints with a job id; the job's lines are the
    # stream's events and its status ends as `done`.
    dockhand.post("/api/images/pull").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(
        200,
        json={
            "id": JOB,
            "status": "done",
            "lines": [
                {"event": "progress", "data": {"status": "Deploying stack..."}},
                {"event": "result", "data": {"success": True, "output": "up"}},
            ],
            "result": {"success": True, "output": "up"},
        },
    )
    env = await run_async_pattern(
        "sse", context(ALICE, registry), wait=True, budget_s=5, meta={}, sse=PULL
    )
    assert env.ok is True, env.error
    assert env.data == {
        "job_id": JOB,
        "result": {"success": True, "output": "up"},
        "progress": [
            'progress: {"status": "Deploying stack..."}',
            'result: {"success": true, "output": "up"}',
        ],
    }


@running
async def test_sse_job_reporting_failure_is_an_error(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/images/pull").respond(200, json={"jobId": JOB})
    dockhand.get(f"/api/jobs/{JOB}").respond(
        200,
        json={"id": JOB, "status": "done", "lines": [], "result": {"success": False, "error": "x"}},
    )
    env = await run_async_pattern(
        "sse", context(ALICE, registry), wait=True, budget_s=5, meta={}, sse=PULL
    )
    assert env.ok is False
    assert env.data["job_id"] == JOB


@running
async def test_job_done_is_terminal(
    registry: OperationRegistry, dockhand: respx.MockRouter
) -> None:
    dockhand.post("/api/stacks/s/start").respond(200, json={"jobId": JOB})
    route = dockhand.get(f"/api/jobs/{JOB}").respond(
        200, json={"id": JOB, "status": "done", "lines": [], "result": {"success": True}}
    )
    ctx = context(ALICE, registry)
    env = await run_async_pattern("job", ctx, wait=True, budget_s=30, meta={}, start=job_start(ctx))
    assert env.ok is True
    assert route.call_count == 1
    assert env.operation is not None
    assert (env.operation.status, env.operation.timed_out) == ("done", False)


# --- detached ---------------------------------------------------------------------------------


@running
async def test_detached_op_is_retrievable_by_its_principal_only(
    registry: OperationRegistry,
) -> None:
    async def work() -> Envelope:
        return ok({"saved": True}, verified=True)

    alice = context(ALICE, registry)
    env = await run_async_pattern("detached", alice, wait=False, budget_s=5, meta={}, work=work)
    assert env.operation is not None
    op_id = env.operation.id
    assert env.data == {"op_id": op_id}
    assert env.warnings and "lost if the server restarts" in env.warnings[0]
    later = await finished(alice, op_id)
    assert later.ok is True
    assert later.verified is True
    assert later.data["result"] == {"saved": True}
    other = await get_operation(context(MALLORY, registry), GetOperationInput(op_id=op_id))
    assert other.ok is False
    assert other.error is not None
    assert other.error.code == "operation_unknown"


@running
async def test_detached_wait_returns_the_result(registry: OperationRegistry) -> None:
    async def work() -> dict[str, str]:
        return {"state": "running"}

    env = await run_async_pattern(
        "detached", context(ALICE, registry), wait=True, budget_s=5, meta={}, work=work
    )
    assert env.ok is True
    assert env.data == {"state": "running"}
    assert env.operation is not None
    assert (env.operation.kind, env.operation.status) == ("detached", "completed")


@running
async def test_detached_wait_timeout_returns_the_op_id(registry: OperationRegistry) -> None:
    gate = anyio.Event()

    async def work() -> dict[str, str]:
        await gate.wait()
        return {"done": "yes"}

    ctx = context(ALICE, registry)
    env = await run_async_pattern("detached", ctx, wait=True, budget_s=0.05, meta={}, work=work)
    assert env.operation is not None
    assert env.operation.timed_out is True
    gate.set()
    assert (await finished(ctx, env.operation.id)).data["result"] == {"done": "yes"}


@running
async def test_detached_failure_is_an_error(registry: OperationRegistry) -> None:
    async def work() -> None:
        raise DockhandError(500, "dockhand_http_error", "DockHand server error (HTTP 500)")

    env = await run_async_pattern(
        "detached", context(ALICE, registry), wait=True, budget_s=5, meta={}, work=work
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.dockhand_status == 500


@running
async def test_full_registry_is_not_available(registry: OperationRegistry) -> None:
    gate = anyio.Event()

    async def work() -> None:
        await gate.wait()

    ctx = context(ALICE, registry)
    for _ in range(2):
        await run_async_pattern("detached", ctx, wait=False, budget_s=1, meta={}, work=work)
    env = await run_async_pattern("detached", ctx, wait=False, budget_s=1, meta={}, work=work)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "not_available"
    gate.set()
