# SPDX-License-Identifier: Apache-2.0
"""In-memory registry of detached operations (ARCHITECTURE §4.3).

For DockHand endpoints that block until done: the tool starts the call here and returns an
`op_id` (uuid4) the client can check later. Operations belong to the principal that started
them; anyone else gets `OperationUnknownError`, exactly as for an id that never existed. At most
`max_entries` are kept: finished ones expire `ttl_s` after finishing, and when full the oldest
finished one is evicted. Running operations are never evicted; if all slots are running,
`start` refuses. Everything is lost on restart.
"""

import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal

import anyio
from anyio.abc import TaskGroup

from dockhand_mcp.client.envelope import ErrorInfo, error_info
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.jobs import ProgressCallback

if TYPE_CHECKING:
    from dockhand_mcp.auth.principal import Principal

log = logging.getLogger(__name__)

DEFAULT_TTL_S: Final = 3600.0
DEFAULT_MAX_ENTRIES: Final = 100

OperationStatus = Literal["running", "completed", "failed", "cancelled"]


class OperationUnknownError(Exception):
    """No such operation for this principal (never distinguishes 'other owner' from 'absent')."""


class RegistryFullError(Exception):
    """Every slot holds a running operation."""


@dataclass
class Operation:
    id: str
    kind: str
    meta: dict[str, Any]
    principal: Principal
    created_at: float
    status: OperationStatus = "running"
    finished_at: float | None = None
    result: Any = None
    error: ErrorInfo | None = None
    done: anyio.Event = field(default_factory=anyio.Event, repr=False)

    def elapsed(self, now: float) -> float:
        return (self.finished_at if self.finished_at is not None else now) - self.created_at


class OperationRegistry:
    def __init__(
        self,
        *,
        ttl_s: float = DEFAULT_TTL_S,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_s
        self._max = max_entries
        self._clock = clock
        self._ops: dict[str, Operation] = {}
        self._tg: TaskGroup | None = None

    @asynccontextmanager
    async def running(self) -> AsyncIterator[OperationRegistry]:
        """Own the task group operations run in; leaving it cancels what is still running."""
        async with anyio.create_task_group() as tg:
            self._tg = tg
            try:
                yield self
            finally:
                self._tg = None
                tg.cancel_scope.cancel()

    async def shutdown(self) -> None:
        if self._tg is not None:
            self._tg.cancel_scope.cancel()

    def __len__(self) -> int:
        return len(self._ops)

    def _purge(self) -> None:
        now = self._clock()
        expired = [
            op.id
            for op in self._ops.values()
            if op.finished_at is not None and now - op.finished_at >= self._ttl
        ]
        for op_id in expired:
            del self._ops[op_id]

    def start(
        self,
        coro: Coroutine[Any, Any, Any],
        kind: str,
        meta: Mapping[str, Any],
        principal: Principal,
    ) -> str:
        """Run `coro` detached and return its op_id. `meta` must hold IDs and names only."""
        if self._tg is None:
            coro.close()
            raise RuntimeError("the operation registry is not running")
        self._purge()
        if len(self._ops) >= self._max:
            finished = [op for op in self._ops.values() if op.status != "running"]
            if not finished:
                coro.close()
                raise RegistryFullError(f"{self._max} operations are already running")
            del self._ops[min(finished, key=lambda op: op.created_at).id]
        op = Operation(
            id=str(uuid.uuid4()),
            kind=kind,
            meta=dict(meta),
            principal=principal,
            created_at=self._clock(),
        )
        self._ops[op.id] = op
        self._tg.start_soon(self._run, op, coro)
        return op.id

    async def _run(self, op: Operation, coro: Coroutine[Any, Any, Any]) -> None:
        try:
            op.result = await coro
            op.status = "completed"
        except DockhandError as e:
            op.status = "failed"
            op.error = error_info(e)
        except anyio.get_cancelled_exc_class():
            op.status = "cancelled"
            raise
        except Exception as e:
            # A bug, not a DockHand answer. Keep the task group (and the server) alive.
            log.error(
                "detached_operation_failed", extra={"op_id": op.id, "exc_type": type(e).__name__}
            )
            op.status = "failed"
            op.error = ErrorInfo(
                code="dockhand_http_error",
                message=f"The operation failed with an internal error ({type(e).__name__}).",
            )
        finally:
            op.finished_at = self._clock()
            op.done.set()

    def elapsed(self, op: Operation) -> float:
        """Seconds the operation has run (so far, or in total once finished)."""
        return op.elapsed(self._clock())

    def get(self, op_id: str, principal: Principal) -> Operation:
        self._purge()
        op = self._ops.get(op_id)
        if op is None or op.principal != principal:
            raise OperationUnknownError(op_id)
        return op

    async def wait(
        self,
        op_id: str,
        principal: Principal,
        budget_s: float,
        *,
        on_progress: ProgressCallback | None = None,
        interval_s: float = 2.0,
    ) -> tuple[Operation, bool]:
        """Wait up to `budget_s` for the operation; returns it and whether the wait timed out.

        Waiting (or being cancelled while waiting) never affects the operation itself.
        """
        op = self.get(op_id, principal)
        deadline = time.monotonic() + budget_s
        started = time.monotonic()
        while not op.done.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return op, True
            if on_progress is not None:
                elapsed = time.monotonic() - started
                await on_progress(f"waiting for operation {op.id}: {elapsed:.0f}s elapsed", elapsed)
            with anyio.move_on_after(min(interval_s, remaining)):
                await op.done.wait()
        return op, False
