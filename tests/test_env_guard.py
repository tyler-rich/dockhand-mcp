# SPDX-License-Identifier: Apache-2.0
"""The client refuses an env-required operation without its environment parameter (#5).

DockHand 1.0.49 requires `env` (`envId` on exec) on the container operations. Without it DockHand
answers some with a 500 and `GET /api/containers/stats` with `200 []`, which would read as "no
containers" (ARCHIVE §14, 1.0.49). The refusal happens in `client/dockhand.py`, before anything is
sent, so it holds for every tool and every request path.
"""

from contextlib import aclosing
from typing import Any

import pytest
import respx
from conftest import DOCKHAND_TOKEN, DOCKHAND_URL, ENV

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.errors import DockhandError

CID = "abc123"


@pytest.fixture
def calls() -> list[tuple[str, str]]:
    return []


@pytest.fixture
def client(calls: list[tuple[str, str]]) -> DockhandClient:
    return DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN, recorder=calls.append)


def _mount(dockhand: respx.MockRouter) -> None:
    dockhand.get(f"/api/containers/{CID}/inspect").respond(200, json={"Id": CID})
    dockhand.post(f"/api/containers/{CID}/restart").respond(200, json={"success": True})
    dockhand.get("/api/containers/stats").respond(200, json=[])
    dockhand.delete(f"/api/containers/{CID}").respond(200, json={"success": True})
    dockhand.post(f"/api/containers/{CID}/exec").respond(200, json={})
    dockhand.get("/api/environments").respond(200, json=[])


async def _inspect(client: DockhandClient, params: dict[str, Any]) -> Any:
    return await client.get_json(
        "/api/containers/{id}/inspect", path_params={"id": CID}, params=params
    )


async def _restart(client: DockhandClient, params: dict[str, Any]) -> Any:
    return await client.post_json(
        "/api/containers/{id}/restart", path_params={"id": CID}, params=params
    )


async def _stats(client: DockhandClient, params: dict[str, Any]) -> Any:
    return await client.get_json("/api/containers/stats", params=params)


async def _remove(client: DockhandClient, params: dict[str, Any]) -> Any:
    return await client.delete_json("/api/containers/{id}", path_params={"id": CID}, params=params)


async def _raw_restart(client: DockhandClient, params: dict[str, Any]) -> Any:
    return await client.raw(
        "POST", "/api/containers/{id}/restart", path_params={"id": CID}, params=params
    )


async def _sse_restart(client: DockhandClient, params: dict[str, Any]) -> Any:
    stream = client.stream_sse(
        "POST", "/api/containers/{id}/restart", path_params={"id": CID}, params=params
    )
    async with aclosing(stream) as events:
        return [e async for e in events]


CALLS = {
    "inspect (read)": ("GET /api/containers/{id}/inspect", _inspect),
    "restart (write)": ("POST /api/containers/{id}/restart", _restart),
    "stats (200 [] without env)": ("GET /api/containers/stats", _stats),
    "remove (delete)": ("DELETE /api/containers/{id}", _remove),
    "raw": ("POST /api/containers/{id}/restart", _raw_restart),
    "stream_sse": ("POST /api/containers/{id}/restart", _sse_restart),
}


@pytest.mark.parametrize("missing", [{}, {"env": None}, {"env": ""}, {"env": "  "}])
@pytest.mark.parametrize("case", list(CALLS))
async def test_refused_without_env_and_nothing_is_sent(
    dockhand: respx.MockRouter,
    client: DockhandClient,
    calls: list[tuple[str, str]],
    case: str,
    missing: dict[str, Any],
) -> None:
    _mount(dockhand)
    operation, call = CALLS[case]
    with pytest.raises(DockhandError) as exc:
        await call(client, missing)
    assert exc.value.code == "validation_error"
    assert exc.value.status is None
    assert exc.value.sent is False
    assert operation in exc.value.message
    assert "env" in exc.value.message
    assert dockhand.calls.call_count == 0
    assert calls == []


@pytest.mark.parametrize("case", list(CALLS))
async def test_sent_as_before_with_env(
    dockhand: respx.MockRouter, client: DockhandClient, case: str
) -> None:
    _mount(dockhand)
    _, call = CALLS[case]
    await call(client, {"env": ENV})
    assert dockhand.calls.call_count == 1
    assert dockhand.calls.last.request.url.params.get_list("env") == [str(ENV)]


async def test_exec_needs_envid_not_env(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    """The guard checks the parameter the spec names for the operation."""
    _mount(dockhand)
    with pytest.raises(DockhandError) as exc:
        await client.post_json(
            "/api/containers/{id}/exec", path_params={"id": CID}, params={"env": ENV}
        )
    assert "envId" in exc.value.message
    assert dockhand.calls.call_count == 0


async def test_probe_status_is_guarded(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    _mount(dockhand)
    with pytest.raises(DockhandError):
        await client.probe_status("GET", "/api/containers/stats")
    assert dockhand.calls.call_count == 0


async def test_operation_that_does_not_require_env_is_unaffected(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    _mount(dockhand)
    assert await client.get_json("/api/environments") == []
    assert dockhand.calls.call_count == 1
    # Optional there: `GET /api/containers` without env is still sent.
    dockhand.get("/api/containers").respond(200, json=[])
    assert await client.get_json("/api/containers") == []
    assert dockhand.calls.call_count == 2
