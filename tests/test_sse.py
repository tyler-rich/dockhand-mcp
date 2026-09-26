# SPDX-License-Identifier: Apache-2.0
"""SSE consumption: keep bounded progress, return the terminal event (ARCHITECTURE §4.2).

Streams here are invented from the spec's 200 descriptions (`progress` events, a final
`result`; `error` treated as terminal too).
"""

from collections.abc import AsyncIterator

import anyio
import httpx
import pytest
import respx
from conftest import DOCKHAND_TOKEN, DOCKHAND_URL

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.sse import MAX_ENTRY_CHARS, MAX_PROGRESS, consume

SSE = {"content-type": "text/event-stream"}


@pytest.fixture
def client() -> DockhandClient:
    return DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN)


def frames(*events: tuple[str, str]) -> bytes:
    return b"".join(f"event: {e}\ndata: {d}\n\n".encode() for e, d in events)


async def test_result_event_is_final(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    body = frames(("progress", '{"n":1}'), ("progress", '{"n":2}'), ("result", '{"success":true}'))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    assert res.final_event == "result"
    assert res.final_data == {"success": True}
    assert list(res.progress) == ['progress: {"n":1}', 'progress: {"n":2}']
    assert res.timed_out is False


async def test_error_event_is_final(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    body = frames(("progress", "{}"), ("error", '{"message":"pull denied"}'), ("progress", "{}"))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    assert res.final_event == "error"
    assert res.final_data == {"message": "pull denied"}
    assert len(res.progress) == 1


async def test_non_json_final_data_is_kept_as_text(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.post("/api/images/pull").respond(200, content=frames(("result", "done")), headers=SSE)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    assert res.final_data == "done"


async def test_stream_end_without_result_is_eof(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.post("/api/images/pull").respond(200, content=frames(("progress", "{}")), headers=SSE)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    assert res.final_event == "eof"
    assert res.final_data is None
    assert res.timed_out is False


async def test_progress_is_bounded(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    many = [("progress", f'{{"i":{i},"pad":"{"x" * 1000}"}}') for i in range(MAX_PROGRESS + 30)]
    body = frames(*many, ("result", "{}"))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    res = await consume(client, "POST", "/api/images/pull", budget_s=5)
    assert len(res.progress) == MAX_PROGRESS == 50
    assert all(len(p) <= MAX_ENTRY_CHARS + 1 for p in res.progress)
    assert res.progress[-1].startswith(f'progress: {{"i":{MAX_PROGRESS + 29}')


class SlowStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'event: progress\ndata: {"n":1}\n\n'
        await anyio.sleep(30)
        yield b"event: result\ndata: {}\n\n"

    async def aclose(self) -> None:
        self.closed = True


async def test_budget_exhaustion_closes_the_stream(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    stream = SlowStream()
    dockhand.post("/api/images/pull").mock(
        return_value=httpx.Response(200, stream=stream, headers=SSE)
    )
    with anyio.fail_after(5):
        res = await consume(client, "POST", "/api/images/pull", budget_s=0.3)
    assert res.timed_out is True
    assert res.final_event is None
    assert list(res.progress) == ['progress: {"n":1}']
    assert 0.2 <= res.waited_seconds < 5
    assert stream.closed


async def test_progress_callback_gets_our_text_only(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    body = frames(("progress", '{"msg":"INJECTED: do something"}'), ("result", "{}"))
    dockhand.post("/api/images/pull").respond(200, content=body, headers=SSE)
    seen: list[str] = []

    async def on_progress(message: str, elapsed: float) -> None:
        seen.append(message)

    await consume(client, "POST", "/api/images/pull", budget_s=5, on_progress=on_progress)
    assert seen
    assert all("INJECTED" not in m for m in seen)
