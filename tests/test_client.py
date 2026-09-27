# SPDX-License-Identifier: Apache-2.0
"""DockHand HTTP client: headers, TLS, redirects, retries, error mapping, logging (S-04, F-12)."""

import logging
import ssl
from collections.abc import Awaitable, Callable

import certifi
import httpx
import pytest
import respx
from conftest import DOCKHAND_TOKEN, DOCKHAND_URL, ENV, SetEnv, fake_dh_token

from dockhand_mcp.client.dockhand import (
    DockhandClient,
    UndeclaredEndpointError,
    declared_endpoints,
)
from dockhand_mcp.client.errors import MAX_BODY_EXCERPT, DockhandError
from dockhand_mcp.config import load_settings

Sleep = Callable[[float], Awaitable[None]]


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def client(sleeps: list[float]) -> DockhandClient:
    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    return DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN, sleep=fake_sleep)


async def raises(coro: Awaitable[object]) -> DockhandError:
    with pytest.raises(DockhandError) as exc:
        await coro
    return exc.value


# --- headers ----------------------------------------------------------------------------------


async def test_sends_bearer_token_and_accept_json(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = dockhand.get("/api/environments").respond(200, json=[])
    assert await client.get_json("/api/environments") == []
    request = route.calls.last.request
    assert request.headers["authorization"] == f"Bearer {DOCKHAND_TOKEN}"
    assert request.headers["accept"] == "application/json"


async def test_no_authorization_header_without_a_token(dockhand: respx.MockRouter) -> None:
    route = dockhand.get("/api/health").respond(200, json={"status": "ok"})
    await DockhandClient(DOCKHAND_URL).get_json("/api/health")
    assert "authorization" not in route.calls.last.request.headers


async def test_accept_can_be_overridden(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.post("/api/stacks/web/start").respond(200, json={"jobId": "j1"})
    await client.post_json(
        "/api/stacks/{name}/start", path_params={"name": "web"}, accept="text/event-stream"
    )
    assert route.calls.last.request.headers["accept"] == "text/event-stream"


async def test_path_params_are_url_encoded(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = dockhand.get(url__regex=r".*/api/containers/.*").respond(200, json={})
    await client.get_json("/api/containers/{id}", path_params={"id": "a/../b c"}, params={"env": 7})
    request = route.calls.last.request
    assert request.url.raw_path == b"/api/containers/a%2F..%2Fb%20c?env=7"


async def test_template_placeholders_must_all_be_filled(client: DockhandClient) -> None:
    with pytest.raises(ValueError, match="id"):
        await client.get_json("/api/containers/{id}")


# --- TLS and scheme ---------------------------------------------------------------------------


def test_http_url_refused_without_allow_http() -> None:
    with pytest.raises(ValueError, match="DOCKHAND_ALLOW_HTTP"):
        DockhandClient("http://dockhand.example.test")


def test_http_url_allowed_with_allow_http(base_env: SetEnv) -> None:
    DockhandClient("http://dockhand.example.test", allow_http=True)
    base_env(DOCKHAND_URL="http://dockhand.example.test", DOCKHAND_ALLOW_HTTP="true")
    DockhandClient.from_settings(load_settings())


def test_tls_verified_by_default(base_env: SetEnv) -> None:
    base_env()
    assert DockhandClient.from_settings(load_settings()).verify is True


def test_tls_insecure_disables_verification_and_warns(
    base_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    base_env(DOCKHAND_TLS_INSECURE="true")
    with caplog.at_level(logging.WARNING):
        client = DockhandClient.from_settings(load_settings())
    assert client.verify is False
    assert any(
        r.levelno == logging.WARNING and "DOCKHAND_TLS_INSECURE" in r.getMessage()
        for r in caplog.records
    )


def test_ca_bundle_builds_a_verifying_context(base_env: SetEnv) -> None:
    base_env(DOCKHAND_CA_BUNDLE=certifi.where())
    verify = DockhandClient.from_settings(load_settings()).verify
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode is ssl.CERT_REQUIRED


# --- redirects --------------------------------------------------------------------------------


async def test_redirect_is_not_followed(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    # Following it would reach an unmocked host, which respx turns into a non-DockhandError.
    route = dockhand.get("/api/health").respond(
        302, headers={"location": "https://internal.example.test/"}
    )
    err = await raises(client.get_json("/api/health"))
    assert err.code == "unexpected_redirect"
    assert err.status == 302
    assert "internal.example.test" not in err.message
    assert route.call_count == 1


# --- retries ----------------------------------------------------------------------------------


async def test_get_retries_5xx_then_succeeds(
    dockhand: respx.MockRouter, client: DockhandClient, sleeps: list[float]
) -> None:
    route = dockhand.get("/api/health").mock(
        side_effect=[httpx.Response(503), httpx.Response(503), httpx.Response(200, json={"a": 1})]
    )
    assert await client.get_json("/api/health") == {"a": 1}
    assert route.call_count == 3
    assert len(sleeps) == 2
    assert all(s > 0 for s in sleeps)


async def test_get_gives_up_after_three_attempts(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = dockhand.get("/api/health").respond(502)
    err = await raises(client.get_json("/api/health"))
    assert route.call_count == 3
    assert (err.code, err.status) == ("dockhand_http_error", 502)


async def test_get_retries_unreachable(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.get("/api/health").mock(side_effect=httpx.ConnectError("refused"))
    err = await raises(client.get_json("/api/health"))
    assert route.call_count == 3
    assert err.code == "dockhand_unreachable"
    assert err.status is None


async def test_post_is_never_retried(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.post("/api/containers/abc/restart").respond(503)
    err = await raises(
        client.post_json(
            "/api/containers/{id}/restart", path_params={"id": "abc"}, params={"env": ENV}
        )
    )
    assert route.call_count == 1
    assert (err.code, err.status) == ("dockhand_http_error", 503)


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failures_are_never_retried(
    dockhand: respx.MockRouter, client: DockhandClient, status: int
) -> None:
    route = dockhand.get("/api/environments").respond(status, json={"error": "nope"})
    err = await raises(client.get_json("/api/environments"))
    assert route.call_count == 1
    assert (err.code, err.status) == ("dockhand_http_error", status)
    assert "token" in err.message.lower() or "permission" in err.message.lower()


async def test_401_and_403_hints_differ(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    dockhand.get("/api/a").respond(401)
    dockhand.get("/api/b").respond(403)
    e401 = await raises(client.get_json("/api/a"))
    e403 = await raises(client.get_json("/api/b"))
    assert "token" in e401.message.lower()
    assert "permission" in e403.message.lower()
    assert e401.message != e403.message


async def test_404_is_not_found(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    dockhand.get("/api/jobs/x").respond(404, json={"error": "Job not found"})
    err = await raises(client.get_json("/api/jobs/{id}", path_params={"id": "x"}))
    assert (err.code, err.status) == ("not_found", 404)
    assert err.body_excerpt is not None and "Job not found" in err.body_excerpt


async def test_429_carries_retry_after(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.get("/api/health").respond(429, headers={"retry-after": "120"})
    err = await raises(client.get_json("/api/health"))
    assert route.call_count == 1
    assert (err.code, err.status, err.retry_after) == ("dockhand_http_error", 429, 120)


async def test_timeout_maps_to_timeout(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.post("/api/x").mock(side_effect=httpx.ReadTimeout("slow"))
    err = await raises(client.post_json("/api/x"))
    assert route.call_count == 1
    assert err.code == "timeout"


async def test_allowed_status_returns_the_body(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = dockhand.get("/api/health/database").respond(503, json={"healthy": False})
    body = await client.get_json("/api/health/database", allow_status={503})
    assert body == {"healthy": False}
    assert route.call_count == 1


async def test_non_json_success_is_an_error(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/health").respond(200, text="<html>proxy login</html>")
    err = await raises(client.get_json("/api/health"))
    assert err.code == "dockhand_http_error"


# --- error bodies -----------------------------------------------------------------------------


async def test_error_body_is_truncated_and_redacted(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    leaked = fake_dh_token("LeakedTokenValue")
    body = leaked + " " + "x" * 10_000
    dockhand.post("/api/x").respond(400, text=body)
    err = await raises(client.post_json("/api/x"))
    assert err.body_excerpt is not None
    assert len(err.body_excerpt) <= MAX_BODY_EXCERPT + 1
    assert "LeakedTokenValue" not in err.body_excerpt
    assert "LeakedTokenValue" not in err.message


# --- logging ----------------------------------------------------------------------------------


async def test_one_log_line_per_call_without_secrets(
    dockhand: respx.MockRouter, client: DockhandClient, caplog: pytest.LogCaptureFixture
) -> None:
    dockhand.get(url__regex=r".*/api/containers.*").respond(200, json=[])
    with caplog.at_level(logging.INFO, logger="dockhand_mcp.client"):
        await client.get_json("/api/containers", params={"env": 7, "search": "secret-name"})
    records = [r for r in caplog.records if r.name.startswith("dockhand_mcp.client")]
    assert len(records) == 1
    rec = records[0]
    assert rec.__dict__["method"] == "GET"
    assert rec.__dict__["path"] == "/api/containers?env&search"
    assert rec.__dict__["status"] == 200
    assert isinstance(rec.__dict__["ms"], int | float)
    flat = repr(rec.__dict__)
    assert DOCKHAND_TOKEN not in flat
    assert "secret-name" not in flat
    assert "authorization" not in flat.lower()


# --- call recording and declared endpoints ----------------------------------------------------


async def test_recorder_sees_method_and_template(dockhand: respx.MockRouter) -> None:
    calls: list[tuple[str, str]] = []
    client = DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN, recorder=calls.append)
    dockhand.get("/api/containers/abc").respond(200, json={})
    dockhand.post("/api/containers/abc/start").respond(200, json={})
    await client.get_json("/api/containers/{id}", path_params={"id": "abc"}, params={"env": ENV})
    await client.post_json(
        "/api/containers/{id}/start", path_params={"id": "abc"}, params={"env": ENV}
    )
    assert calls == [("GET", "/api/containers/{id}"), ("POST", "/api/containers/{id}/start")]


async def test_undeclared_endpoint_is_refused_before_any_request(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    allowed = dockhand.get("/api/health").respond(200, json={})
    other = dockhand.get("/api/environments").respond(200, json=[])
    with declared_endpoints(frozenset({("GET", "/api/health")})):
        await client.get_json("/api/health")
        with pytest.raises(UndeclaredEndpointError):
            await client.get_json("/api/environments")
    assert allowed.called
    assert not other.called
    await client.get_json("/api/environments")  # outside a tool: unrestricted


# --- SSE --------------------------------------------------------------------------------------


async def test_stream_sse_yields_events(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    stream = (
        b": keepalive\n\n"
        b'event: progress\ndata: {"checked":1}\n\n'
        b"data: line one\ndata: line two\n\n"
        b'event: result\r\ndata: {"ok":true}\r\n\r\n'
    )
    route = dockhand.post("/api/images/pull").respond(
        200, content=stream, headers={"content-type": "text/event-stream"}
    )
    events = [e async for e in client.stream_sse("POST", "/api/images/pull", json={"image": "x"})]
    assert events == [
        ("progress", '{"checked":1}'),
        ("message", "line one\nline two"),
        ("result", '{"ok":true}'),
    ]
    assert route.calls.last.request.headers["accept"] == "text/event-stream"


async def test_stream_sse_maps_http_errors(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.post("/api/images/pull").respond(403)
    with pytest.raises(DockhandError) as exc:
        async for _ in client.stream_sse("POST", "/api/images/pull"):
            pass
    assert exc.value.status == 403


async def test_probe_status_does_not_raise(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/roles").respond(403, json={"error": "Enterprise license required"})
    assert await client.probe_status("GET", "/api/roles") == 403
