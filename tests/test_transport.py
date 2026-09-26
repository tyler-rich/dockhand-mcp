# SPDX-License-Identifier: Apache-2.0
"""The MCP endpoint's request pipeline, in ARCHITECTURE §3 order.

Body cap -> global rate limit -> Host/Origin -> bearer auth -> protocol checks -> SDK.
"""

import json
from collections.abc import Iterator

import httpx
import pytest
from conftest import (
    DOCKHAND_URL,
    MCP_TOKEN,
    SetEnv,
    mcp_client,
    mcp_headers,
    read_tool_names,
    rpc,
    rpc_response,
)
from starlette.testclient import TestClient

from dockhand_mcp.config import load_settings
from dockhand_mcp.transport.app import MAX_REQUEST_BODY_BYTES, StartupError, create_app

NONE_MODE = {
    "DOCKHAND_URL": DOCKHAND_URL,
    "DOCKHAND_MCP_AUTH_MODE": "none",
    "DOCKHAND_MCP_ALLOW_UNAUTHENTICATED": "true",
}
BASE = "http://127.0.0.1:8080"
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022


@pytest.fixture
def client(base_env: SetEnv) -> Iterator[TestClient]:
    base_env()
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        yield tc


def post(tc: TestClient, body: object, **headers: str) -> httpx.Response:
    return tc.post("/mcp", json=body, headers=headers)


def list_tools(tc: TestClient, **extra: str) -> httpx.Response:
    return post(tc, rpc("tools/list"), **(mcp_headers("tools/list") | extra))


# --- app construction -------------------------------------------------------------------------


def test_bearer_mode_starts(base_env: SetEnv) -> None:
    base_env()
    create_app(load_settings())


def test_oauth_mode_refuses_to_start(set_env: SetEnv) -> None:
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_AUTH_MODE="oauth")
    with pytest.raises(StartupError, match=r"^oauth auth not implemented until Phase 5$"):
        create_app(load_settings())


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
async def test_none_mode_still_serves_loopback(set_env: SetEnv, mode: str) -> None:
    set_env(**NONE_MODE)
    async with mcp_client(create_app(load_settings()), mode, token=None) as c:
        names = [t.name for t in (await c.list_tools()).tools]
    assert names == read_tool_names()


async def test_endpoint_follows_configured_path(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PATH="/custom/mcp")
    app = create_app(load_settings())
    async with mcp_client(app, url="http://127.0.0.1:8080/custom/mcp") as c:
        assert len((await c.list_tools()).tools) == len(read_tool_names())
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        assert list_tools(tc).status_code == 404


# --- 1. body cap ------------------------------------------------------------------------------


def big_body() -> bytes:
    return (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"'
        + b"a" * (MAX_REQUEST_BODY_BYTES)
        + b'"}'
    )


def test_body_over_one_mib_is_413(client: TestClient) -> None:
    r = client.post("/mcp", content=big_body(), headers=mcp_headers("tools/list"))
    assert r.status_code == 413


def test_oversized_and_unauthenticated_is_413_not_401(client: TestClient) -> None:
    headers = mcp_headers("tools/list", token=None) | {"content-type": "application/json"}
    r = client.post("/mcp", content=big_body(), headers=headers)
    assert r.status_code == 413


def test_oversized_without_content_length_is_413(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield big_body()

    headers = mcp_headers("tools/list", token=None) | {"content-type": "application/json"}
    r = client.post("/mcp", content=chunks(), headers=headers)
    assert r.status_code == 413


def test_body_at_the_limit_reaches_auth(client: TestClient) -> None:
    head = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"'
    body = head + b"a" * (MAX_REQUEST_BODY_BYTES - len(head) - 2) + b'"}'
    assert len(body) == MAX_REQUEST_BODY_BYTES
    headers = mcp_headers("tools/list", token=None) | {"content-type": "application/json"}
    assert client.post("/mcp", content=body, headers=headers).status_code == 401


# --- 2. global rate limit ---------------------------------------------------------------------


def test_global_limit_is_429_with_retry_after(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RATE_LIMIT_PER_MIN="3")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        assert [list_tools(tc).status_code for _ in range(3)] == [200, 200, 200]
        r = list_tools(tc)
    assert r.status_code == 429
    assert 1 <= int(r.headers["retry-after"]) <= 60


def test_global_limit_applies_before_auth(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RATE_LIMIT_PER_MIN="2")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        no_auth = mcp_headers("tools/list", token=None)
        assert [post(tc, rpc("tools/list"), **no_auth).status_code for _ in range(2)] == [401, 401]
        assert post(tc, rpc("tools/list"), **no_auth).status_code == 429


def test_global_limit_does_not_touch_healthz(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RATE_LIMIT_PER_MIN="1")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        list_tools(tc)
        assert list_tools(tc).status_code == 429
        assert tc.get("/healthz").status_code == 200


def xff_limited(tc: TestClient, forwarded: list[str]) -> list[int]:
    return [list_tools(tc, **{"x-forwarded-for": f}).status_code for f in forwarded]


def test_trusted_proxy_counts_the_right_most_forwarded_entry(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RATE_LIMIT_PER_MIN="3", DOCKHAND_MCP_TRUST_PROXY="true")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        # A client varying the left-most (client-supplied) entry does not get a fresh bucket.
        spoofed = [f"192.0.2.{i}, 203.0.113.7" for i in range(4)]
        assert xff_limited(tc, spoofed) == [200, 200, 200, 429]
        # Distinct right-most entries (what our proxy appended) are distinct clients.
        distinct = [f"203.0.113.7, 198.51.100.{i}" for i in range(4)]
        assert xff_limited(tc, distinct) == [200, 200, 200, 200]


def test_forwarded_for_ignored_without_trust_proxy(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RATE_LIMIT_PER_MIN="3")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        distinct = [f"198.51.100.{i}" for i in range(4)]
        assert xff_limited(tc, distinct) == [200, 200, 200, 429]


def test_trusted_proxy_auth_failures_keyed_by_right_most_entry(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_TRUST_PROXY="true")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        bad = mcp_headers("tools/list", token="x" * 43)
        for i in range(10):
            post(tc, rpc("tools/list"), **(bad | {"x-forwarded-for": f"192.0.2.{i}, 203.0.113.9"}))
        blocked = mcp_headers("tools/list") | {"x-forwarded-for": "192.0.2.99, 203.0.113.9"}
        assert post(tc, rpc("tools/list"), **blocked).status_code == 429
        other = mcp_headers("tools/list") | {"x-forwarded-for": "203.0.113.10"}
        assert post(tc, rpc("tools/list"), **other).status_code == 200


# --- 3. Host / Origin -------------------------------------------------------------------------


def test_unlisted_host_is_rejected_before_auth(client: TestClient) -> None:
    assert list_tools(client, host="attacker.example.test").status_code == 421
    assert list_tools(client, host="attacker.example.test:8080").status_code == 421
    no_auth = mcp_headers("tools/list", token=None) | {"host": "attacker.example.test"}
    assert post(client, rpc("tools/list"), **no_auth).status_code == 421


def test_legacy_request_with_unlisted_host_is_rejected(client: TestClient) -> None:
    headers = mcp_headers(version=None) | {"host": "attacker.example.test"}
    assert post(client, rpc("tools/list", modern=False), **headers).status_code == 421


def test_configured_host_with_any_port_is_accepted(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_ALLOWED_HOSTS="mcp.example.test")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        assert list_tools(tc, host="mcp.example.test:8080").status_code == 200
        assert list_tools(tc, host="127.0.0.1:8080").status_code == 421  # replaced, not merged


def test_unlisted_origin_is_rejected(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_ALLOWED_ORIGINS="https://ok.example.test")
    with TestClient(create_app(load_settings()), base_url=BASE) as tc:
        assert list_tools(tc, origin="https://evil.example.test").status_code == 403
        assert list_tools(tc, origin="https://ok.example.test").status_code == 200


def test_no_browser_origins_by_default(client: TestClient) -> None:
    assert list_tools(client, origin="http://localhost:8080").status_code == 403


# --- 5. protocol checks (S-12) ----------------------------------------------------------------


def error_code(r: httpx.Response) -> int:
    return int(rpc_response(r)["error"]["code"])


def test_unsupported_protocol_version_is_400(client: TestClient) -> None:
    body = rpc("tools/list")
    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
    r = post(client, body, **mcp_headers("tools/list", version="2099-01-01"))
    assert r.status_code == 400
    assert error_code(r) == UNSUPPORTED_PROTOCOL_VERSION


def test_unknown_version_header_is_400(client: TestClient) -> None:
    r = post(client, rpc("tools/list", modern=False), **mcp_headers(version="1999-01-01"))
    assert r.status_code == 400


@pytest.mark.parametrize("modern", [True, False])
def test_mcp_method_mismatch_is_400(client: TestClient, modern: bool) -> None:
    version = "2026-07-28" if modern else None
    body = rpc("tools/list", modern=modern)
    r = post(client, body, **mcp_headers("tools/call", version=version))
    assert r.status_code == 400
    assert error_code(r) == HEADER_MISMATCH


@pytest.mark.parametrize("modern", [True, False])
def test_mcp_name_mismatch_is_400(client: TestClient, modern: bool) -> None:
    version = "2026-07-28" if modern else None
    body = rpc("tools/call", {"name": "dockhand_health", "arguments": {}}, modern=modern)
    headers = mcp_headers("tools/call", name="dockhand_get_operation", version=version)
    r = post(client, body, **headers)
    assert r.status_code == 400
    assert error_code(r) == HEADER_MISMATCH


def test_modern_request_without_mcp_name_is_400(client: TestClient) -> None:
    body = rpc("tools/call", {"name": "dockhand_health", "arguments": {}})
    r = post(client, body, **mcp_headers("tools/call"))
    assert r.status_code == 400


def test_legacy_mcp_name_on_a_method_without_a_name_is_400(client: TestClient) -> None:
    r = post(
        client,
        rpc("tools/list", modern=False),
        **mcp_headers("tools/list", name="dockhand_health", version=None),
    )
    assert r.status_code == 400
    assert error_code(r) == HEADER_MISMATCH


def test_legacy_duplicate_routing_header_is_400(client: TestClient) -> None:
    raw = [
        ("authorization", f"Bearer {MCP_TOKEN}"),
        ("accept", "application/json, text/event-stream"),
        ("content-type", "application/json"),
        ("mcp-method", "tools/list"),
        ("mcp-method", "tools/list"),
    ]
    r = client.post("/mcp", content=json.dumps(rpc("tools/list", modern=False)), headers=raw)
    assert r.status_code == 400


def test_legacy_mismatch_with_unparseable_body_is_400(client: TestClient) -> None:
    headers = mcp_headers("tools/list", version=None) | {"content-type": "application/json"}
    r = client.post("/mcp", content=b"not json", headers=headers)
    assert r.status_code == 400


def test_legacy_matching_headers_pass(client: TestClient) -> None:
    r = post(client, rpc("tools/list", modern=False), **mcp_headers("tools/list", version=None))
    assert r.status_code == 200
    assert len(rpc_response(r)["result"]["tools"]) == len(read_tool_names())


def test_protocol_checks_run_after_auth(client: TestClient) -> None:
    r = post(client, rpc("tools/list"), **mcp_headers("tools/call", token=None))
    assert r.status_code == 401
