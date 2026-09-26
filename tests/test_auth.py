# SPDX-License-Identifier: Apache-2.0
"""Bearer authentication on the MCP endpoint: before any response, constant time (D-004, S-01)."""

import hmac
from collections.abc import Iterator

import httpx
import pytest
from conftest import (
    LEGACY,
    MCP_TOKEN,
    SetEnv,
    mcp_headers,
    read_tool_names,
    rpc,
    rpc_response,
)
from starlette.testclient import TestClient

from dockhand_mcp.auth import bearer
from dockhand_mcp.auth.bearer import BearerAuthenticator
from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.config import load_settings
from dockhand_mcp.tools.registry import Profile
from dockhand_mcp.transport.app import create_app

UNAUTHORIZED = b'{"error":"unauthorized"}'
CHALLENGE = 'Bearer realm="dockhand-mcp"'


@pytest.fixture
def client(base_env: SetEnv) -> Iterator[TestClient]:
    base_env()
    with TestClient(create_app(load_settings()), base_url="http://127.0.0.1:8080") as tc:
        yield tc


def tools_list(tc: TestClient, **headers: str) -> httpx.Response:
    return tc.post("/mcp", json=rpc("tools/list"), headers=headers)


def assert_unauthorized(r: httpx.Response) -> None:
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == CHALLENGE
    assert r.content == UNAUTHORIZED
    assert set(r.headers) == {"content-type", "content-length", "www-authenticate"}


def test_no_authorization_header_is_401(client: TestClient) -> None:
    assert_unauthorized(tools_list(client, **mcp_headers("tools/list", token=None)))


def test_wrong_token_is_401(client: TestClient) -> None:
    assert_unauthorized(tools_list(client, **mcp_headers("tools/list", token="x" * 43)))


@pytest.mark.parametrize(
    "value",
    [
        "Basic " + MCP_TOKEN,
        "Bearer",
        "Bearer ",
        MCP_TOKEN,
        f"Bearer {MCP_TOKEN} ",  # never normalised: trailing space is a different token
        f"Bearer  {MCP_TOKEN}",
        f"Token {MCP_TOKEN}",
    ],
)
def test_malformed_authorization_is_401(client: TestClient, value: str) -> None:
    headers = mcp_headers("tools/list", token=None) | {"authorization": value}
    assert_unauthorized(tools_list(client, **headers))


def test_scheme_is_case_insensitive(client: TestClient) -> None:
    headers = mcp_headers("tools/list", token=None) | {"authorization": f"bearer {MCP_TOKEN}"}
    assert tools_list(client, **headers).status_code == 200


def test_right_token_lists_tools(client: TestClient) -> None:
    r = tools_list(client, **mcp_headers("tools/list"))
    assert r.status_code == 200
    names = [t["name"] for t in rpc_response(r)["result"]["tools"]]
    assert names == read_tool_names()


@pytest.mark.parametrize("modern", [True, False])
def test_tools_list_without_auth_is_401_not_an_empty_list(client: TestClient, modern: bool) -> None:
    if modern:
        headers = mcp_headers("tools/list", token=None)
    else:
        headers = mcp_headers(token=None, version=None)
    r = client.post("/mcp", json=rpc("tools/list", modern=modern), headers=headers)
    assert_unauthorized(r)


def test_legacy_initialize_without_auth_is_401(client: TestClient) -> None:
    body = rpc(
        "initialize",
        {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
        modern=False,
    )
    r = client.post("/mcp", json=body, headers=mcp_headers(token=None, version=None))
    assert_unauthorized(r)


def test_get_and_delete_need_auth_too(client: TestClient) -> None:
    for method in ("GET", "DELETE"):
        r = client.request(method, "/mcp", headers=mcp_headers(token=None))
        assert_unauthorized(r)


def test_compare_digest_gets_raw_configured_token_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(bearer.hmac, "compare_digest", spy)
    auth = BearerAuthenticator([MCP_TOKEN], Profile.READ_ONLY)
    configured = MCP_TOKEN.encode()

    assert auth.authenticate(b"Bearer short") is None  # wrong length
    assert auth.authenticate(b"Bearer " + b"x" * len(configured)) is None  # wrong content
    assert calls == [(b"short", configured), (b"x" * len(configured), configured)]

    assert auth.authenticate(b"Bearer " + configured) == Principal("default", Profile.READ_ONLY)


def test_compare_digest_is_used_by_the_endpoint(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(bearer.hmac, "compare_digest", spy)
    assert_unauthorized(tools_list(client, **mcp_headers("tools/list", token="short")))
    assert calls == [(b"short", MCP_TOKEN.encode())]


def test_every_configured_token_is_compared() -> None:
    other = "o" * 43
    auth = BearerAuthenticator([MCP_TOKEN, other], Profile.OPERATOR)
    assert auth.authenticate(f"Bearer {other}".encode()) == Principal("default", Profile.OPERATOR)
    assert auth.authenticate(f"Bearer {MCP_TOKEN}".encode()) == Principal(
        "default", Profile.OPERATOR
    )


def test_principal_carries_the_configured_profile(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="operator")
    auth = BearerAuthenticator.from_settings(load_settings())
    assert auth.authenticate(f"Bearer {MCP_TOKEN}".encode()) == Principal(
        "default", Profile.OPERATOR
    )


def test_ten_failures_then_429_with_retry_after(client: TestClient) -> None:
    for _ in range(10):
        assert_unauthorized(tools_list(client, **mcp_headers("tools/list", token="x" * 43)))
    r = tools_list(client, **mcp_headers("tools/list", token="x" * 43))
    assert r.status_code == 429
    assert 1 <= int(r.headers["retry-after"]) <= 300
    # Blocked means blocked: even the right token waits out the penalty.
    assert tools_list(client, **mcp_headers("tools/list")).status_code == 429


def test_missing_header_is_not_counted_as_a_guess(client: TestClient) -> None:
    for _ in range(15):
        assert_unauthorized(tools_list(client, **mcp_headers("tools/list", token=None)))
    assert tools_list(client, **mcp_headers("tools/list")).status_code == 200


def test_healthz_needs_no_auth_and_ignores_the_block(client: TestClient) -> None:
    for _ in range(11):
        tools_list(client, **mcp_headers("tools/list", token="x" * 43))
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.content == b'{"status":"ok"}'
