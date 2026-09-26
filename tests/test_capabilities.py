# SPDX-License-Identifier: Apache-2.0
"""The server advertises the `tools` capability and nothing else (ARCHITECTURE §7, F-14).

Checked on the wire over both served revisions: `server/discover` (2026-07-28) and the
`initialize` result (2025-11-25), plus through the SDK client in each mode.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from conftest import LEGACY, SetEnv, mcp_client, mcp_headers, rpc, rpc_response
from starlette.testclient import TestClient

from dockhand_mcp.config import load_settings
from dockhand_mcp.transport.app import create_app

REFUSED = ("resources", "prompts", "completions", "logging")


@pytest.fixture
def client(base_env: SetEnv) -> Iterator[TestClient]:
    base_env()
    with TestClient(create_app(load_settings()), base_url="http://127.0.0.1:8080") as tc:
        yield tc


def assert_tools_only(capabilities: dict[str, Any]) -> None:
    assert "tools" in capabilities
    assert capabilities["tools"].get("listChanged") in (None, False)
    for name in REFUSED:
        assert name not in capabilities, f"{name} advertised: {capabilities}"
    # Nothing else either, not even an empty `experimental` object.
    assert capabilities == {"tools": {"listChanged": False}}


def test_discover_2026_07_28(client: TestClient) -> None:
    r = client.post("/mcp", json=rpc("server/discover"), headers=mcp_headers("server/discover"))
    assert r.status_code == 200
    assert_tools_only(rpc_response(r)["result"]["capabilities"])


def test_initialize_2025_11_25(client: TestClient) -> None:
    body = rpc(
        "initialize",
        {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
        modern=False,
    )
    r = client.post("/mcp", json=body, headers=mcp_headers(version=None))
    assert r.status_code == 200
    result = rpc_response(r)["result"]
    assert result["protocolVersion"] == LEGACY
    assert_tools_only(result["capabilities"])


def test_refused_methods_are_not_served(client: TestClient) -> None:
    for method in ("resources/list", "prompts/list", "completion/complete", "subscriptions/listen"):
        r = client.post("/mcp", json=rpc(method), headers=mcp_headers(method))
        assert r.status_code in (400, 404, 406), method
        if r.status_code != 406:
            assert "error" in rpc_response(r)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_sdk_client_sees_tools_only(base_env: SetEnv, mode: str) -> None:
    base_env()
    async with mcp_client(create_app(load_settings()), mode) as c:
        caps = c.server_capabilities.model_dump(by_alias=True, exclude_none=True)
    assert_tools_only(caps)
