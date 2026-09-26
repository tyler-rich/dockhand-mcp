# SPDX-License-Identifier: Apache-2.0
"""GET /healthz: unauthenticated, exactly {"status":"ok"}, nothing informational (F-02)."""

import pytest
from conftest import DOCKHAND_URL, SetEnv
from starlette.testclient import TestClient

from dockhand_mcp.config import load_settings
from dockhand_mcp.transport.app import create_app


@pytest.fixture
def client(set_env: SetEnv) -> TestClient:
    set_env(
        DOCKHAND_URL=DOCKHAND_URL,
        DOCKHAND_MCP_AUTH_MODE="none",
        DOCKHAND_MCP_ALLOW_UNAUTHENTICATED="true",
    )
    return TestClient(create_app(load_settings()), base_url="http://127.0.0.1:8080")


def test_healthz_body_is_exact(client: TestClient) -> None:
    with client:
        r = client.get("/healthz")
    assert r.status_code == 200
    assert r.content == b'{"status":"ok"}'
    assert r.headers["content-type"] == "application/json"


def test_healthz_sends_no_informational_headers(client: TestClient) -> None:
    with client:
        r = client.get("/healthz")
    assert set(r.headers) == {"content-type", "content-length"}


def test_healthz_ignores_host_allow_list(client: TestClient) -> None:
    # The container healthcheck and orchestrators probe by IP or service name.
    with client:
        r = client.get("/healthz", headers={"host": "dockhand-mcp:8080"})
    assert r.status_code == 200


def test_healthz_rejects_other_methods(client: TestClient) -> None:
    with client:
        r = client.post("/healthz")
    assert r.status_code == 405
