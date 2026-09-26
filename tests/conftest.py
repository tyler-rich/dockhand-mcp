# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures: every test starts from an environment with no DOCKHAND_* variables."""

import hashlib
import json
import logging
import os
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest
import respx
from mcp import Client
from mcp.client.session import ElicitationFnT
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from dockhand_mcp.logging import set_redaction_secrets

DOCKHAND_URL = "https://dockhand.example.test"
# 43 characters: the minimum accepted MCP bearer token length (32 bytes, base64url).
MCP_TOKEN = "t" * 43
DOCKHAND_TOKEN = "dh_" + "k" * 43


def fake_dh_token(body: str = "AbC-123_xyz") -> str:
    """A fake DockHand token, built at runtime: test files never hold token-shaped literals."""
    return "dh_" + body


def fake_secret(body: str = "hunter2") -> str:
    """A fake secret value; tests pair it with keys (`password=`, `Authorization:`) at runtime."""
    return body


def hexid(seed: str) -> str:
    """A 64-hex id derived at runtime, so fixtures never hold id- or key-shaped literals."""
    return hashlib.sha256(seed.encode()).hexdigest()


ENV = 7
IDS: dict[str, str] = {
    name: hexid(name.lower())
    for name in (
        "CID_WEB",
        "CID_DB",
        "CID_WORKER",
        "IMG_NGINX",
        "IMG_REDIS",
        "IMG_BUSYBOX",
        "IMG_DANGLING",
        "DIGEST_NGINX",
        "NID_FRONT",
        "NID_BACK",
    )
}
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CATALOGUE_SNAPSHOT = FIXTURES / "tool-catalogue-read.json"
CATALOGUE_SNAPSHOTS = {
    tier: FIXTURES / f"tool-catalogue-{tier}.json" for tier in ("read", "operator", "destructive")
}


def _fill(value: Any, subs: dict[str, str]) -> Any:
    if isinstance(value, str):
        for name, sub in subs.items():
            value = value.replace("{{" + name + "}}", sub)
        return value
    if isinstance(value, dict):
        return {_fill(k, subs): _fill(v, subs) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, subs) for v in value]
    return value


def load_fixture(domain: str, name: str, **subs: str) -> Any:
    """An invented DockHand response body from tests/fixtures/dockhand, placeholders filled."""
    wrapped = json.loads((FIXTURES / "dockhand" / domain / f"{name}.json").read_text("utf-8"))
    return _fill(wrapped["body"], {**IDS, "SECRET": fake_secret("s3cr3t-value"), **subs})


def read_tool_names() -> list[str]:
    """The read tier's tool names, from the committed catalogue snapshot."""
    catalogue = json.loads(CATALOGUE_SNAPSHOT.read_text("utf-8"))
    return [t["name"] for t in catalogue if t["tier"] == "read"]


def operator_tool_names() -> list[str]:
    """The operator tier's tool names, from the committed catalogue snapshot."""
    catalogue = json.loads(CATALOGUE_SNAPSHOTS["operator"].read_text("utf-8"))
    return [t["name"] for t in catalogue if t["tier"] == "operator"]


def destructive_tool_names() -> list[str]:
    """The destructive tier's tool names, from the committed catalogue snapshot."""
    catalogue = json.loads(CATALOGUE_SNAPSHOTS["destructive"].read_text("utf-8"))
    return [t["name"] for t in catalogue if t["tier"] == "destructive"]


MCP_URL = "http://127.0.0.1:8080/mcp"
MODERN = "2026-07-28"
LEGACY = "2025-11-25"

SetEnv = Callable[..., None]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in list(os.environ):
        if name.upper().startswith("DOCKHAND_"):
            monkeypatch.delenv(name, raising=False)
    yield


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    """configure_logging() replaces the root handlers; put pytest's back after each test."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    set_redaction_secrets(())


@pytest.fixture
def set_env(monkeypatch: pytest.MonkeyPatch) -> SetEnv:
    def _set(**env: str) -> None:
        for name, value in env.items():
            monkeypatch.setenv(name, value)

    return _set


@pytest.fixture
def base_env(set_env: SetEnv) -> SetEnv:
    """A minimal valid bearer-mode configuration; keyword arguments override it."""

    def _set(**env: str) -> None:
        set_env(**({"DOCKHAND_URL": DOCKHAND_URL, "DOCKHAND_MCP_TOKEN": MCP_TOKEN} | env))

    return _set


@pytest.fixture
def dockhand() -> Iterator[respx.MockRouter]:
    """A mocked DockHand at DOCKHAND_URL. Unrouted requests fail the test."""
    with respx.mock(base_url=DOCKHAND_URL, assert_all_called=False) as router:
        yield router


def healthy_dockhand(router: respx.MockRouter) -> None:
    """Route the two public health endpoints with healthy (invented) responses."""
    router.get("/api/health").respond(
        200, json={"status": "ok", "timestamp": "2026-01-01T00:00:00.000Z"}
    )
    router.get("/api/health/database").respond(
        200,
        json={
            "healthy": True,
            "database": "sqlite",
            "migrationsTable": True,
            "appliedMigrations": 42,
            "pendingMigrations": 0,
            "tables": 25,
            "timestamp": "2026-01-01T00:00:00.000Z",
        },
    )


# --- raw MCP requests -------------------------------------------------------------------------


def rpc(method: str, params: dict[str, Any] | None = None, *, modern: bool = True) -> Any:
    """A JSON-RPC request body; 2026-07-28 requests carry the per-request `_meta` envelope."""
    body_params = dict(params or {})
    if modern:
        body_params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "tests", "version": "0"},
        }
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": body_params}


def mcp_headers(
    method: str | None = None,
    *,
    name: str | None = None,
    token: str | None = MCP_TOKEN,
    version: str | None = MODERN,
) -> dict[str, str]:
    headers = {"accept": "application/json, text/event-stream"}
    if version is not None:
        headers["mcp-protocol-version"] = version
    if method is not None:
        headers["mcp-method"] = method
    if name is not None:
        headers["mcp-name"] = name
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return headers


def rpc_response(response: httpx.Response | httpx2.Response) -> Any:
    """The JSON-RPC message in a response, whether sent as JSON or as one SSE `message` event."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [
            line[len("data:") :].strip()
            for line in response.text.splitlines()
            if line.startswith("data:")
        ]
        return json.loads(data[-1])
    return response.json()


@asynccontextmanager
async def mcp_client(
    app: Starlette,
    mode: str = MODERN,
    *,
    token: str | None = MCP_TOKEN,
    url: str = MCP_URL,
    elicitation_callback: ElicitationFnT | None = None,
) -> AsyncIterator[Client]:
    """An SDK client talking to the in-process app, authenticated with `token`.

    With `elicitation_callback` the client declares the elicitation capability and answers
    elicitation requests with it.
    """
    headers = {"authorization": f"Bearer {token}"} if token is not None else {}
    async with app.router.lifespan_context(app):
        http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers)
        transport = streamable_http_client(url, http_client=http)
        client = Client(transport, mode=mode, elicitation_callback=elicitation_callback)  # type: ignore[arg-type]
        async with http, client as c:
            yield c
