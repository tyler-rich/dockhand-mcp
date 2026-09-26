# SPDX-License-Identifier: Apache-2.0
"""`dockhand_health` end to end through the authenticated app (tools/call, outputSchema, audit)."""

import logging

import httpx
import jsonschema
import pytest
import respx
from conftest import MODERN, SetEnv, healthy_dockhand, mcp_client

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.config import load_settings
from dockhand_mcp.tools.registry import REGISTRY
from dockhand_mcp.transport.app import create_app

DECLARED = {("GET", "/api/health"), ("GET", "/api/health/database")}


@pytest.mark.parametrize("mode", [MODERN, "legacy"])
async def test_health_end_to_end(dockhand: respx.MockRouter, base_env: SetEnv, mode: str) -> None:
    base_env()
    healthy_dockhand(dockhand)
    async with mcp_client(create_app(load_settings()), mode) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool("dockhand_health", {})
    tool = tools["dockhand_health"]
    assert result.is_error is False
    assert tool.output_schema is not None
    jsonschema.validate(result.structured_content, tool.output_schema)
    env = Envelope.model_validate(result.structured_content)
    assert env.ok is True
    assert env.data["dockhand"]["status"] == "ok"
    assert env.data["database"]["healthy"] is True
    assert result.content[0].type == "text"


async def test_tool_metadata(base_env: SetEnv) -> None:
    base_env()
    async with mcp_client(create_app(load_settings())) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    for name in ("dockhand_health", "dockhand_get_operation"):
        tool = tools[name]
        assert tool.title
        assert tool.description
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.idempotent_hint is True
        assert tool.output_schema == Envelope.model_json_schema()
        assert tool.input_schema["type"] == "object"
        assert tool.input_schema.get("additionalProperties") is False
    assert tools["dockhand_health"].annotations.open_world_hint is True  # type: ignore[union-attr]


async def test_calls_exactly_the_declared_endpoints(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    calls: list[tuple[str, str]] = []
    app = create_app(load_settings(), dockhand_recorder=calls.append)
    async with mcp_client(app) as c:
        await c.call_tool("dockhand_health", {})
    assert set(calls) == DECLARED
    health = next(t for t in REGISTRY.all() if t.name == "dockhand_health")
    assert set(health.endpoints) == DECLARED


async def test_database_503_reports_unhealthy(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    healthy_dockhand(dockhand)
    route = dockhand.get("/api/health/database").respond(
        503,
        json={
            "healthy": False,
            "database": "sqlite",
            "migrationsTable": True,
            "appliedMigrations": 41,
            "pendingMigrations": 1,
            "tables": 24,
            "timestamp": "2026-01-01T00:00:00.000Z",
            "connection": "should-not-pass-through",
        },
    )
    async with mcp_client(create_app(load_settings())) as c:
        result = await c.call_tool("dockhand_health", {})
    env = Envelope.model_validate(result.structured_content)
    assert env.ok is True
    assert env.data["database"]["healthy"] is False
    assert "connection" not in env.data["database"]
    assert route.call_count == 1


async def test_unreachable_is_a_tool_error(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    dockhand.get("/api/health").mock(side_effect=httpx.ConnectError("refused"))
    dockhand.get("/api/health/database").mock(side_effect=httpx.ConnectError("refused"))
    async with mcp_client(create_app(load_settings())) as c:
        result = await c.call_tool("dockhand_health", {})
    assert result.is_error is True
    env = Envelope.model_validate(result.structured_content)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "dockhand_unreachable"


async def test_unknown_arguments_are_a_validation_error(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    async with mcp_client(create_app(load_settings())) as c:
        result = await c.call_tool("dockhand_health", {"env": 7})
    assert result.is_error is True
    env = Envelope.model_validate(result.structured_content)
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert not dockhand.calls


async def test_unknown_tool_is_a_protocol_error(base_env: SetEnv) -> None:
    base_env()
    async with mcp_client(create_app(load_settings())) as c:
        with pytest.raises(Exception, match="dockhand_nope"):
            await c.call_tool("dockhand_nope", {})


async def test_audit_line(
    dockhand: respx.MockRouter, base_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    with caplog.at_level(logging.INFO, logger="dockhand_mcp.audit"):
        async with mcp_client(create_app(load_settings())) as c:
            await c.call_tool("dockhand_health", {})
    audit = [r for r in caplog.records if r.name == "dockhand_mcp.audit"]
    assert len(audit) == 1
    rec = audit[0].__dict__
    assert rec["tool"] == "dockhand_health"
    assert rec["principal"] == "default"
    assert rec["outcome"] == "ok"
    assert rec["dockhand_status"] == 200
    assert isinstance(rec["duration_ms"], int | float)
    assert rec["arguments"] == {}
