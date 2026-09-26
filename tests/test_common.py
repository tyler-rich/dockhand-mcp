# SPDX-License-Identifier: Apache-2.0
"""tools/_common.py: pagination, text caps, env redaction, and environment defaulting (F-09)."""

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
import yaml
from conftest import DOCKHAND_URL, fake_secret, load_fixture
from pydantic import ValidationError

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.operations import OperationRegistry
from dockhand_mcp.config import Settings
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.tools import _common
from dockhand_mcp.tools.base import ToolContext


class _Input(_common.EnvScoped):
    pass


def test_base_input_forbids_extra_and_strips() -> None:
    with pytest.raises(ValidationError):
        _Input.model_validate({"environment_id": 7, "nope": 1})
    assert _common.ToolInput.model_config["str_strip_whitespace"] is True
    with pytest.raises(ValidationError):
        _Input.model_validate({"environment_id": 0})


# --- pagination -------------------------------------------------------------------------------


def test_page_has_more() -> None:
    items = list(range(5))
    assert _common.page(items, 2, 0) == {"items": [0, 1], "count": 2, "total": 5, "has_more": True}
    assert _common.page(items, 2, 4) == {"items": [4], "count": 1, "total": 5, "has_more": False}
    assert _common.page(items, 10, 0)["has_more"] is False
    assert _common.page(items, 2, 9) == {"items": [], "count": 0, "total": 5, "has_more": False}


def test_remote_page_has_more() -> None:
    assert _common.remote_page([1, 2], 5, 0)["has_more"] is True
    assert _common.remote_page([4, 5], 5, 3)["has_more"] is False
    unknown = _common.remote_page([1], None, 0)
    assert unknown == {"items": [1], "count": 1, "has_more": False}


# --- text cap ---------------------------------------------------------------------------------


def test_cap_text_under_limit() -> None:
    out = _common.cap_text("a\nb\n", 1024, key="logs")
    assert out == {"logs": "a\nb\n", "bytes": 4, "truncated": False, "dropped_bytes": 0}


def test_cap_text_keeps_the_newest_whole_lines() -> None:
    lines = [f"line {i:05d}" for i in range(2000)]
    text = "\n".join(lines) + "\n"
    out = _common.cap_text(text, 1024)
    assert out["truncated"] is True
    assert out["bytes"] == len(text)
    assert out["text"].endswith("line 01999\n")
    assert out["text"].startswith("line ")  # starts on a whole line
    assert len(out["text"].encode()) <= 1024
    assert out["dropped_bytes"] == len(text) - len(out["text"].encode())


def test_cap_text_never_splits_a_character() -> None:
    text = "é" * 2000  # 2 bytes each, no newlines
    out = _common.cap_text(text, 1025)
    assert out["truncated"] is True
    assert set(out["text"]) == {"é"}
    assert out["dropped_bytes"] + len(out["text"].encode()) == len(text.encode())


# --- env redaction ----------------------------------------------------------------------------


def test_redact_env_keeps_keys() -> None:
    inspect = load_fixture("containers", "inspect")
    out = _common.redact_env(inspect)
    assert out["Config"]["Env"] == [
        f"PATH={REDACTED}",
        f"DB_PASSWORD={REDACTED}",
        f"EMPTY={REDACTED}",
        "FLAG_ONLY",
    ]
    assert fake_secret("s3cr3t-value") in str(inspect)  # input untouched
    assert out["Config"]["Image"] == "nginx:1.27"
    assert _common.redact_env("not a dict") == "not a dict"


def test_redact_compose_list_form_map_form_and_bare_keys() -> None:
    compose = load_fixture("containers", "compose")["compose"]
    secret = fake_secret("s3cr3t-value")
    assert secret in compose
    out = _common.redact_compose_env(compose)
    assert secret not in out
    doc = yaml.safe_load(out)
    assert doc["services"]["web"]["environment"] == [
        f"DB_PASSWORD={REDACTED}",
        f"PLAIN={REDACTED}",
        "BARE",
    ]
    assert doc["services"]["sidecar"]["environment"] == {
        "API_TOKEN": REDACTED,
        "MODE": REDACTED,
        "UNSET": None,
    }
    assert doc["services"]["web"]["image"] == "nginx:1.27"


def test_redact_compose_numbers_and_booleans() -> None:
    out = _common.redact_compose_env(
        "services:\n  a:\n    environment:\n      N: 5\n      B: true\n"
    )
    assert yaml.safe_load(out)["services"]["a"]["environment"] == {"N": REDACTED, "B": REDACTED}


@pytest.mark.parametrize("bad", ["services: [unclosed", "- just\n- a list\n", "key: {a: b"])
def test_redact_compose_refuses_what_it_cannot_parse(bad: str) -> None:
    with pytest.raises(DockhandError) as e:
        _common.redact_compose_env(bad)
    assert e.value.code == "guardrail_blocked"
    assert "not returned" in e.value.message


def test_redact_compose_without_services_or_env() -> None:
    assert _common.redact_compose_env("") == ""
    assert yaml.safe_load(_common.redact_compose_env("version: '3'\n")) == {"version": "3"}


# --- environment defaulting (F-09) ------------------------------------------------------------


@pytest.fixture
async def client() -> AsyncIterator[DockhandClient]:
    c = DockhandClient(DOCKHAND_URL, retry_attempts=1)
    yield c
    await c.aclose()


def context(client: DockhandClient, default_env: int | None = None) -> ToolContext:
    settings = Settings.model_construct(dockhand_default_environment_id=default_env)
    return ToolContext(
        principal=AsyncMock(),
        client=client,
        operations=OperationRegistry(),
        settings=settings,
        progress=AsyncMock(),
    )


async def test_explicit_environment_wins(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = dockhand.get("/api/environments")
    assert await _common.resolve_env(context(client, 8), 7) == (7, [])
    assert route.call_count == 0


async def test_configured_default(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = dockhand.get("/api/environments")
    assert await _common.resolve_env(context(client, 8), None) == (8, [])
    assert route.call_count == 0


async def test_single_environment_is_used_and_reported(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/environments").respond(200, json=load_fixture("environments", "list"))
    env, warnings = await _common.resolve_env(context(client), None)
    assert env == 7
    assert warnings == ["environment_id not given; used the only environment, 7 (env-seven)"]


async def test_several_environments_are_listed(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/environments").respond(200, json=load_fixture("environments", "list-two"))
    with pytest.raises(DockhandError) as e:
        await _common.resolve_env(context(client), None)
    assert e.value.code == "validation_error"
    assert "7 (env-seven), 8 (env-eight)" in e.value.message


@pytest.mark.parametrize("body", [[], {"unexpected": True}])
async def test_no_environments(
    dockhand: respx.MockRouter, client: DockhandClient, body: Any
) -> None:
    dockhand.get("/api/environments").respond(200, json=body)
    with pytest.raises(DockhandError) as e:
        await _common.resolve_env(context(client), None)
    assert e.value.code == "validation_error"


async def test_gather_sections_isolates_dockhand_errors() -> None:
    async def good() -> int:
        return 1

    async def bad() -> int:
        raise DockhandError(403, "dockhand_http_error", "denied")

    results, errors = await _common.gather_sections({"a": good(), "b": bad()})
    assert results == {"a": 1}
    assert errors == {
        "b": {"code": "dockhand_http_error", "message": "denied", "dockhand_status": 403}
    }
    assert _common.section_warnings(errors) == ["b unavailable: denied"]


async def test_gather_sections_propagates_bugs() -> None:
    async def boom() -> int:
        raise KeyError("bug")

    with pytest.raises(KeyError):
        await _common.gather_sections({"a": boom()})


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("2026-01-31", True),
        ("2026-01-31T12:00:00Z", True),
        ("yesterday", False),
        ("2026-13-01", False),
    ],
)
def test_iso_dates(value: str, ok: bool) -> None:
    class M(_common.ToolInput):
        d: _common.IsoDate

    if ok:
        assert M(d=value).d == value
    else:
        with pytest.raises(ValidationError):
            M(d=value)
