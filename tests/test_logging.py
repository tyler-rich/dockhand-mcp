# SPDX-License-Identifier: Apache-2.0
"""JSON-lines logging and redaction (D-009)."""

import io
import json
import logging

import respx
from conftest import DOCKHAND_URL, fake_dh_token, fake_secret

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.logging import configure_logging, redact

DH = fake_dh_token()
PW = fake_secret("hunter2hunter2")
CRED = fake_secret("abc.def-ghi")
LONG = fake_secret("supersecretvalue")


def test_redacts_dockhand_tokens() -> None:
    assert redact(f"token {DH} end") == "token dh_*** end"


def test_redacts_bearer_credentials() -> None:
    assert redact(f"Authorization: Bearer {CRED}") == "Authorization: Bearer ***"
    assert redact("bearer\tsecret") == "bearer ***"


def test_redacts_configured_secrets() -> None:
    assert redact(f"key={LONG}!", secrets=[LONG]) == "key=***!"


def test_ignores_empty_secret() -> None:
    assert redact("abc", secrets=[""]) == "abc"


def test_json_lines_to_the_given_stream() -> None:
    stream = io.StringIO()
    configure_logging("info", "json", stream=stream, secrets=[PW])
    log = logging.getLogger("dockhand_mcp.test")
    log.info(f"password {PW} and {fake_dh_token('tok')}\nsecond line", extra={"tool": "dockhand_x"})
    log.debug("not emitted")
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["level"] == "info"
    assert rec["logger"] == "dockhand_mcp.test"
    assert rec["message"] == "password *** and dh_***\nsecond line"
    assert rec["tool"] == "dockhand_x"
    assert "ts" in rec


def test_extra_fields_are_redacted() -> None:
    stream = io.StringIO()
    configure_logging("info", "json", stream=stream)
    logging.getLogger("x").info("m", extra={"detail": "Bearer abc"})
    assert json.loads(stream.getvalue())["detail"] == "Bearer ***"


def test_long_messages_are_truncated() -> None:
    stream = io.StringIO()
    configure_logging("info", "json", stream=stream)
    logging.getLogger("x").info("a" * 2000)
    assert len(json.loads(stream.getvalue())["message"]) <= 513


def test_text_format_is_redacted() -> None:
    stream = io.StringIO()
    configure_logging("info", "text", stream=stream)
    logging.getLogger("x").warning("Bearer abc")
    assert "abc" not in stream.getvalue()
    assert "Bearer ***" in stream.getvalue()


async def test_http_libraries_do_not_log_request_urls(dockhand: respx.MockRouter) -> None:
    # httpx logs every request's full URL, query values included, at INFO. Only our own
    # one-line-per-call record (query values stripped) may appear.
    stream = io.StringIO()
    configure_logging("debug", "json", stream=stream)
    dockhand.get("/api/containers").respond(200, json=[])
    client = DockhandClient(DOCKHAND_URL)
    await client.get_json("/api/containers", params={"env": 7, "search": "secret-name"})
    await client.aclose()
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert "secret-name" not in stream.getvalue()
    assert [r["logger"] for r in records if "dockhand" not in r["logger"]] == []
    assert [r["message"] for r in records] == ["dockhand_request"]
