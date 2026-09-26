# SPDX-License-Identifier: Apache-2.0
"""`redact()` and free-text truncation (D-009, SECURITY §2 log injection)."""

import io
import json
import logging

import pytest
from conftest import MCP_TOKEN, fake_dh_token, fake_secret

from dockhand_mcp.logging import MAX_MESSAGE_CHARS, configure_logging, redact, truncate

# Fake secrets are built at runtime and joined to their keys in f-strings, so no line of
# this file is itself shaped like a credential.
DH = fake_dh_token()
DH_BODY = DH.removeprefix("dh_")
PW = fake_secret()
CRED = fake_secret("abc.def-ghi")
BASIC = fake_secret("dXNlcjpwYXNz")
RAW = fake_secret("rawtoken123")
LONG = fake_secret("supersecretvalue")


@pytest.mark.parametrize(
    "text",
    [
        DH,
        f"token {DH} end",
        f'{{"value":"{DH}"}}',
        f"https://dockhand.example.test/api?t={DH}#x",
        f"prefix-{DH}",
    ],
)
def test_dockhand_tokens_anywhere(text: str) -> None:
    out = redact(text)
    assert DH_BODY not in out
    assert "dh_***" in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"Authorization: Bearer {CRED}", "Authorization: Bearer ***"),
        (f"authorization: Basic {BASIC}", "authorization: Basic ***"),
        (f'{{"Authorization": "{RAW}"}}', '{"Authorization": "***"}'),
        (f"authorization={RAW}", "authorization=***"),
        (f"bearer\t{PW}", "bearer ***"),
    ],
)
def test_authorization_values(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_configured_mcp_token_is_redacted_by_default() -> None:
    configure_logging("info", "json", stream=io.StringIO(), secrets=[MCP_TOKEN])
    out = redact(f"client sent {MCP_TOKEN} twice: {MCP_TOKEN}")
    assert MCP_TOKEN not in out
    assert out == "client sent *** twice: ***"


def test_explicit_secrets_are_redacted() -> None:
    assert redact(f"key={LONG}!", secrets=[LONG]) == "key=***!"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"token={RAW}", "token=***"),
        (f"password={PW}", "password=***"),
        (f"user=bob&password={PW}&x=1", "user=bob&password=***&x=1"),
        (f"PASSWORD={PW} next", "PASSWORD=*** next"),
        (f"access_token={RAW}; path=/", "access_token=***; path=/"),
        (f"DOCKHAND_TOKEN={RAW}", "DOCKHAND_TOKEN=***"),
    ],
)
def test_token_and_password_pairs(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_plain_text_is_untouched() -> None:
    text = "container web-1 restarted (exit 0) after 3.2s"
    assert redact(text) == text


def test_truncate() -> None:
    assert truncate("short") == "short"
    long = "a" * (MAX_MESSAGE_CHARS + 100)
    out = truncate(long)
    assert len(out) == MAX_MESSAGE_CHARS + 1
    assert out.endswith("…")
    assert truncate("a" * MAX_MESSAGE_CHARS) == "a" * MAX_MESSAGE_CHARS


def test_log_fields_are_truncated_and_redacted() -> None:
    stream = io.StringIO()
    configure_logging("info", "json", stream=stream)
    logging.getLogger("x").info("m", extra={"detail": f"password={PW} " + "b" * 2000})
    rec = json.loads(stream.getvalue())
    assert PW not in rec["detail"]
    assert len(rec["detail"]) <= MAX_MESSAGE_CHARS + 1
