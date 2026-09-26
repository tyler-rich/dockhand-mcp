# SPDX-License-Identifier: Apache-2.0
"""guardrails/secrets.py: the key-based redaction every tool's data passes through."""

import pytest
from conftest import fake_secret

from dockhand_mcp.guardrails.secrets import (
    REDACTED,
    SENSITIVE_KEYS,
    is_sensitive_key,
    redact_sensitive_keys,
)


@pytest.mark.parametrize(
    "key",
    [
        "webhookSecret",
        "secret",
        "password",
        "passwd",
        "token",
        "apiKey",
        "api_key",
        "privateKey",
        "private_key",
        "tlsKey",
        "clientSecret",
        "accessKey",
        "secretKey",
        "credentials",
        # case-insensitive, and anything ending in secret/token/password
        "PASSWORD",
        "dbPassword",
        "refresh_token",
        "hawserToken",
        "SHARED-SECRET",
        "com.example.api-token",
    ],
)
def test_sensitive(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "key",
        "value",
        "secretProvider",
        "injectedSecretKeys",
        "hasCredentials",
        "credentialId",
        "tokens_used",
        "name",
        "passwordPolicy",
    ],
)
def test_not_sensitive_by_name(key: str) -> None:
    assert not is_sensitive_key(key)


def test_flags_match_by_name_but_are_exempt_by_value() -> None:
    assert is_sensitive_key("isSecret")
    assert is_sensitive_key("hasHawserToken")
    assert redact_sensitive_keys({"isSecret": True, "hasHawserToken": False}) == {
        "isSecret": True,
        "hasHawserToken": False,
    }


def test_key_list_is_lowercased_once() -> None:
    assert all(k == k.lower() for k in SENSITIVE_KEYS)
    assert "webhooksecret" in SENSITIVE_KEYS


def test_nested_dicts_and_lists() -> None:
    value = fake_secret("nested-value")
    data = {
        "items": [
            {"id": 1, "webhookSecret": value, "url": "https://git.example.test/r.git"},
            {"id": 2, "webhookSecret": None},
        ],
        "deep": {"a": [{"b": {"apiKey": value, "keep": value}}]},
        "credentials": {"user": "u", "password": value},
    }
    out = redact_sensitive_keys(data)
    assert out["items"][0] == {"id": 1, "webhookSecret": REDACTED, "url": data["items"][0]["url"]}
    assert out["items"][1] == {"id": 2, "webhookSecret": None}  # null stays null: "not set"
    assert out["deep"]["a"][0]["b"] == {"apiKey": REDACTED, "keep": value}
    assert out["credentials"] == REDACTED  # a whole sensitive subtree goes
    assert value in str(data)  # the input is not modified
    assert value not in str({k: v for k, v in out.items() if k != "deep"})


def test_booleans_and_nulls_are_left_alone() -> None:
    data = {"hasHawserToken": True, "isSecret": False, "token": None, "password": 0}
    assert redact_sensitive_keys(data) == {
        "hasHawserToken": True,
        "isSecret": False,
        "token": None,
        "password": REDACTED,
    }


def test_scalars_and_non_string_keys_pass_through() -> None:
    assert redact_sensitive_keys("text") == "text"
    assert redact_sensitive_keys(3) == 3
    assert redact_sensitive_keys({1: "x"}) == {1: "x"}
    assert redact_sensitive_keys([("token", "v")]) == [["token", "v"]]
