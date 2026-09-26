# SPDX-License-Identifier: Apache-2.0
"""Configuration parsing and the docs/SECURITY.md §6 startup rules.

Every rule has a test asserting the exact one-line reason the process exits with.
"""

import logging
import os
import sys
from pathlib import Path

import pytest
from conftest import DOCKHAND_URL, MCP_TOKEN, SetEnv, fake_dh_token

from dockhand_mcp.config import ConfigError, Settings, load_settings
from dockhand_mcp.tools.registry import Profile


def reason() -> str:
    with pytest.raises(ConfigError) as exc:
        load_settings()
    assert "\n" not in exc.value.reason
    return exc.value.reason


# --- defaults (ARCHITECTURE §5) -------------------------------------------------------------


def test_defaults(base_env: SetEnv) -> None:
    base_env()
    s = load_settings()
    assert s.dockhand_url == DOCKHAND_URL
    assert s.dockhand_token is None
    assert s.dockhand_ca_bundle is None
    assert s.dockhand_tls_insecure is False
    assert s.dockhand_default_environment_id is None
    assert s.profile is Profile.READ_ONLY
    assert s.disable_tools == ()
    assert s.transport == "http"
    assert s.bind == "127.0.0.1"
    assert s.port == 8080
    assert s.path == "/mcp"
    assert s.auth_mode == "bearer"
    assert s.allow_unauthenticated is False
    assert s.allowed_hosts == ("localhost", "127.0.0.1")
    assert s.allowed_origins == ()
    assert s.trust_proxy is False
    assert s.rate_limit_per_min == 120
    assert s.default_timeout == 60
    assert s.max_timeout == 300
    assert s.log_level == "info"
    assert s.log_format == "json"
    assert s.guardrails == "strict"
    assert s.guardrail_allow_bind == ()
    assert s.confirm_mode == "auto"
    assert s.destructive_per_min == 10
    assert s.i_understand_admin_over_insecure_tls is False


def test_challenge_key_random_per_process_when_unset(base_env: SetEnv) -> None:
    base_env()
    a, b = load_settings(), load_settings()
    assert len(a.challenge_key_bytes) == 32
    assert a.challenge_key_bytes != b.challenge_key_bytes


def test_phase5_oauth_variables_are_not_parsed(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_RESOURCE_URL="not a url", DOCKHAND_MCP_OAUTH_ISSUER="x")
    s = load_settings()
    assert not any("resource" in f or "oauth_" in f for f in Settings.model_fields)
    assert s.auth_mode == "bearer"


def test_lists_are_comma_separated(base_env: SetEnv) -> None:
    base_env(
        DOCKHAND_MCP_ALLOWED_HOSTS="localhost, mcp.example.test",
        DOCKHAND_MCP_ALLOWED_ORIGINS="https://mcp.example.test",
        DOCKHAND_MCP_DISABLE_TOOLS="dockhand_a,,dockhand_b",
    )
    s = load_settings()
    assert s.allowed_hosts == ("localhost", "mcp.example.test")
    assert s.allowed_origins == ("https://mcp.example.test",)
    assert s.disable_tools == ("dockhand_a", "dockhand_b")


# --- DOCKHAND_URL ---------------------------------------------------------------------------


def test_url_missing(set_env: SetEnv) -> None:
    set_env(DOCKHAND_MCP_TOKEN=MCP_TOKEN)
    assert reason() == "DOCKHAND_URL is required"


@pytest.mark.parametrize(
    "url", ["dockhand.example.test", "ftp://dockhand.example.test", "https://"]
)
def test_url_invalid(base_env: SetEnv, url: str) -> None:
    base_env(DOCKHAND_URL=url)
    assert reason() == "DOCKHAND_URL must be an absolute http:// or https:// URL"


def test_url_with_credentials(base_env: SetEnv) -> None:
    base_env(DOCKHAND_URL="https://user:pw@dockhand.example.test")
    assert reason() == "DOCKHAND_URL must not contain credentials, a query or a fragment"


def test_url_http_without_allow_http(base_env: SetEnv) -> None:
    base_env(DOCKHAND_URL="http://dockhand.example.test")
    assert reason() == "DOCKHAND_URL uses http:// but DOCKHAND_ALLOW_HTTP is not true"


def test_url_http_with_allow_http(base_env: SetEnv) -> None:
    base_env(DOCKHAND_URL="http://dockhand.example.test/", DOCKHAND_ALLOW_HTTP="true")
    assert load_settings().dockhand_url == "http://dockhand.example.test"


# --- MCP authentication ---------------------------------------------------------------------


def test_bearer_without_token(set_env: SetEnv) -> None:
    set_env(DOCKHAND_URL=DOCKHAND_URL)
    assert reason() == (
        "DOCKHAND_MCP_AUTH_MODE=bearer requires DOCKHAND_MCP_TOKEN or DOCKHAND_MCP_TOKEN_FILE"
    )


def test_bearer_token_too_short(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_TOKEN="t" * 42)
    assert reason() == "DOCKHAND_MCP_TOKEN must be at least 43 characters (32 bytes base64url)"


def test_none_over_http_without_allow_unauthenticated(set_env: SetEnv) -> None:
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_AUTH_MODE="none")
    assert reason() == (
        "DOCKHAND_MCP_AUTH_MODE=none over HTTP requires DOCKHAND_MCP_ALLOW_UNAUTHENTICATED=true"
    )


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.0.2.1", "127.0.0.2"])  # noqa: S104
def test_none_over_http_with_non_loopback_bind(set_env: SetEnv, bind: str) -> None:
    set_env(
        DOCKHAND_URL=DOCKHAND_URL,
        DOCKHAND_MCP_AUTH_MODE="none",
        DOCKHAND_MCP_ALLOW_UNAUTHENTICATED="true",
        DOCKHAND_MCP_BIND=bind,
    )
    assert (
        reason()
        == "DOCKHAND_MCP_AUTH_MODE=none over HTTP requires DOCKHAND_MCP_BIND=127.0.0.1 or ::1"
    )


@pytest.mark.parametrize("bind", ["127.0.0.1", "::1"])
def test_none_over_http_on_loopback_is_allowed(set_env: SetEnv, bind: str) -> None:
    set_env(
        DOCKHAND_URL=DOCKHAND_URL,
        DOCKHAND_MCP_AUTH_MODE="none",
        DOCKHAND_MCP_ALLOW_UNAUTHENTICATED="true",
        DOCKHAND_MCP_BIND=bind,
    )
    assert load_settings().auth_mode == "none"


def test_none_over_stdio_is_allowed(set_env: SetEnv) -> None:
    set_env(
        DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_AUTH_MODE="none", DOCKHAND_MCP_TRANSPORT="stdio"
    )
    assert load_settings().transport == "stdio"


def test_stdio_with_oauth(set_env: SetEnv) -> None:
    set_env(
        DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_AUTH_MODE="oauth", DOCKHAND_MCP_TRANSPORT="stdio"
    )
    assert (
        reason() == "DOCKHAND_MCP_TRANSPORT=stdio cannot be used with DOCKHAND_MCP_AUTH_MODE=oauth"
    )


# --- admin over insecure TLS ----------------------------------------------------------------


def test_admin_with_insecure_tls(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_TLS_INSECURE="true")
    assert reason() == (
        "DOCKHAND_MCP_PROFILE=admin with DOCKHAND_TLS_INSECURE=true requires "
        "DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS=true"
    )


def test_admin_with_insecure_tls_and_escape_hatch(base_env: SetEnv) -> None:
    base_env(
        DOCKHAND_MCP_PROFILE="admin",
        DOCKHAND_TLS_INSECURE="true",
        DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS="true",
    )
    assert load_settings().profile is Profile.ADMIN


def test_insecure_tls_warns(base_env: SetEnv, caplog: pytest.LogCaptureFixture) -> None:
    base_env(DOCKHAND_TLS_INSECURE="true")
    with caplog.at_level(logging.WARNING):
        load_settings()
    assert any("DOCKHAND_TLS_INSECURE" in r.getMessage() for r in caplog.records)


# --- enumerations ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("var", "value", "expected"),
    [
        ("DOCKHAND_MCP_PROFILE", "root", "read-only, operator, admin"),
        ("DOCKHAND_MCP_TRANSPORT", "sse", "http, stdio"),
        ("DOCKHAND_MCP_AUTH_MODE", "basic", "bearer, oauth, none"),
        ("DOCKHAND_MCP_LOG_LEVEL", "trace", "debug, info, warning, error"),
        ("DOCKHAND_MCP_LOG_FORMAT", "xml", "json, text"),
        ("DOCKHAND_MCP_GUARDRAILS", "off", "strict, warn"),
        ("DOCKHAND_MCP_CONFIRM_MODE", "none", "auto, elicitation, param"),
    ],
)
def test_enum_values(base_env: SetEnv, var: str, value: str, expected: str) -> None:
    base_env(**{var: value})
    assert reason() == f"{var} must be one of: {expected}"


@pytest.mark.parametrize(
    ("var", "value", "lo", "hi"),
    [
        ("DOCKHAND_MCP_PORT", "0", 1, 65535),
        ("DOCKHAND_MCP_PORT", "http", 1, 65535),
        ("DOCKHAND_MCP_RATE_LIMIT_PER_MIN", "0", 1, 100000),
        ("DOCKHAND_MCP_DESTRUCTIVE_PER_MIN", "0", 1, 1000),
        ("DOCKHAND_MCP_DESTRUCTIVE_PER_MIN", "1001", 1, 1000),
        ("DOCKHAND_MCP_MAX_TIMEOUT", "301", 1, 300),
        ("DOCKHAND_DEFAULT_ENVIRONMENT_ID", "-7", 1, 2147483647),
    ],
)
def test_integer_ranges(base_env: SetEnv, var: str, value: str, lo: int, hi: int) -> None:
    base_env(**{var: value})
    assert reason() == f"{var} must be an integer between {lo} and {hi}"


def test_boolean_values(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_TRUST_PROXY="maybe")
    assert reason() == "DOCKHAND_MCP_TRUST_PROXY must be true or false"


def test_default_timeout_above_max(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_DEFAULT_TIMEOUT="120", DOCKHAND_MCP_MAX_TIMEOUT="90")
    assert reason() == "DOCKHAND_MCP_DEFAULT_TIMEOUT must not exceed DOCKHAND_MCP_MAX_TIMEOUT"


# --- network settings -----------------------------------------------------------------------


def test_bind_must_be_ip(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_BIND="localhost")
    assert reason() == "DOCKHAND_MCP_BIND must be an IP address"


@pytest.mark.parametrize("path", ["mcp", "/", "/healthz", "/mcp?x=1", "/a//b"])
def test_path(base_env: SetEnv, path: str) -> None:
    base_env(DOCKHAND_MCP_PATH=path)
    assert reason() == "DOCKHAND_MCP_PATH must be a URL path like /mcp, other than /healthz"


@pytest.mark.parametrize("host", ["*", "*.example.test", "host/path", "a b"])
def test_allowed_hosts(base_env: SetEnv, host: str) -> None:
    base_env(DOCKHAND_MCP_ALLOWED_HOSTS=host)
    assert reason() == f"DOCKHAND_MCP_ALLOWED_HOSTS entry {host!r} is not a host name or address"


@pytest.mark.parametrize("origin", ["*", "null", "mcp.example.test", "https://mcp.example.test/x"])
def test_allowed_origins(base_env: SetEnv, origin: str) -> None:
    base_env(DOCKHAND_MCP_ALLOWED_ORIGINS=origin)
    assert reason() == (
        f"DOCKHAND_MCP_ALLOWED_ORIGINS entry {origin!r} must be an origin like https://host[:port]"
    )


def test_disable_tools_names(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_DISABLE_TOOLS="dockhand_ok,Bad-Name")
    assert reason() == "DOCKHAND_MCP_DISABLE_TOOLS entry 'Bad-Name' is not a tool name"


def test_ca_bundle_missing(base_env: SetEnv, tmp_path: Path) -> None:
    missing = tmp_path / "ca.pem"
    base_env(DOCKHAND_CA_BUNDLE=str(missing))
    assert reason() == f"DOCKHAND_CA_BUNDLE: file not found: {missing}"


# --- guardrail allow-bind (SECURITY §5) -----------------------------------------------------


def test_allow_bind_normalised(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND="/srv/media/, /srv/./data,/root")
    assert load_settings().guardrail_allow_bind == ("/srv/media", "/srv/data", "/root")


@pytest.mark.parametrize(
    ("entry", "denied"),
    [
        ("/", "/"),
        ("/etc", "/etc"),
        ("/etc/myapp", "/etc"),
        ("/srv/../etc", "/etc"),
        ("/var", "/var/lib/docker"),
        ("/var/run", "/var/run/docker.sock"),
        ("/run/docker.sock", "/run/docker.sock"),
        ("/var/lib/docker/volumes", "/var/lib/docker"),
        ("/proc", "/proc"),
        ("/sys/fs", "/sys"),
        ("/dev", "/dev"),
        ("/boot", "/boot"),
    ],
)
def test_allow_bind_non_configurable_deny_set(base_env: SetEnv, entry: str, denied: str) -> None:
    base_env(DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND=entry)
    assert reason() == (
        f"DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND entry {entry!r} overlaps {denied}, "
        "which can never be allowed"
    )


@pytest.mark.parametrize("entry", ["srv/media", "~/media", "./data"])
def test_allow_bind_must_be_absolute(base_env: SetEnv, entry: str) -> None:
    base_env(DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND=entry)
    assert reason() == f"DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND entry {entry!r} must be an absolute path"


# --- challenge key --------------------------------------------------------------------------


def test_challenge_key_too_short(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_CHALLENGE_KEY="k" * 31)
    assert reason() == "DOCKHAND_MCP_CHALLENGE_KEY must be at least 32 bytes"


def test_challenge_key_accepted(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_CHALLENGE_KEY="k" * 32)
    assert load_settings().challenge_key_bytes == b"k" * 32


# --- *_FILE variants ------------------------------------------------------------------------


def test_token_file_strips_one_trailing_newline(set_env: SetEnv, tmp_path: Path) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_bytes((MCP_TOKEN + "\n").encode())
    os.chmod(token_file, 0o600)
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    s = load_settings()
    assert s.mcp_token is not None
    assert s.mcp_token.get_secret_value() == MCP_TOKEN


def test_token_file_strips_only_one_newline(set_env: SetEnv, tmp_path: Path) -> None:
    token_file = tmp_path / "dockhand_token"
    token_file.write_bytes(fake_dh_token("abc").encode() + b"\n\n")
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN=MCP_TOKEN)
    set_env(DOCKHAND_TOKEN_FILE=str(token_file))
    s = load_settings()
    assert s.dockhand_token is not None
    assert s.dockhand_token.get_secret_value() == fake_dh_token("abc") + "\n"


def test_token_file_short_token_is_rejected(set_env: SetEnv, tmp_path: Path) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_bytes(b"short\n")
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    assert reason() == "DOCKHAND_MCP_TOKEN must be at least 43 characters (32 bytes base64url)"


def test_token_file_unreadable(set_env: SetEnv, tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(missing))
    assert reason() == f"DOCKHAND_MCP_TOKEN_FILE: cannot read {missing}"


def test_value_and_file_both_set(base_env: SetEnv, tmp_path: Path) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_text(MCP_TOKEN)
    base_env(DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    assert reason() == "set only one of DOCKHAND_MCP_TOKEN and DOCKHAND_MCP_TOKEN_FILE"


def test_challenge_key_file(base_env: SetEnv, tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(b"k" * 32 + b"\n")
    base_env(DOCKHAND_MCP_CHALLENGE_KEY_FILE=str(key_file))
    assert load_settings().challenge_key_bytes == b"k" * 32


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_token_file_mode_wider_than_0600_warns(
    set_env: SetEnv, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_text(MCP_TOKEN)
    os.chmod(token_file, 0o644)
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    with caplog.at_level(logging.INFO):
        load_settings()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "DOCKHAND_MCP_TOKEN_FILE" in r.getMessage() and "0644" in r.getMessage() for r in warnings
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_token_file_mode_0600_does_not_warn(
    set_env: SetEnv, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_text(MCP_TOKEN)
    os.chmod(token_file, 0o600)
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    with caplog.at_level(logging.INFO):
        load_settings()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows has no meaningful mode bits")
def test_token_file_mode_check_skipped_on_windows(
    set_env: SetEnv, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_text(MCP_TOKEN)
    set_env(DOCKHAND_URL=DOCKHAND_URL, DOCKHAND_MCP_TOKEN_FILE=str(token_file))
    with caplog.at_level(logging.INFO):
        load_settings()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("skipped" in r.getMessage() for r in caplog.records)


# --- masking for `check` --------------------------------------------------------------------


def test_masked_never_contains_secrets(base_env: SetEnv) -> None:
    dh_token = "dh_" + "s" * 40
    key = "c" * 32
    base_env(DOCKHAND_TOKEN=dh_token, DOCKHAND_MCP_CHALLENGE_KEY=key)
    masked = load_settings().masked()
    text = repr(masked)
    assert dh_token not in text
    assert MCP_TOKEN not in text
    assert key not in text
    assert masked["DOCKHAND_TOKEN"] == "dh_… (set)"
    assert masked["DOCKHAND_MCP_TOKEN"] == "*** (set)"
    assert masked["DOCKHAND_MCP_CHALLENGE_KEY"] == "*** (set)"
    assert masked["DOCKHAND_URL"] == DOCKHAND_URL
    assert masked["DOCKHAND_MCP_PROFILE"] == "read-only"
