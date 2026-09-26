# SPDX-License-Identifier: Apache-2.0
"""Configuration from environment variables (ARCHITECTURE §5) and startup validation (SECURITY §6).

Every problem surfaces as a `ConfigError` whose `reason` is one line naming the variable. The
DockHand reachability checks of SECURITY §6 run later, against the live server (S1).
"""

import ipaddress
import logging
import os
import posixpath
import re
import secrets
import stat
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import (
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# SECURITY §5: bind sources no DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND entry may ever cover; one list,
# kept with the guardrails that enforce it.
from dockhand_mcp.guardrails.compose import NON_CONFIGURABLE_DENY
from dockhand_mcp.tools.registry import Profile

log = logging.getLogger(__name__)

MIN_MCP_TOKEN_CHARS: Final = 43  # 32 bytes, base64url-encoded
MIN_CHALLENGE_KEY_BYTES: Final = 32
LOOPBACK_BINDS: Final = frozenset({"127.0.0.1", "::1"})


_HOST: Final = re.compile(
    r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::[0-9]{1,5})?$"
)
_ORIGIN: Final = re.compile(
    r"^https?://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
    r"(?::[0-9]{1,5})?$"
)
_PATH: Final = re.compile(r"^(?:/[A-Za-z0-9._~-]+)+$")
_TOOL: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# Enumerated values, in the order they are documented.
PROFILES: Final = tuple(p.value for p in Profile)
TRANSPORTS: Final = ("http", "stdio")
AUTH_MODES: Final = ("bearer", "oauth", "none")
LOG_LEVELS: Final = ("debug", "info", "warning", "error")
LOG_FORMATS: Final = ("json", "text")
GUARDRAIL_MODES: Final = ("strict", "warn")
CONFIRM_MODES: Final = ("auto", "elicitation", "param")

# (value variable, file variable) pairs for secrets.
SECRET_FILES: Final = (
    ("DOCKHAND_TOKEN", "DOCKHAND_TOKEN_FILE"),
    ("DOCKHAND_MCP_TOKEN", "DOCKHAND_MCP_TOKEN_FILE"),
    ("DOCKHAND_MCP_CHALLENGE_KEY", "DOCKHAND_MCP_CHALLENGE_KEY_FILE"),
)


class ConfigError(Exception):
    """A configuration problem; `reason` is a single line suitable for printing before exit."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _comma_list(value: object) -> tuple[str, ...]:
    if isinstance(value, tuple):
        return value
    return tuple(item.strip() for item in str(value).split(",") if item.strip())


def _env(var: str, **kwargs: Any) -> Any:
    """Declare a field read from environment variable `var`."""
    return Field(validation_alias=var, **kwargs)


_ENUMS: Final[dict[str, tuple[str, ...]]] = {
    "profile": PROFILES,
    "transport": TRANSPORTS,
    "auth_mode": AUTH_MODES,
    "log_level": LOG_LEVELS,
    "log_format": LOG_FORMATS,
    "guardrails": GUARDRAIL_MODES,
    "confirm_mode": CONFIRM_MODES,
}

_RANGES: Final[dict[str, tuple[int, int]]] = {
    "port": (1, 65535),
    "rate_limit_per_min": (1, 100_000),
    "default_timeout": (1, 300),
    "max_timeout": (1, 300),
    "destructive_per_min": (1, 1000),
    "dockhand_default_environment_id": (1, 2**31 - 1),
}

_BOOLS: Final = (
    "dockhand_allow_http",
    "dockhand_tls_insecure",
    "allow_unauthenticated",
    "trust_proxy",
    "i_understand_admin_over_insecure_tls",
)


class Settings(BaseSettings):
    """Effective configuration. Field names are internal; the environment variable is the API."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_ignore_empty=True,
        extra="ignore",
        populate_by_name=False,
    )

    # DockHand connection
    dockhand_url: str | None = _env("DOCKHAND_URL", default=None)
    dockhand_allow_http: bool = _env("DOCKHAND_ALLOW_HTTP", default=False)
    dockhand_token: SecretStr | None = _env("DOCKHAND_TOKEN", default=None)
    dockhand_token_file: Path | None = _env("DOCKHAND_TOKEN_FILE", default=None)
    dockhand_ca_bundle: Path | None = _env("DOCKHAND_CA_BUNDLE", default=None)
    dockhand_tls_insecure: bool = _env("DOCKHAND_TLS_INSECURE", default=False)
    dockhand_default_environment_id: int | None = _env(
        "DOCKHAND_DEFAULT_ENVIRONMENT_ID", default=None
    )

    # Tool exposure
    profile: Profile = _env("DOCKHAND_MCP_PROFILE", default=Profile.READ_ONLY)
    disable_tools: Annotated[tuple[str, ...], NoDecode] = _env(
        "DOCKHAND_MCP_DISABLE_TOOLS", default=()
    )

    # Transport
    transport: Literal["http", "stdio"] = _env("DOCKHAND_MCP_TRANSPORT", default="http")
    bind: str = _env("DOCKHAND_MCP_BIND", default="127.0.0.1")
    port: int = _env("DOCKHAND_MCP_PORT", default=8080)
    path: str = _env("DOCKHAND_MCP_PATH", default="/mcp")

    # MCP-side authentication
    auth_mode: Literal["bearer", "oauth", "none"] = _env("DOCKHAND_MCP_AUTH_MODE", default="bearer")
    mcp_token: SecretStr | None = _env("DOCKHAND_MCP_TOKEN", default=None)
    mcp_token_file: Path | None = _env("DOCKHAND_MCP_TOKEN_FILE", default=None)
    allow_unauthenticated: bool = _env("DOCKHAND_MCP_ALLOW_UNAUTHENTICATED", default=False)

    # HTTP hardening
    allowed_hosts: Annotated[tuple[str, ...], NoDecode] = _env(
        "DOCKHAND_MCP_ALLOWED_HOSTS", default=("localhost", "127.0.0.1")
    )
    allowed_origins: Annotated[tuple[str, ...], NoDecode] = _env(
        "DOCKHAND_MCP_ALLOWED_ORIGINS", default=()
    )
    trust_proxy: bool = _env("DOCKHAND_MCP_TRUST_PROXY", default=False)
    rate_limit_per_min: int = _env("DOCKHAND_MCP_RATE_LIMIT_PER_MIN", default=120)

    # Waits
    default_timeout: int = _env("DOCKHAND_MCP_DEFAULT_TIMEOUT", default=60)
    max_timeout: int = _env("DOCKHAND_MCP_MAX_TIMEOUT", default=300)

    # Logging
    log_level: Literal["debug", "info", "warning", "error"] = _env(
        "DOCKHAND_MCP_LOG_LEVEL", default="info"
    )
    log_format: Literal["json", "text"] = _env("DOCKHAND_MCP_LOG_FORMAT", default="json")

    # Guardrails and destructive-call approval (implemented in S3a / S3b)
    guardrails: Literal["strict", "warn"] = _env("DOCKHAND_MCP_GUARDRAILS", default="strict")
    guardrail_allow_bind: Annotated[tuple[str, ...], NoDecode] = _env(
        "DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND", default=()
    )
    confirm_mode: Literal["auto", "elicitation", "param"] = _env(
        "DOCKHAND_MCP_CONFIRM_MODE", default="auto"
    )
    challenge_key: SecretStr | None = _env("DOCKHAND_MCP_CHALLENGE_KEY", default=None)
    challenge_key_file: Path | None = _env("DOCKHAND_MCP_CHALLENGE_KEY_FILE", default=None)
    destructive_per_min: int = _env("DOCKHAND_MCP_DESTRUCTIVE_PER_MIN", default=10)

    i_understand_admin_over_insecure_tls: bool = _env(
        "DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS", default=False
    )

    # Filled in after validation: the configured challenge key, or a random per-process one.
    _challenge_key_bytes: bytes = PrivateAttr(default=b"")

    @property
    def challenge_key_bytes(self) -> bytes:
        return self._challenge_key_bytes

    # --- field validators -------------------------------------------------------------------

    @field_validator(*_BOOLS, mode="before")
    @classmethod
    def _bool(cls, value: object, info: ValidationInfo) -> bool:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "1", "yes", "on"):
            return True
        if text in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"{_var(info.field_name)} must be true or false")

    @field_validator(*_ENUMS, mode="before")
    @classmethod
    def _enum(cls, value: object, info: ValidationInfo) -> str:
        allowed = _ENUMS[_name(info)]
        if isinstance(value, StrEnum):
            value = value.value
        if isinstance(value, str) and value.strip().lower() in allowed:
            return value.strip().lower()
        raise ValueError(f"{_var(info.field_name)} must be one of: {', '.join(allowed)}")

    @field_validator(*_RANGES, mode="before")
    @classmethod
    def _range(cls, value: object, info: ValidationInfo) -> int | None:
        if value is None:
            return None
        lo, hi = _RANGES[_name(info)]
        try:
            number = value if type(value) is int else int(str(value).strip(), 10)
        except ValueError:
            number = lo - 1
        if not lo <= number <= hi:
            raise ValueError(f"{_var(info.field_name)} must be an integer between {lo} and {hi}")
        return number

    @field_validator("bind", mode="before")
    @classmethod
    def _bind(cls, value: object) -> str:
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            raise ValueError("DOCKHAND_MCP_BIND must be an IP address") from None

    @field_validator("path", mode="before")
    @classmethod
    def _path(cls, value: object) -> str:
        text = str(value).strip()
        if not _PATH.match(text) or text == "/healthz":
            raise ValueError("DOCKHAND_MCP_PATH must be a URL path like /mcp, other than /healthz")
        return text

    @field_validator("disable_tools", mode="before")
    @classmethod
    def _disable_tools(cls, value: object) -> tuple[str, ...]:
        items = _comma_list(value)
        for item in items:
            if not _TOOL.match(item):
                raise ValueError(f"DOCKHAND_MCP_DISABLE_TOOLS entry {item!r} is not a tool name")
        return items

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _allowed_hosts(cls, value: object) -> tuple[str, ...]:
        items = _comma_list(value)
        for item in items:
            if not _HOST.match(item):
                raise ValueError(
                    f"DOCKHAND_MCP_ALLOWED_HOSTS entry {item!r} is not a host name or address"
                )
        return items

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _allowed_origins(cls, value: object) -> tuple[str, ...]:
        items = _comma_list(value)
        for item in items:
            if not _ORIGIN.match(item):
                raise ValueError(
                    f"DOCKHAND_MCP_ALLOWED_ORIGINS entry {item!r} "
                    "must be an origin like https://host[:port]"
                )
        return items

    @field_validator("guardrail_allow_bind", mode="before")
    @classmethod
    def _allow_bind(cls, value: object) -> tuple[str, ...]:
        return tuple(_normalise_allow_bind(item) for item in _comma_list(value))

    # --- cross-field rules ------------------------------------------------------------------

    @model_validator(mode="after")
    def _resolve(self) -> Settings:
        self.dockhand_token = _secret_from_file(
            self.dockhand_token, self.dockhand_token_file, *SECRET_FILES[0]
        )
        self.mcp_token = _secret_from_file(self.mcp_token, self.mcp_token_file, *SECRET_FILES[1])
        self.challenge_key = _secret_from_file(
            self.challenge_key, self.challenge_key_file, *SECRET_FILES[2]
        )
        if self.challenge_key is None:
            self._challenge_key_bytes = secrets.token_bytes(MIN_CHALLENGE_KEY_BYTES)
        else:
            self._challenge_key_bytes = self.challenge_key.get_secret_value().encode("utf-8")
        return self

    # --- output -----------------------------------------------------------------------------

    def secret_values(self) -> list[str]:
        """Configured secret values, for log redaction."""
        values = [self.dockhand_token, self.mcp_token, self.challenge_key]
        return [v.get_secret_value() for v in values if v is not None]

    def masked(self) -> dict[str, Any]:
        """The effective configuration keyed by environment variable, with secrets masked."""
        out: dict[str, Any] = {}
        for name, info in type(self).model_fields.items():
            var = info.validation_alias
            if not isinstance(var, str) or var.endswith("_FILE"):
                continue
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                prefix = "dh_" if value.get_secret_value().startswith("dh_") else ""
                value = f"{prefix}… (set)" if prefix else "*** (set)"
            elif name == "challenge_key" and value is None:
                value = "(random per process)"
            elif isinstance(value, Profile):
                value = value.value
            elif isinstance(value, Path):
                value = str(value)
            elif isinstance(value, tuple):
                value = list(value)
            out[var] = value
        return out


def _var(field_name: str | None) -> str:
    """The environment variable behind a field, for error messages."""
    alias = Settings.model_fields[str(field_name)].validation_alias
    return alias if isinstance(alias, str) else str(field_name)


def _name(info: ValidationInfo) -> str:
    return str(info.field_name)


def _normalise_allow_bind(entry: str) -> str:
    var = "DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND"
    if not entry.startswith("/") or "\\" in entry or "\x00" in entry:
        raise ValueError(f"{var} entry {entry!r} must be an absolute path")
    path = posixpath.normpath(entry)
    path = "/" if path == "//" else path
    for denied in NON_CONFIGURABLE_DENY:
        covers = denied == path or denied.startswith(path.rstrip("/") + "/")
        inside = denied != "/" and path.startswith(denied + "/")
        if covers or inside:
            raise ValueError(f"{var} entry {entry!r} overlaps {denied}, which can never be allowed")
    return path


def _secret_from_file(
    value: SecretStr | None, file: Path | None, var: str, file_var: str
) -> SecretStr | None:
    if file is None:
        return value
    if value is not None:
        raise ValueError(f"set only one of {var} and {file_var}")
    try:
        raw = file.read_bytes()
        text = raw.decode("utf-8")
    except OSError, UnicodeDecodeError:
        raise ValueError(f"{file_var}: cannot read {file}") from None
    _check_file_mode(file, file_var)
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    return SecretStr(text) if text else None


def _check_file_mode(file: Path, file_var: str) -> None:
    if sys.platform == "win32":
        log.info("%s: file permission check skipped on Windows", file_var)
        return
    mode = stat.S_IMODE(os.stat(file).st_mode)
    if mode & 0o177:
        log.warning(
            "%s: %s has mode %04o, wider than 0600; restrict it to the server's user",
            file_var,
            file,
            mode,
        )


def _check_url(url: str | None, allow_http: bool) -> str:
    if url is None:
        raise ConfigError("DOCKHAND_URL is required")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("DOCKHAND_URL must be an absolute http:// or https:// URL")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ConfigError("DOCKHAND_URL must not contain credentials, a query or a fragment")
    if parts.scheme == "http" and not allow_http:
        raise ConfigError("DOCKHAND_URL uses http:// but DOCKHAND_ALLOW_HTTP is not true")
    return url.strip().rstrip("/")


def validate_startup(s: Settings) -> None:
    """Apply the SECURITY §6 rules that need no network access. Raises `ConfigError`."""
    s.dockhand_url = _check_url(s.dockhand_url, s.dockhand_allow_http)

    if s.dockhand_ca_bundle is not None and not s.dockhand_ca_bundle.is_file():
        raise ConfigError(f"DOCKHAND_CA_BUNDLE: file not found: {s.dockhand_ca_bundle}")

    if s.auth_mode == "bearer":
        if s.mcp_token is None:
            raise ConfigError(
                "DOCKHAND_MCP_AUTH_MODE=bearer requires "
                "DOCKHAND_MCP_TOKEN or DOCKHAND_MCP_TOKEN_FILE"
            )
        if len(s.mcp_token.get_secret_value()) < MIN_MCP_TOKEN_CHARS:
            raise ConfigError(
                f"DOCKHAND_MCP_TOKEN must be at least {MIN_MCP_TOKEN_CHARS} characters "
                "(32 bytes base64url)"
            )

    if s.auth_mode == "none" and s.transport == "http":
        if not s.allow_unauthenticated:
            raise ConfigError(
                "DOCKHAND_MCP_AUTH_MODE=none over HTTP requires "
                "DOCKHAND_MCP_ALLOW_UNAUTHENTICATED=true"
            )
        if s.bind not in LOOPBACK_BINDS:
            raise ConfigError(
                "DOCKHAND_MCP_AUTH_MODE=none over HTTP requires DOCKHAND_MCP_BIND=127.0.0.1 or ::1"
            )

    if s.transport == "stdio" and s.auth_mode == "oauth":
        raise ConfigError(
            "DOCKHAND_MCP_TRANSPORT=stdio cannot be used with DOCKHAND_MCP_AUTH_MODE=oauth"
        )

    if (
        s.profile is Profile.ADMIN
        and s.dockhand_tls_insecure
        and not s.i_understand_admin_over_insecure_tls
    ):
        raise ConfigError(
            "DOCKHAND_MCP_PROFILE=admin with DOCKHAND_TLS_INSECURE=true requires "
            "DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS=true"
        )

    if len(s.challenge_key_bytes) < MIN_CHALLENGE_KEY_BYTES:
        raise ConfigError(
            f"DOCKHAND_MCP_CHALLENGE_KEY must be at least {MIN_CHALLENGE_KEY_BYTES} bytes"
        )

    if s.default_timeout > s.max_timeout:
        raise ConfigError("DOCKHAND_MCP_DEFAULT_TIMEOUT must not exceed DOCKHAND_MCP_MAX_TIMEOUT")

    if s.dockhand_tls_insecure:
        log.warning("DOCKHAND_TLS_INSECURE=true: TLS certificate verification of DockHand is off")


def _reason(exc: ValidationError) -> str:
    err = exc.errors(include_url=False)[0]
    ctx = err.get("ctx") or {}
    if "error" in ctx:
        return str(ctx["error"]).splitlines()[0]
    loc = ".".join(str(p) for p in err["loc"]) or "configuration"
    return f"{loc}: {err['msg']}".splitlines()[0]


def load_settings() -> Settings:
    """Read the environment, apply the startup rules, and return the effective settings."""
    try:
        settings = Settings()
    except ValidationError as exc:
        raise ConfigError(_reason(exc)) from None
    validate_startup(settings)
    return settings
