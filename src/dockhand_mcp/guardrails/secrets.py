# SPDX-License-Identifier: Apache-2.0
"""Key-based secret redaction applied to every tool's `data` before it is returned.

Any mapping key, at any depth, whose name is sensitive has its value replaced with
`REDACTED`; the key stays, so the model can tell "set" from "not set". A key is sensitive when,
compared case-insensitively, it is one of `SENSITIVE_KEYS` or ends in one of
`SENSITIVE_SUFFIXES`. Values left alone: `None` (nothing is set) and booleans (flags such as
`hasHawserToken` or `isSecret` say whether a secret exists; they cannot carry one).

This is independent of, and in addition to, the value-level redactions (`Config.Env`, compose
`environment:`) and the fail-closed credential canaries, which run first inside the tools.
"""

from collections.abc import Mapping
from typing import Any, Final

REDACTED: Final = "<redacted>"

SENSITIVE_KEYS: Final = frozenset(
    k.lower()
    for k in (
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
    )
)
SENSITIVE_SUFFIXES: Final = ("secret", "token", "password")


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_KEYS or lowered.endswith(SENSITIVE_SUFFIXES)


def redact_sensitive_keys(value: Any) -> Any:
    """A copy of `value` with every sensitive key's non-null, non-boolean value redacted."""
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if (
                isinstance(key, str)
                and is_sensitive_key(key)
                and item is not None
                and not isinstance(item, bool)
            ):
                out[key] = REDACTED
            else:
                out[key] = redact_sensitive_keys(item)
        return out
    if isinstance(value, list | tuple):
        return [redact_sensitive_keys(item) for item in value]
    return value


# --- placeholder write-back guard ---------------------------------------------------------------

MASKED: Final = "***"
"""How DockHand itself masks stack secrets."""

PLACEHOLDERS: Final = (REDACTED, MASKED)


def placeholders_in(fields: Mapping[str, str | None]) -> list[tuple[str, str]]:
    """`(field, placeholder)` for every field whose text contains a redaction placeholder.

    Read tools replace secrets with `REDACTED` and DockHand masks them as `MASKED`; writing either
    back would replace real values with placeholder text.
    """
    return [
        (name, marker)
        for name, text in fields.items()
        if text is not None
        for marker in PLACEHOLDERS
        if marker in text
    ]
