# SPDX-License-Identifier: Apache-2.0
"""`.env` files as docker compose reads them: parse to values, and edit in place.

Parsing follows compose's dotenv format: `KEY=value` lines, an optional `export ` prefix, `#`
comment lines, unquoted values ending at an inline ` #` comment, single-quoted values taken
literally, double-quoted values with `\\"`, `\\\\` and `\\n` escapes, and quoted values that span
lines. Unquoted and double-quoted values are interpolated with the variables defined before them.

Editing rewrites only the lines that assign an affected key and appends new keys at the end, so
comments, blank lines, order and line endings are kept. Values are written unquoted when that is
unambiguous, else single-quoted (literal, never interpolated).
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final

from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.guardrails.compose import Variables, interpolate

_ASSIGN: Final = re.compile(
    r"^(?P<indent>[ \t]*)(?P<export>export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<gap>[ \t]*)=(?P<rest>.*)$",
    re.DOTALL,
)
_PLAIN_VALUE: Final = re.compile(r"^[A-Za-z0-9_./:@%+,=-]*$")
_INLINE_COMMENT: Final = re.compile(r"[ \t]+#.*$")


class DotenvEditError(DockhandError):
    def __init__(self, message: str) -> None:
        super().__init__(None, "validation_error", message)


@dataclass(frozen=True)
class Entry:
    """One logical line: an assignment (possibly spanning lines), or anything else."""

    text: str  # as written, including its line ending(s)
    key: str | None = None
    value: str | None = None  # parsed, before interpolation
    quote: str = ""  # "", "'" or '"'
    comment: str = ""  # an unquoted value's inline comment, with its leading whitespace
    multiline: bool = False
    indent: str = ""
    export: str = ""
    gap: str = ""


def _eol(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    return "\n" if line.endswith("\n") else ""


def _unescape_double(value: str) -> str:
    return re.sub(r"\\([\\\"n$])", lambda m: "\n" if m[1] == "n" else m[1], value)


def _closing_double(text: str) -> int:
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i
        i += 1
    return -1


def entries(text: str) -> list[Entry]:
    lines = text.splitlines(keepends=True)
    out: list[Entry] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        body = line[: len(line) - len(_eol(line))]
        m = _ASSIGN.match(body)
        stripped = body.strip()
        if m is None or stripped.startswith("#"):
            out.append(Entry(line))
            i += 1
            continue
        rest = m["rest"].lstrip(" \t")
        common = Entry(
            line, key=m["key"], indent=m["indent"], export=m["export"] or "", gap=m["gap"]
        )
        if rest[:1] in ("'", '"'):
            quote = rest[0]
            joined = rest[1:]
            consumed = [line]
            while True:
                end = joined.find("'") if quote == "'" else _closing_double(joined)
                if end >= 0 or i + len(consumed) >= len(lines):
                    break
                joined += _eol(consumed[-1]) or "\n"
                nxt = lines[i + len(consumed)]
                consumed.append(nxt)
                joined += nxt[: len(nxt) - len(_eol(nxt))]
            if end < 0:
                raise DotenvEditError(f".env value for {common.key} has an unterminated {quote}")
            value = joined[:end]
            if quote == '"':
                value = _unescape_double(value)
            trailing = _INLINE_COMMENT.match(joined[end + 1 :])
            out.append(
                replace(
                    common,
                    text="".join(consumed),
                    value=value,
                    quote=quote,
                    comment=trailing[0] if trailing else "",
                    multiline=len(consumed) > 1,
                )
            )
            i += len(consumed)
            continue
        comment = _INLINE_COMMENT.search(rest)
        value = rest[: comment.start()] if comment else rest
        out.append(
            replace(common, value=value.rstrip(" \t"), comment=comment[0] if comment else "")
        )
        i += 1
    return out


def parse_dotenv(text: str, base: Variables | None = None) -> dict[str, Any]:
    """Variable values defined by `text`, later assignments winning.

    Values are interpolated with `base` and the variables defined earlier in the file.
    """
    values: dict[str, Any] = {}
    for entry in entries(text):
        if entry.key is None or entry.value is None:
            continue
        if entry.quote == "'":
            values[entry.key] = entry.value
        else:
            known = {**(base or {}), **values}
            values[entry.key] = interpolate(entry.value, known)[0]
    return values


def format_value(key: str, value: str) -> str:
    if _PLAIN_VALUE.match(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    raise DotenvEditError(
        f"the value for {key} contains a single quote and characters that need quoting; "
        "write the file with the raw .env tool instead"
    )


def _assignment(entry: Entry, key: str, value: str, eol: str) -> str:
    # The value's inline comment, if any, is kept.
    value = format_value(key, value)
    return f"{entry.indent}{entry.export}{key}{entry.gap}={value}{entry.comment}{eol}"


@dataclass(frozen=True)
class EditResult:
    text: str
    added: list[str]
    changed: list[str]
    unchanged: list[str]
    renamed: list[dict[str, str]]
    deleted: list[str]

    def diff(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "changed": self.changed,
            "unchanged": self.unchanged,
            "renamed": self.renamed,
            "deleted": self.deleted,
        }


def edit_dotenv(
    text: str,
    *,
    set_vars: Mapping[str, str] | None = None,
    rename: Mapping[str, str] | None = None,
    delete: Sequence[str] | None = None,
) -> EditResult:
    """Apply renames, then sets, then deletes. Unknown keys in `rename`/`delete` are errors."""
    set_vars = dict(set_vars or {})
    rename = dict(rename or {})
    delete = list(dict.fromkeys(delete or []))
    items = entries(text)
    existing = {e.key for e in items if e.key is not None}

    unknown = sorted({*rename, *delete} - existing)
    if unknown:
        raise DotenvEditError(f"not defined in the .env file: {', '.join(unknown)}")
    targets = list(rename.values())
    clashes = sorted(
        {t for t in targets if t in existing and t not in rename}
        | {t for t in targets if targets.count(t) > 1}
    )
    if clashes:
        raise DotenvEditError(f"rename target already defined or repeated: {', '.join(clashes)}")
    both = sorted(set(delete) & ({*set_vars, *rename, *targets}))
    if both:
        raise DotenvEditError(f"a key cannot be deleted and also set or renamed: {', '.join(both)}")
    gone = sorted(set(set_vars) & set(rename))
    if gone:
        raise DotenvEditError(f"cannot set a key that is being renamed away: {', '.join(gone)}")
    touched = {*set_vars, *rename, *delete}
    split = sorted({e.key for e in items if e.key in touched and e.multiline})
    if split:
        raise DotenvEditError(
            f"cannot edit multi-line values in place: {', '.join(split)}; write the file with "
            "the raw .env tool instead"
        )

    old_values = parse_dotenv(text)
    newline = "\r\n" if "\r\n" in text else "\n"
    out: list[str] = []
    for entry in items:
        key = entry.key
        if key is None:
            out.append(entry.text)
            continue
        if key in delete:
            continue
        new_key = rename.get(key, key)
        eol = _eol(entry.text)
        if new_key in set_vars:
            out.append(_assignment(entry, new_key, set_vars[new_key], eol))
        elif new_key != key:
            start = len(entry.indent) + len(entry.export)
            out.append(entry.text[:start] + new_key + entry.text[start + len(key) :])
        else:
            out.append(entry.text)
    present = {rename.get(k, k) for k in existing if k not in delete}
    added = [k for k in set_vars if k not in present]
    if added and out and not out[-1].endswith("\n"):
        out[-1] += newline
    for key in added:
        out.append(f"{key}={format_value(key, set_vars[key])}{newline}")

    changed: list[str] = []
    unchanged: list[str] = []
    for key, value in set_vars.items():
        if key in added:
            continue
        before_key = next((old for old, new in rename.items() if new == key), key)
        (unchanged if old_values.get(before_key) == value else changed).append(key)
    return EditResult(
        text="".join(out),
        added=added,
        changed=changed,
        unchanged=unchanged,
        renamed=[{"from": k, "to": v} for k, v in rename.items()],
        deleted=delete,
    )
