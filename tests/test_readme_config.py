# SPDX-License-Identifier: Apache-2.0
"""README's configuration table is ARCHITECTURE §5's, and both match the `Settings` fields."""

import re
from pathlib import Path
from typing import Any

import pytest

from dockhand_mcp.config import Settings

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"

_NAME = re.compile(r"`([A-Z][A-Z0-9_]*\*?|_[A-Z0-9_]+)`")
_CODE = re.compile(r"`([^`]*)`")


def table_after(text: str, heading: re.Pattern[str]) -> list[str]:
    """The rows (header and separator included) of the first table under a matching heading."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if heading.match(line)), None)
    assert start is not None, f"no heading matching {heading.pattern!r}"
    rows: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            break
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    assert rows, f"no table under {heading.pattern!r}"
    return rows


def architecture_rows() -> list[str]:
    return table_after(ARCHITECTURE.read_text("utf-8"), re.compile(r"^## 5\. Configuration\b"))


def readme_rows() -> list[str]:
    return table_after(README.read_text("utf-8"), re.compile(r"^## Configuration\b"))


def cells(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def variables(cell: str) -> list[str]:
    """Variable names in a first-column cell; `_SUFFIX` shorthand is expanded from the first name.

    `_FILE` is appended (`DOCKHAND_MCP_CHALLENGE_KEY` / `_FILE`); any other suffix replaces as many
    trailing words of the first name (`DOCKHAND_MCP_DEFAULT_TIMEOUT` / `_MAX_TIMEOUT`).
    """
    names = _NAME.findall(cell)
    assert names and not names[0].startswith("_"), f"cannot read variables from {cell!r}"
    out = [names[0]]
    for name in names[1:]:
        if name == "_FILE":
            out.append(names[0] + name)
        elif name.startswith("_"):
            words = names[0].split("_")
            out.append("_".join(words[: len(words) - name.count("_")]) + name)
        else:
            out.append(name)
    return out


def data_rows(rows: list[str]) -> list[list[str]]:
    assert cells(rows[0])[:2] == ["Variable", "Default"], rows[0]
    return [cells(row) for row in rows[2:]]


def is_reserved(row: list[str]) -> bool:
    return row[2].startswith("**Phase 5 only.**")


def settings_aliases() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for info in Settings.model_fields.values():
        alias = info.validation_alias
        assert isinstance(alias, str)
        out[alias] = info.default
    return out


def render(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        return ",".join(value)
    return str(getattr(value, "value", value))


def test_readme_table_is_architecture_table() -> None:
    assert readme_rows() == architecture_rows()


def test_table_variables_are_the_settings_fields() -> None:
    documented: set[str] = set()
    for row in data_rows(readme_rows()):
        if not is_reserved(row):
            documented.update(variables(row[0]))
    assert documented == set(settings_aliases())


def test_reserved_names_are_not_parsed() -> None:
    reserved = [row for row in data_rows(readme_rows()) if is_reserved(row)]
    assert reserved, "the Phase 5 reserved row is missing"
    prefixes = [name.rstrip("*") for row in reserved for name in variables(row[0])]
    for alias in settings_aliases():
        assert not any(alias.startswith(prefix) for prefix in prefixes), alias


def test_env_example_lists_every_variable() -> None:
    text = (ROOT / "deploy" / ".env.example").read_text("utf-8")
    listed = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, flags=re.MULTILINE))
    assert listed == set(settings_aliases())


@pytest.mark.parametrize("row", [r for r in data_rows(architecture_rows()) if not is_reserved(r)])
def test_documented_defaults_match_settings(row: list[str]) -> None:
    defaults = settings_aliases()
    names = [n for n in variables(row[0]) if not n.endswith("_FILE")]
    shown = _CODE.findall(row[1])
    if not shown:
        for name in names:
            assert defaults[name] in (None, ()), f"{name}: README shows no default"
        return
    assert len(shown) == len(names), f"{row[0]}: {len(names)} variables, {len(shown)} defaults"
    for name, text in zip(names, shown, strict=True):
        assert render(defaults[name]) == text, name
