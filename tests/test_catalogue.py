# SPDX-License-Identifier: Apache-2.0
"""Each tier's catalogue matches its committed snapshot (rug-pull detection, SECURITY §2).

A deliberate change to a tool's name, title, description, endpoints or schemas updates
tests/fixtures/tool-catalogue-<tier>.json in the same PR, noted in docs/ARCHIVE.md. Regenerate
with `uv run dockhand-mcp tools` and keep the tier's entries.
"""

import json
from pathlib import Path

import pytest
from conftest import CATALOGUE_SNAPSHOTS

from dockhand_mcp.__main__ import main
from dockhand_mcp.tools.registry import REGISTRY, Tier


@pytest.mark.parametrize("tier", sorted(CATALOGUE_SNAPSHOTS))
def test_catalogue_matches_snapshot(tier: str) -> None:
    snapshot = json.loads(CATALOGUE_SNAPSHOTS[tier].read_text("utf-8"))
    live = [t for t in REGISTRY.catalogue() if t["tier"] == tier]
    assert [t["name"] for t in live] == [t["name"] for t in snapshot]
    for current, recorded in zip(live, snapshot, strict=True):
        assert current == recorded, f"{current['name']} differs from the snapshot"


@pytest.mark.parametrize("tier", sorted(CATALOGUE_SNAPSHOTS))
def test_snapshot_is_what_the_cli_prints(tier: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tools"]) == 0
    printed = [t for t in json.loads(capsys.readouterr().out) if t["tier"] == tier]
    assert printed == json.loads(CATALOGUE_SNAPSHOTS[tier].read_text("utf-8"))


def test_every_registered_tier_has_a_snapshot() -> None:
    assert {t.tier.value for t in REGISTRY.all()} == set(CATALOGUE_SNAPSHOTS)


def test_every_tool_is_documented() -> None:
    tools_md = (Path(__file__).resolve().parents[1] / "docs" / "TOOLS.md").read_text("utf-8")
    for tool in REGISTRY.all():
        if tool.tier in (Tier.READ, Tier.OPERATOR, Tier.DESTRUCTIVE):
            assert f"`{tool.name}`" in tools_md, tool.name
