# SPDX-License-Identifier: Apache-2.0
"""No tracked file pins a specific image version; docs show a placeholder to replace.

A version written into a deploy file or a doc goes stale with the next release (and the v0.1.0
package no longer exists), so they carry `ghcr.io/tyler-rich/dockhand-mcp:X.Y.Z@sha256:<digest>`
and say to copy the exact pinned `image:` line from the latest release notes. CHANGELOG.md and
docs/ARCHIVE.md are history and may name versions.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HISTORY = {"CHANGELOG.md", "docs/ARCHIVE.md"}
# The image name followed by a dotted version (`0.1.0`, `v1.2`, `1.2.3-rc1`); `dockhand-mcp:8080`
# (a compose service name and port) is not an image reference.
VERSIONED = re.compile(r"dockhand-mcp:v?\d+\.\d+")
PLACEHOLDER = "ghcr.io/tyler-rich/dockhand-mcp:X.Y.Z@sha256:<digest>"
INSTRUCTION = re.compile(r"exact pinned\s+`?image:`?\s+line", re.IGNORECASE)
IMAGE_DOCS = [
    "README.md",
    "deploy/docker-compose.yml",
    "deploy/dockhand-stack.yml",
    "deploy/docker-run.md",
    "docs/CLIENTS.md",
    "docs/SECURITY.md",
]


def tracked_files() -> list[str]:
    git = shutil.which("git")
    assert git is not None, "git is needed to list the tracked files"
    out = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [git, "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def test_there_are_files_to_check() -> None:
    files = tracked_files()
    assert "deploy/docker-compose.yml" in files
    assert "README.md" in files


def test_no_tracked_file_pins_an_image_version() -> None:
    found = []
    for rel in tracked_files():
        if rel in HISTORY:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="ignore")
        for number, line in enumerate(text.splitlines(), 1):
            if VERSIONED.search(line):
                found.append(f"{rel}:{number}: {line.strip()}")
    assert found == [], "image versions outside CHANGELOG.md/ARCHIVE:\n" + "\n".join(found)


@pytest.mark.parametrize("rel", IMAGE_DOCS)
def test_image_docs_show_the_placeholder_and_where_to_get_the_line(rel: str) -> None:
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert PLACEHOLDER in text
    assert INSTRUCTION.search(text), f"{rel} must say to copy the exact pinned image: line"
    assert "latest" in text and "release notes" in text
