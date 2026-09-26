# SPDX-License-Identifier: Apache-2.0
"""Every Python source file starts with the Apache-2.0 SPDX identifier (D-015)."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPDX = "# SPDX-License-Identifier: Apache-2.0"
FILES = sorted(p for d in ("src", "tests", "scripts") for p in (ROOT / d).rglob("*.py"))


def test_there_are_files_to_check() -> None:
    assert any(p.is_relative_to(ROOT / "src") for p in FILES)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_spdx_header(path: Path) -> None:
    head = path.read_text(encoding="utf-8").splitlines()[:2]
    assert SPDX in head
