# SPDX-License-Identifier: Apache-2.0
"""scripts/deps-current.py: the hand-maintained pins the lockfile check cannot see (D-013).

Offline: PyPI's answers are fixtures. They are invented, not recorded; only the two fields the
script reads (`version`, `classifiers`) are modelled.
"""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deps-current.py"

DOCKERFILE = (
    "FROM ghcr.io/astral-sh/uv:0.13.6@sha256:" + "ab" * 32 + " AS uv\nFROM python:3.15-slim\n"
)
PYPROJECT = """\
[build-system]
requires = ["uv_build>=0.13.6,<0.14"]
build-backend = "uv_build"

[tool.uv]
build-constraint-dependencies = ["setuptools==84.2.1", "Cython==3.3.0"]
"""
CI = 'env:\n  SEMGREP_VERSION: 1.182.1\n  SEMGREP_PYTHON: "3.14"\n'
SEMGREP_314 = [f"Programming Language :: Python :: 3.{n}" for n in range(10, 15)]


def _info(version: str, classifiers: list[str] | None = None) -> dict[str, object]:
    return {"version": version, "classifiers": classifiers or []}


CURRENT = {
    "uv": _info("0.13.6"),
    "uv-build": _info("0.13.6"),
    "setuptools": _info("84.2.1"),
    "cython": _info("3.3.0"),
    "semgrep": _info("1.182.1", SEMGREP_314),
}


@pytest.fixture(scope="module")
def dc() -> ModuleType:
    spec = importlib.util.spec_from_file_location("deps_current", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["deps_current"] = module
    spec.loader.exec_module(module)
    return module


def _check(
    dc: ModuleType,
    latest: dict[str, dict[str, object]],
    *,
    dockerfile: str = DOCKERFILE,
    pyproject: str = PYPROJECT,
    ci: str = CI,
) -> tuple[list[str], list[str]]:
    result = dc.check(dockerfile, pyproject, ci, "3.15", latest.__getitem__)
    return result.problems, result.notices


def test_everything_current_is_clean(dc: ModuleType) -> None:
    assert _check(dc, CURRENT) == ([], [])


def test_dockerfile_uv_stage_behind(dc: ModuleType) -> None:
    problems, _ = _check(dc, CURRENT | {"uv": _info("0.13.7")})
    assert len(problems) == 1
    assert "Dockerfile" in problems[0] and "0.13.6" in problems[0] and "0.13.7" in problems[0]


def test_uv_build_upper_bound_behind(dc: ModuleType) -> None:
    problems, _ = _check(dc, CURRENT | {"uv-build": _info("0.14.0")})
    assert len(problems) == 1
    assert "uv_build" in problems[0] and "0.14.0" in problems[0]


def test_uv_build_lower_bound_behind(dc: ModuleType) -> None:
    problems, _ = _check(dc, CURRENT | {"uv-build": _info("0.13.7")})
    assert len(problems) == 1
    assert "uv_build" in problems[0]


@pytest.mark.parametrize(("name", "newer"), [("setuptools", "85.0.0"), ("cython", "3.3.1")])
def test_build_constraint_behind(dc: ModuleType, name: str, newer: str) -> None:
    problems, _ = _check(dc, CURRENT | {name: _info(newer)})
    assert len(problems) == 1
    assert name in problems[0].lower() and newer in problems[0]


def test_semgrep_version_behind(dc: ModuleType) -> None:
    problems, _ = _check(dc, CURRENT | {"semgrep": _info("1.183.0", SEMGREP_314)})
    assert len(problems) == 1
    assert "SEMGREP_VERSION" in problems[0] and "1.183.0" in problems[0]


def test_each_stale_pin_is_reported(dc: ModuleType) -> None:
    latest = CURRENT | {
        "uv": _info("0.14.0"),
        "uv-build": _info("0.14.0"),
        "setuptools": _info("85.0.0"),
        "cython": _info("3.4.0"),
        "semgrep": _info("1.190.0", SEMGREP_314),
    }
    problems, _ = _check(dc, latest)
    assert len(problems) == 5


def test_semgrep_notice_when_newest_declares_the_project_python(dc: ModuleType) -> None:
    classifiers = [*SEMGREP_314, "Programming Language :: Python :: 3.15"]
    problems, notices = _check(dc, CURRENT | {"semgrep": _info("1.182.1", classifiers)})
    assert problems == []
    assert len(notices) == 1
    assert "SEMGREP_PYTHON" in notices[0] and "3.15" in notices[0]


def test_no_semgrep_notice_without_the_override(dc: ModuleType) -> None:
    classifiers = [*SEMGREP_314, "Programming Language :: Python :: 3.15"]
    ci = "env:\n  SEMGREP_VERSION: 1.182.1\n"
    _, notices = _check(dc, CURRENT | {"semgrep": _info("1.182.1", classifiers)}, ci=ci)
    assert notices == []


def test_unreadable_pin_is_a_problem(dc: ModuleType) -> None:
    problems, _ = _check(dc, CURRENT, ci="env: {}\n")
    assert len(problems) == 1 and "SEMGREP_VERSION" in problems[0]


def test_unreachable_index_is_tolerated(dc: ModuleType) -> None:
    def offline(_name: str) -> dict[str, object]:
        raise OSError("network is unreachable")

    result = dc.check(DOCKERFILE, PYPROJECT, CI, "3.15", offline)
    assert result.problems == []
    assert result.notices and all("skipped" in n for n in result.notices)


def test_the_repository_pins_are_parseable(dc: ModuleType) -> None:
    """The real files still have the shapes the script reads; a reshuffle must not silently pass."""
    texts = {
        "dockerfile": (ROOT / "Dockerfile").read_text("utf-8"),
        "pyproject": (ROOT / "pyproject.toml").read_text("utf-8"),
        "ci": (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8"),
    }
    pins = dc.read_pins(texts["dockerfile"], texts["pyproject"], texts["ci"])
    assert set(pins) == {"uv", "uv-build", "setuptools", "cython", "semgrep"}
