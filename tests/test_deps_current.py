# SPDX-License-Identifier: Apache-2.0
"""scripts/deps-current.py: the hand-maintained pins the lockfile check cannot see (D-013).

Offline: PyPI's and GitHub's answers are fixtures. They are invented, not recorded; only the
fields the script reads are modelled (PyPI `version`, `classifiers`; GitHub the latest release's
`tag_name`).
"""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import fake_secret

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
OSV_SHA = "  OSV_SCANNER_SHA256: " + "cd" * 32 + "\n"
CI = (
    "env:\n  OSV_SCANNER_VERSION: v2.7.0\n"
    + OSV_SHA
    + '  SEMGREP_VERSION: 1.182.1\n  SEMGREP_PYTHON: "3.14"\n  GITLEAKS_VERSION: 8.30.1\n'
)
RELEASE = (
    "env:\n  OSV_SCANNER_VERSION: v2.7.0\n"
    + OSV_SHA
    + "  COSIGN_VERSION: v3.1.4\n  SYFT_VERSION: v1.55.0\n"
)
IMAGE_SCAN = "env:\n  OSV_SCANNER_VERSION: v2.7.0\n" + OSV_SHA
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
RELEASES = {
    "google/osv-scanner": "v2.7.0",
    "sigstore/cosign": "v3.1.4",
    "anchore/syft": "v1.55.0",
    "gitleaks/gitleaks": "v8.30.1",
}


@pytest.fixture(scope="module")
def dc() -> ModuleType:
    spec = importlib.util.spec_from_file_location("deps_current", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["deps_current"] = module
    spec.loader.exec_module(module)
    return module


def _workflows(
    ci: str = CI, release: str = RELEASE, image_scan: str = IMAGE_SCAN
) -> dict[str, str]:
    return {"ci.yml": ci, "release.yml": release, "image-scan.yml": image_scan}


def _check(
    dc: ModuleType,
    latest: dict[str, dict[str, object]],
    *,
    dockerfile: str = DOCKERFILE,
    pyproject: str = PYPROJECT,
    workflows: dict[str, str] | None = None,
    releases: dict[str, str] = RELEASES,
) -> tuple[list[str], list[str]]:
    result = dc.check(
        dockerfile,
        pyproject,
        workflows if workflows is not None else _workflows(),
        "3.15",
        latest.__getitem__,
        releases.__getitem__,
    )
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
    releases = {
        "google/osv-scanner": "v2.8.0",
        "sigstore/cosign": "v3.2.0",
        "anchore/syft": "v1.56.0",
        "gitleaks/gitleaks": "v8.31.0",
    }
    problems, _ = _check(dc, latest, releases=releases)
    # five PyPI pins; OSV-Scanner in three workflows, cosign, syft and gitleaks in one each
    assert len(problems) == 11


def test_semgrep_notice_when_newest_declares_the_project_python(dc: ModuleType) -> None:
    classifiers = [*SEMGREP_314, "Programming Language :: Python :: 3.15"]
    problems, notices = _check(dc, CURRENT | {"semgrep": _info("1.182.1", classifiers)})
    assert problems == []
    assert len(notices) == 1
    assert "SEMGREP_PYTHON" in notices[0] and "3.15" in notices[0]


def test_no_semgrep_notice_without_the_override(dc: ModuleType) -> None:
    classifiers = [*SEMGREP_314, "Programming Language :: Python :: 3.15"]
    ci = CI.replace('  SEMGREP_PYTHON: "3.14"\n', "")
    _, notices = _check(
        dc, CURRENT | {"semgrep": _info("1.182.1", classifiers)}, workflows=_workflows(ci=ci)
    )
    assert notices == []


def test_unreadable_pin_is_a_problem(dc: ModuleType) -> None:
    ci = CI.replace("  SEMGREP_VERSION: 1.182.1\n", "")
    problems, _ = _check(dc, CURRENT, workflows=_workflows(ci=ci))
    assert len(problems) == 1 and "SEMGREP_VERSION" in problems[0]


def test_unreachable_index_is_tolerated(dc: ModuleType) -> None:
    def offline(_name: str) -> dict[str, object]:
        raise OSError("network is unreachable")

    result = dc.check(DOCKERFILE, PYPROJECT, _workflows(), "3.15", offline, RELEASES.__getitem__)
    assert result.problems == []
    assert result.notices and all("skipped" in n for n in result.notices)


@pytest.mark.parametrize(
    ("repo", "newer", "files", "variable"),
    [
        ("google/osv-scanner", "v2.7.1", 3, "OSV_SCANNER_VERSION"),
        ("sigstore/cosign", "v3.2.0", 1, "COSIGN_VERSION"),
        ("anchore/syft", "v1.56.0", 1, "SYFT_VERSION"),
        ("gitleaks/gitleaks", "v8.31.0", 1, "GITLEAKS_VERSION"),
    ],
)
def test_release_tool_behind(
    dc: ModuleType, repo: str, newer: str, files: int, variable: str
) -> None:
    """Each workflow that pins the tool is reported; OSV-Scanner is pinned in three."""
    problems, _ = _check(dc, CURRENT, releases=RELEASES | {repo: newer})
    assert len(problems) == files
    assert all(variable in p and newer.lstrip("v") in p for p in problems)


def test_osv_scanner_behind_in_one_workflow(dc: ModuleType) -> None:
    stale = IMAGE_SCAN.replace("v2.7.0", "v2.6.0")
    problems, _ = _check(dc, CURRENT, workflows=_workflows(image_scan=stale))
    assert len(problems) == 1
    assert "image-scan.yml" in problems[0] and "2.6.0" in problems[0] and "2.7.0" in problems[0]


def test_a_release_tool_ahead_of_the_latest_release_is_a_problem(dc: ModuleType) -> None:
    """A pin that is not exactly the newest stable release (e.g. a pre-release) is reported."""
    release = RELEASE.replace("COSIGN_VERSION: v3.1.4", "COSIGN_VERSION: v3.2.0")
    problems, _ = _check(dc, CURRENT, workflows=_workflows(release=release))
    assert len(problems) == 1 and "COSIGN_VERSION" in problems[0]


@pytest.mark.parametrize(
    ("file", "variable"),
    [
        ("ci.yml", "OSV_SCANNER_VERSION"),
        ("release.yml", "OSV_SCANNER_VERSION"),
        ("image-scan.yml", "OSV_SCANNER_VERSION"),
        ("release.yml", "COSIGN_VERSION"),
        ("release.yml", "SYFT_VERSION"),
        ("ci.yml", "GITLEAKS_VERSION"),
    ],
)
def test_missing_release_tool_pin_is_a_problem(dc: ModuleType, file: str, variable: str) -> None:
    texts = _workflows()
    texts[file] = "".join(
        line
        for line in texts[file].splitlines(keepends=True)
        if not line.strip().startswith(variable + ":")
    )
    problems, _ = _check(dc, CURRENT, workflows=texts)
    assert len(problems) == 1
    assert file in problems[0] and variable in problems[0] and "not found" in problems[0]


def test_unreachable_github_is_tolerated(dc: ModuleType) -> None:
    def offline(_repo: str) -> str:
        raise OSError("network is unreachable")

    result = dc.check(DOCKERFILE, PYPROJECT, _workflows(), "3.15", CURRENT.__getitem__, offline)
    assert result.problems == []
    assert len(result.notices) == 4 and all("skipped" in n for n in result.notices)


class _Answer:
    """A stand-in for urlopen's response: a context manager with `read()`."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def test_github_latest_reads_the_latest_release(
    dc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`releases/latest` (never a draft or pre-release); a token in the environment is sent."""
    token = fake_secret("ghs-fake")
    monkeypatch.setenv("GITHUB_TOKEN", token)
    seen: list[object] = []

    def urlopen(request: object, timeout: float) -> _Answer:
        seen.append(request)
        return _Answer(b'{"tag_name": "v9.9.9", "prerelease": false}')

    monkeypatch.setattr(dc.urllib.request, "urlopen", urlopen)
    assert dc.github_latest("google/osv-scanner") == "v9.9.9"
    request = seen[0]
    url = "https://api.github.com/repos/google/osv-scanner/releases/latest"
    assert request.full_url == url  # type: ignore[attr-defined]
    assert request.get_header("Authorization") == f"Bearer {token}"  # type: ignore[attr-defined]


def test_github_latest_without_a_token(dc: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen: list[object] = []

    def urlopen(request: object, timeout: float) -> _Answer:
        seen.append(request)
        return _Answer(b'{"tag_name": "v1.0.0"}')

    monkeypatch.setattr(dc.urllib.request, "urlopen", urlopen)
    assert dc.github_latest("sigstore/cosign") == "v1.0.0"
    assert not seen[0].has_header("Authorization")  # type: ignore[attr-defined]


def test_the_repository_pins_are_parseable(dc: ModuleType) -> None:
    """The real files still have the shapes the script reads; a reshuffle must not silently pass."""
    workflows = ROOT / ".github" / "workflows"
    texts = {
        "dockerfile": (ROOT / "Dockerfile").read_text("utf-8"),
        "pyproject": (ROOT / "pyproject.toml").read_text("utf-8"),
        "ci": (workflows / "ci.yml").read_text("utf-8"),
    }
    pins = dc.read_pins(texts["dockerfile"], texts["pyproject"], texts["ci"])
    assert set(pins) == {"uv", "uv-build", "setuptools", "cython", "semgrep"}
    tools = dc.read_release_pins(
        {name: (workflows / name).read_text("utf-8") for name in dc.RELEASE_PIN_FILES}
    )
    assert set(tools) == {
        ("ci.yml", "OSV_SCANNER_VERSION"),
        ("release.yml", "OSV_SCANNER_VERSION"),
        ("image-scan.yml", "OSV_SCANNER_VERSION"),
        ("release.yml", "COSIGN_VERSION"),
        ("release.yml", "SYFT_VERSION"),
        ("ci.yml", "GITLEAKS_VERSION"),
    }
