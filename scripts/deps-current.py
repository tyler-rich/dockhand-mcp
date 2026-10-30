#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hand-maintained pins must be at the newest stable release (plan D-013).

`uv lock --upgrade` does not see these, so `ci`'s deps-current step runs this script after its
lockfile and CPython checks:

- the Dockerfile's uv stage tag (newest `uv`);
- the `uv_build` requirement in `[build-system]` (newest `uv-build` must satisfy it, and the lower
  bound is the newest release);
- each `[tool.uv] build-constraint-dependencies` pin (newest release of that project);
- `SEMGREP_VERSION` in ci.yml (newest `semgrep`);
- the release tools the workflows download: `OSV_SCANNER_VERSION` (ci.yml, release.yml and
  image-scan.yml), `COSIGN_VERSION` and `SYFT_VERSION` (release.yml), `GITLEAKS_VERSION` (ci.yml),
  each the tag of its project's newest GitHub release.

It also prints a notice, never a failure, when the newest Semgrep declares support for the
project's Python while ci.yml still overrides it with SEMGREP_PYTHON.

Newest stable releases come from PyPI's JSON API (`info.version` is never a pre-release) and
GitHub's `releases/latest` (never a draft or a pre-release; `GITHUB_TOKEN`, when set, is sent to
avoid the anonymous rate limit). An unreachable index or API skips that check with a notice
instead of failing, so an offline run passes.

    deps-current.py [--root DIR]
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

Version = tuple[int, ...]
Fetch = Callable[[str], dict[str, object]]
FetchRelease = Callable[[str], str]

UV_STAGE = re.compile(
    r"^FROM ghcr\.io/astral-sh/uv:(?P<v>[0-9][^@\s]*)(?:@\S+)?\s+AS\s+uv\s*$", re.M
)
UV_BUILD = re.compile(r"uv_build\s*>=\s*(?P<low>[0-9][\w.]*)\s*,\s*<\s*(?P<high>[0-9][\w.]*)")
BUILD_CONSTRAINTS = re.compile(r"^build-constraint-dependencies\s*=\s*\[(?P<items>[^\]]*)\]", re.M)
CONSTRAINT = re.compile(r"""["'](?P<name>[A-Za-z0-9._-]+)==(?P<v>[^"']+)["']""")
SEMGREP_VERSION = re.compile(r"^\s*SEMGREP_VERSION:\s*(?P<v>[0-9][\w.]*)\s*$", re.M)
SEMGREP_PYTHON = re.compile(r"^\s*SEMGREP_PYTHON:", re.M)

# (workflow file, variable) -> the GitHub repository whose newest release it must name.
RELEASE_PINS = {
    ("ci.yml", "OSV_SCANNER_VERSION"): "google/osv-scanner",
    ("release.yml", "OSV_SCANNER_VERSION"): "google/osv-scanner",
    ("image-scan.yml", "OSV_SCANNER_VERSION"): "google/osv-scanner",
    ("release.yml", "COSIGN_VERSION"): "sigstore/cosign",
    ("release.yml", "SYFT_VERSION"): "anchore/syft",
    ("ci.yml", "GITLEAKS_VERSION"): "gitleaks/gitleaks",
}
RELEASE_PIN_FILES = sorted({file for file, _ in RELEASE_PINS})


@dataclass
class Result:
    problems: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def parse(version: str) -> Version:
    return tuple(int(part) for part in version.removeprefix("v").split("."))


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(dockerfile: str, pyproject: str, ci: str) -> dict[str, str]:
    """Package name -> pinned version of the watched pins; for `uv-build`, the lower bound."""
    pins: dict[str, str] = {}
    if m := UV_STAGE.search(dockerfile):
        pins["uv"] = m["v"]
    if m := UV_BUILD.search(pyproject):
        pins["uv-build"] = m["low"]
    if m := BUILD_CONSTRAINTS.search(pyproject):
        for item in CONSTRAINT.finditer(m["items"]):
            pins[normalise(item["name"])] = item["v"]
    if m := SEMGREP_VERSION.search(ci):
        pins["semgrep"] = m["v"]
    return pins


def read_release_pins(workflows: dict[str, str]) -> dict[tuple[str, str], str]:
    """(workflow file, variable) -> pinned version of each release tool found."""
    pins: dict[tuple[str, str], str] = {}
    for file, variable in RELEASE_PINS:
        pattern = re.compile(rf"^\s*{variable}:\s*(?P<v>v?[0-9][\w.]*)\s*$", re.M)
        if m := pattern.search(workflows.get(file, "")):
            pins[(file, variable)] = m["v"]
    return pins


def check_release_pins(
    workflows: dict[str, str], latest_release: FetchRelease, result: Result
) -> None:
    """Compare each release-tool pin with its project's newest GitHub release tag."""
    pins = read_release_pins(workflows)
    newest: dict[str, str | None] = {}
    for (file, variable), repo in RELEASE_PINS.items():
        label = f"{file} {variable}"
        if (file, variable) not in pins:
            result.problems.append(f"{label}: pin not found (did its format change?)")
            continue
        if repo not in newest:
            try:
                newest[repo] = latest_release(repo)
            except OSError as err:  # URLError, HTTPError (rate limit) and timeouts are OSErrors
                newest[repo] = None
                result.notices.append(f"{repo}: skipped, GitHub unreachable ({err})")
        tag = newest[repo]
        if tag is None:
            continue
        pinned = pins[(file, variable)]
        if parse(pinned) != parse(tag):
            result.problems.append(
                f"{label} is {pinned}; the newest release of {repo} is {tag.removeprefix('v')}"
            )


def check(
    dockerfile: str,
    pyproject: str,
    workflows: dict[str, str],
    python: str,
    latest: Fetch,
    latest_release: FetchRelease,
) -> Result:
    """Compare every hand pin with its newest release.

    `latest(name)` returns PyPI's JSON `info`; `latest_release(owner/repo)` the newest GitHub
    release's tag.
    """
    result = Result()
    ci = workflows.get("ci.yml", "")
    pins = read_pins(dockerfile, pyproject, ci)
    where = {
        "uv": "Dockerfile uv stage",
        "uv-build": "pyproject.toml uv_build",
        "semgrep": "ci.yml SEMGREP_VERSION",
    }
    required = ["uv", "uv-build", "semgrep"]
    constrained = sorted(set(pins) - set(where))
    if not constrained:
        result.problems.append("pyproject.toml: no build-constraint-dependencies pins were found")
    for name in [*required, *constrained]:
        label = where.get(name, f"pyproject.toml build-constraint {name}")
        if name not in pins:
            result.problems.append(f"{label}: pin not found (did its format change?)")
            continue
        try:
            info = latest(name)
        except OSError as err:  # URLError and timeouts are OSErrors
            result.notices.append(f"{label}: skipped, PyPI unreachable ({err})")
            continue
        newest = str(info["version"])
        if name == "uv-build":
            bounds = UV_BUILD.search(pyproject)
            high = bounds["high"] if bounds else "0"
            if parse(pins[name]) != parse(newest) or parse(newest) >= parse(high):
                result.problems.append(
                    f"{label} is >={pins[name]},<{high}; the newest release is {newest}"
                )
        elif parse(pins[name]) != parse(newest):
            result.problems.append(f"{label} is {pins[name]}; the newest release is {newest}")
        if name == "semgrep" and SEMGREP_PYTHON.search(ci):
            classifiers = info.get("classifiers") or []
            if f"Programming Language :: Python :: {python}" in classifiers:  # type: ignore[operator]
                result.notices.append(
                    f"Semgrep {newest} declares support for Python {python}: try removing "
                    "SEMGREP_PYTHON and the step's --python (CONTRIBUTING, Hand-maintained pins)"
                )
    check_release_pins(workflows, latest_release, result)
    return result


def pypi_latest(name: str) -> dict[str, object]:
    url = f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        info = json.load(response)["info"]
    return {"version": info["version"], "classifiers": info["classifiers"]}


def github_latest(repo: str) -> str:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json"},
    )
    if token := os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (fixed https URL)
        return str(json.loads(response.read())["tag_name"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args(argv).root
    python = (root / ".python-version").read_text("utf-8").strip()
    workflows = root / ".github" / "workflows"
    result = check(
        (root / "Dockerfile").read_text("utf-8"),
        (root / "pyproject.toml").read_text("utf-8"),
        {name: (workflows / name).read_text("utf-8") for name in RELEASE_PIN_FILES},
        python,
        pypi_latest,
        github_latest,
    )
    for notice in result.notices:
        print(f"::notice::{notice}")
    for problem in result.problems:
        print(f"::error::{problem}")
    return 1 if result.problems else 0


if __name__ == "__main__":
    sys.exit(main())
