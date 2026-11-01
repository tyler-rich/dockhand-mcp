# SPDX-License-Identifier: Apache-2.0
"""scripts/dependency-snapshot.py: uv.lock as a dependency-graph snapshot (plan S-09).

GitHub's own uv parsing (Dependabot's graph job) stopped at v0.2.0's lockfile because Dependabot
does not support `requires-python >=3.15`, so the graph and Dependabot alerts judged v0.2.0's
versions. The workflow submits this snapshot for manifest `uv.lock`; a user submission outranks
the stale graph-job entry for that path.

The fixture lockfile and its expected snapshot are invented, not recorded (see their headers).
"""

import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dependency-snapshot.py"
FIXTURES = ROOT / "tests" / "fixtures" / "uv-lock"
WORKFLOWS = ROOT / ".github" / "workflows"

ARGS = {
    "sha": "0123456789abcdef0123456789abcdef01234567",
    "ref": "refs/heads/main",
    "job_id": "42",
    "scanned": "2026-11-01T00:00:00Z",
    "detector_url": "https://github.example.test/owner/repo/blob/main/scripts/dependency-snapshot.py",
}


@pytest.fixture(scope="module")
def ds() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_snapshot", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dependency_snapshot"] = module
    spec.loader.exec_module(module)
    return module


def _lock(text: str | None = None) -> dict[str, Any]:
    if text is None:
        text = (FIXTURES / "revision5.uv.lock").read_text("utf-8")
    return tomllib.loads(text)


def _resolved(ds: ModuleType, lock: dict[str, Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = ds.build_manifest(lock)["resolved"]
    return resolved


def test_revision_5_lock_gives_the_expected_snapshot(ds: ModuleType) -> None:
    expected = json.loads((FIXTURES / "revision5.snapshot.json").read_text("utf-8"))
    assert ds.build_snapshot(_lock(), **ARGS) == expected


def test_a_transitive_runtime_dependency_is_runtime_and_indirect(ds: ModuleType) -> None:
    otel = _resolved(ds, _lock())["opentelemetry-api"]
    assert otel["package_url"] == "pkg:pypi/opentelemetry-api@1.45.2"
    assert (otel["scope"], otel["relationship"]) == ("runtime", "indirect")


def test_dev_group_dependencies_are_development(ds: ModuleType) -> None:
    resolved = _resolved(ds, _lock())
    assert (resolved["pytest"]["scope"], resolved["pytest"]["relationship"]) == (
        "development",
        "direct",
    )
    assert resolved["iniconfig"]["scope"] == "development"


def test_a_package_reached_from_runtime_and_dev_is_runtime(ds: ModuleType) -> None:
    """httpx is a runtime dependency and also a dependency of respx (dev)."""
    assert _resolved(ds, _lock())["httpx"]["scope"] == "runtime"


def test_an_activated_extra_brings_its_optional_dependencies(ds: ModuleType) -> None:
    """mcp needs pyjwt[crypto]; cryptography and cffi are therefore runtime packages."""
    resolved = _resolved(ds, _lock())
    assert resolved["pyjwt"]["dependencies"] == ["pkg:pypi/cryptography@50.0.2"]
    assert resolved["cryptography"]["scope"] == resolved["cffi"]["scope"] == "runtime"


def test_marker_restricted_dependencies_are_kept(ds: ModuleType) -> None:
    """Platform markers do not drop a package: an alert for any platform's install still counts."""
    resolved = _resolved(ds, _lock())
    assert "colorama" in resolved and "anyio" in resolved


def test_the_project_itself_is_metadata_not_a_dependency(ds: ModuleType) -> None:
    manifest = ds.build_manifest(_lock())
    assert "demo-app" not in manifest["resolved"]
    assert manifest["metadata"] == {
        "project": "demo-app",
        "project_version": "1.2.3",
        "lock_revision": 5,
    }


def test_purl_names_are_normalised(ds: ModuleType) -> None:
    lock = _lock()
    lock["package"][0]["name"] = "AnyIO"
    resolved = _resolved(ds, lock)
    assert resolved["anyio"]["package_url"] == "pkg:pypi/anyio@4.12.0"


def test_two_versions_of_one_package_are_both_reported(ds: ModuleType) -> None:
    lock = _lock()
    lock["package"].append({"name": "certifi", "version": "2026.7.22", "source": {}})
    for package in lock["package"]:
        if package["name"] == "httpx":
            package["dependencies"][1] = {"name": "certifi", "version": "2026.10.23"}
        if package["name"] == "pytest":
            package["dependencies"].append({"name": "certifi", "version": "2026.7.22"})
    resolved = _resolved(ds, lock)
    assert resolved["certifi@2026.10.23"]["scope"] == "runtime"
    assert resolved["certifi@2026.7.22"]["scope"] == "development"
    assert "certifi" not in resolved


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda lock: lock.update(version=2), "lockfile version 2"),
        (lambda lock: lock["package"].pop(5), "exactly one project"),
        (
            lambda lock: lock["package"][6]["dependencies"].append({"name": "missing"}),
            "missing",
        ),
    ],
)
def test_an_unreadable_lock_is_an_error(ds: ModuleType, change: Any, message: str) -> None:
    lock = _lock()
    assert lock["package"][5]["name"] == "demo-app" and lock["package"][6]["name"] == "httpx"
    change(lock)
    with pytest.raises(ds.LockError, match=message):
        ds.build_manifest(lock)


def test_the_repository_lock_gives_a_snapshot(ds: ModuleType) -> None:
    """The real uv.lock parses, its project version matches pyproject, key packages are there."""
    lock = tomllib.loads((ROOT / "uv.lock").read_text("utf-8"))
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    manifest = ds.build_manifest(lock)
    assert manifest["metadata"]["project"] == "dockhand-mcp"
    assert manifest["metadata"]["project_version"] == pyproject["project"]["version"]
    resolved = manifest["resolved"]
    assert (resolved["mcp"]["scope"], resolved["mcp"]["relationship"]) == ("runtime", "direct")
    assert resolved["opentelemetry-api"]["scope"] == "runtime"
    assert (resolved["pytest"]["scope"], resolved["pytest"]["relationship"]) == (
        "development",
        "direct",
    )


def test_main_writes_the_snapshot_and_a_summary(
    ds: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "snapshot.json"
    argv = [
        "--lockfile",
        str(FIXTURES / "revision5.uv.lock"),
        "--output",
        str(out),
        "--sha",
        ARGS["sha"],
        "--ref",
        ARGS["ref"],
        "--job-id",
        ARGS["job_id"],
        "--scanned",
        ARGS["scanned"],
        "--detector-url",
        ARGS["detector_url"],
    ]
    assert ds.main(argv) == 0
    expected = json.loads((FIXTURES / "revision5.snapshot.json").read_text("utf-8"))
    assert json.loads(out.read_text("utf-8")) == expected
    summary = capsys.readouterr().err
    assert "demo-app 1.2.3" in summary
    assert "12 packages (8 runtime, 4 development)" in summary


def test_main_reports_an_unreadable_lock(
    ds: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 2\n", "utf-8")
    assert ds.main(["--lockfile", str(lock), "--output", str(tmp_path / "out.json")]) == 1
    assert "::error" in capsys.readouterr().out


def _workflow(name: str) -> dict[Any, Any]:
    data: dict[Any, Any] = yaml.safe_load((WORKFLOWS / name).read_text("utf-8"))
    return data


def test_submission_workflow_runs_on_main_and_dispatch_only() -> None:
    workflow = _workflow("dependency-submission.yml")
    triggers = workflow[True]  # PyYAML reads the bare key `on` as the boolean true
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"] == {"branches": ["main"]}


def test_submission_workflow_grants_contents_write_to_one_job_only() -> None:
    workflow = _workflow("dependency-submission.yml")
    assert workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert len(jobs) == 1
    (job,) = jobs.values()
    assert job["permissions"] == {"contents": "write"}
    text = (WORKFLOWS / "dependency-submission.yml").read_text("utf-8")
    assert "secrets." not in text.replace("secrets.GITHUB_TOKEN", "")


def test_submission_workflow_actions_are_sha_pinned() -> None:
    for job in _workflow("dependency-submission.yml")["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                ref = step["uses"].split("@", 1)[1]
                assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), step


def test_ci_dry_runs_the_snapshot_without_submitting() -> None:
    steps = _workflow("ci.yml")["jobs"]["ci"]["steps"]
    runs = [step.get("run", "") for step in steps]
    dry = [run for run in runs if "scripts/dependency-snapshot.py" in run]
    assert len(dry) == 1
    assert "dependency-graph/snapshots" not in dry[0] and "gh api" not in dry[0]
