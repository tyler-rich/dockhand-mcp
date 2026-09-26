# SPDX-License-Identifier: Apache-2.0
"""scripts/osv-image-gate.py: which OSV-Scanner image findings fail a release (plan S-09).

Every scan result here is invented, in the shape OSV-Scanner v2.6.0 writes with `--format json`
(`results[].source`, `packages[].package` / `groups` / `vulnerabilities[].affected`), checked
against a real scan of this project's image.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "osv-image-gate.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("osv_image_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["osv_image_gate"] = module
    spec.loader.exec_module(module)
    return module


def affected(ecosystem: str, fixed: str | None = None) -> dict[str, Any]:
    events: list[dict[str, str]] = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "package": {"ecosystem": ecosystem, "name": "glibc"},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
    }


def debian(
    vid: str,
    *,
    severity: str = "7.5",
    fixed_13: str | None = None,
    fixed_14: str | None = "2.43-5",
    unimportant: bool = False,
    name: str = "glibc",
) -> dict[str, Any]:
    """One Debian:13 OS package with one vulnerability group."""
    return {
        "package": {
            "name": name,
            "os_package_name": "libc6",
            "version": "2.41-12+deb13u4",
            "ecosystem": "Debian:13",
            "image_origin_details": {"index": 0},
        },
        "groups": [
            {
                "ids": [vid],
                "aliases": [vid.removeprefix("DEBIAN-"), vid],
                "experimental_analysis": {vid: {"called": True, "unimportant": unimportant}},
                "max_severity": severity,
            }
        ],
        "vulnerabilities": [
            {
                "id": vid,
                "affected": [
                    affected("Debian:12"),
                    {
                        **affected("Debian:13", fixed_13),
                        "package": {"ecosystem": "Debian:13", "name": name},
                    },
                    affected("Debian:14", fixed_14),
                ],
            }
        ],
    }


def pypi(vid: str, severity: str = "5.3") -> dict[str, Any]:
    return {
        "package": {"name": "somepkg", "version": "1.0.0", "ecosystem": "PyPI"},
        "groups": [{"ids": [vid], "aliases": [vid], "max_severity": severity}],
        "vulnerabilities": [
            {
                "id": vid,
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "somepkg"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }


def scan(*packages: dict[str, Any], source_type: str = "os") -> dict[str, Any]:
    path = (
        "/var/lib/dpkg/status" if source_type == "os" else "/app/.venv/lib/python3.14/site-packages"
    )
    return {
        "results": [{"source": {"path": path, "type": source_type}, "packages": list(packages)}]
    }


def verdicts(gate: ModuleType, report: dict[str, Any]) -> dict[str, str]:
    return {f.vuln_id: f.verdict for f in gate.classify(report)}


def test_non_debian_finding_fails(gate: ModuleType) -> None:
    report = scan(pypi("GHSA-aaaa-bbbb-cccc"), source_type="lockfile")
    assert verdicts(gate, report) == {"GHSA-aaaa-bbbb-cccc": gate.FAIL}


def test_fix_in_the_images_release_fails(gate: ModuleType) -> None:
    report = scan(debian("DEBIAN-CVE-2026-0001", fixed_13="2.41-12+deb13u5"))
    assert verdicts(gate, report) == {"DEBIAN-CVE-2026-0001": gate.FAIL}


def test_fix_only_in_a_later_release_is_reported(gate: ModuleType) -> None:
    report = scan(debian("DEBIAN-CVE-2026-0002", fixed_13=None, fixed_14="2.43-5"))
    assert verdicts(gate, report) == {"DEBIAN-CVE-2026-0002": gate.REPORT}


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("9.8", "fail"), ("9.0", "fail"), ("8.9", "report"), ("", "report"), ("n/a", "report")],
)
def test_unfixed_severity_threshold(gate: ModuleType, severity: str, expected: str) -> None:
    report = scan(debian("DEBIAN-CVE-2026-0003", severity=severity))
    want = gate.FAIL if expected == "fail" else gate.REPORT
    assert verdicts(gate, report) == {"DEBIAN-CVE-2026-0003": want}


def test_unimportant_never_fails(gate: ModuleType) -> None:
    report = scan(
        debian("DEBIAN-CVE-2019-0001", severity="9.8", unimportant=True),
        debian("DEBIAN-CVE-2019-0002", fixed_13="2.41-12+deb13u5", unimportant=True),
    )
    assert verdicts(gate, report) == {
        "DEBIAN-CVE-2019-0001": gate.REPORT,
        "DEBIAN-CVE-2019-0002": gate.REPORT,
    }


def test_reasons(gate: ModuleType) -> None:
    report = scan(
        debian("DEBIAN-CVE-2026-0010", severity="7.5"),
        debian("DEBIAN-CVE-2026-0011", severity="9.1"),
        debian("DEBIAN-CVE-2026-0012", fixed_13="2.41-12+deb13u5"),
        debian("DEBIAN-CVE-2026-0013", unimportant=True),
        debian("DEBIAN-CVE-2026-0014", severity=""),
    )
    reasons = {f.vuln_id: f.reason for f in gate.classify(report)}
    assert reasons["DEBIAN-CVE-2026-0010"] == "no fix in trixie"
    assert reasons["DEBIAN-CVE-2026-0011"] == "no fix in trixie, CVSS 9.1 ≥ 9.0"
    assert reasons["DEBIAN-CVE-2026-0012"] == "fixed in trixie: 2.41-12+deb13u5"
    assert reasons["DEBIAN-CVE-2026-0013"] == "no fix in trixie, unimportant (Debian)"
    assert reasons["DEBIAN-CVE-2026-0014"] == "no fix in trixie, CVSS unknown"


def test_clean_scan_passes(gate: ModuleType) -> None:
    assert gate.classify({"results": []}) == []


@pytest.mark.parametrize(
    "bad",
    [{}, {"results": "x"}, {"results": [{"packages": [{"package": {}}]}]}, []],
)
def test_unreadable_report_is_an_error(gate: ModuleType, bad: Any) -> None:
    with pytest.raises(ValueError):
        gate.classify(bad)


def write(tmp_path: Path, name: str, report: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(report), "utf-8")
    return path


def test_cli_passes_and_lists_reported_findings(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    amd = write(tmp_path, "amd64.json", scan(debian("DEBIAN-CVE-2026-0020", severity="7.8")))
    arm = write(tmp_path, "arm64.json", scan(debian("DEBIAN-CVE-2026-0020", severity="7.8")))
    code = gate.main([f"linux/amd64={amd}", f"linux/arm64={arm}"])
    out = capsys.readouterr().out
    assert code == 0
    assert "DEBIAN-CVE-2026-0020" in out and "glibc" in out and "7.8" in out
    assert "no fix in trixie" in out
    assert "linux/amd64" in out and "linux/arm64" in out
    assert "passes" in out


def test_cli_fails_on_a_blocking_finding(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    amd = write(tmp_path, "amd64.json", scan(debian("DEBIAN-CVE-2026-0030")))
    arm = write(tmp_path, "arm64.json", scan(debian("DEBIAN-CVE-2026-0031", severity="9.3")))
    code = gate.main([f"linux/amd64={amd}", f"linux/arm64={arm}"])
    out = capsys.readouterr().out
    assert code == 1
    assert "DEBIAN-CVE-2026-0031" in out and "fails" in out


@pytest.mark.parametrize("content", ["not json", "{}"])
def test_cli_fails_closed_on_a_bad_report(
    gate: ModuleType, tmp_path: Path, content: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, "utf-8")
    assert gate.main([f"linux/amd64={path}"]) == 2
    assert gate.main([f"linux/amd64={tmp_path / 'missing.json'}"]) == 2
