# SPDX-License-Identifier: Apache-2.0
"""The image-scan gate (plan S-09): which OSV-Scanner image findings fail a release.

Reads `osv-scanner scan image --format json` reports (OSV-Scanner has already applied the
`osv-scanner.toml` exceptions) and fails when any finding

- is in a package that is not one of the image's Debian packages (the virtualenv's Python
  packages, anything else);
- is a Debian finding with a fixed version in the image's own Debian release: the `affected[]`
  entry whose `package.ecosystem` is the installed package's (`Debian:13` for trixie) has a
  `fixed` event, so rebuilding on a newer base digest would remove it;
- has no fix in that release and a CVSS score of 9.0 or more (`groups[].max_severity`).

Findings Debian triaged as unimportant (`groups[].experimental_analysis.*.unimportant`, the flag
OSV-Scanner's own exit code ignores) and the other unfixed Debian findings are reported, not
failed. An unreadable report fails closed. Stdlib only, so both workflows run it without setup.

    osv-image-gate.py linux/amd64=amd64.json [linux/arm64=arm64.json …]

Prints a Markdown summary (for $GITHUB_STEP_SUMMARY). Exit 0: passes; 1: fails; 2: unreadable.
"""

import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FAIL = "fail"
REPORT = "report"
CVSS_LIMIT = 9.0

_DEBIAN = re.compile(r"^Debian:(\d+)$")
_CODENAMES = {"11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    package: str
    cvss: str
    verdict: str
    reason: str


def _need(value: Any, kind: type, what: str) -> Any:
    if not isinstance(value, kind):
        raise ValueError(f"unreadable OSV-Scanner report: {what} is not a {kind.__name__}")
    return value


def _release(ecosystem: str) -> str:
    match = _DEBIAN.match(ecosystem)
    number = match.group(1) if match else "?"
    return _CODENAMES.get(number, f"Debian {number}")


def _fixed_in_release(vulns: list[dict[str, Any]], name: str, ecosystem: str) -> list[str]:
    """`fixed` events of the affected entries for this package in the installed release."""
    fixed: list[str] = []
    for vuln in vulns:
        for entry in _need(vuln.get("affected", []), list, "affected"):
            package = entry.get("package") or {}
            if package.get("ecosystem") != ecosystem or package.get("name", name) != name:
                continue
            for rng in entry.get("ranges") or []:
                fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return sorted(set(fixed))


def _cvss(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _judge(package: dict[str, Any], group: dict[str, Any], vulns: list[dict[str, Any]]) -> Finding:
    name = _need(package.get("name"), str, "package.name")
    ecosystem = _need(package.get("ecosystem"), str, "package.ecosystem")
    ids = sorted(_need(group.get("ids"), list, "groups[].ids"))
    vuln_id = ", ".join(ids)
    severity = str(group.get("max_severity") or "")
    label = name
    if package.get("os_package_name") and package["os_package_name"] != name:
        label = f"{name} ({package['os_package_name']})"

    def finding(verdict: str, reason: str) -> Finding:
        return Finding(vuln_id, label, severity or "—", verdict, reason)

    if not _DEBIAN.match(ecosystem):
        return finding(FAIL, f"not a Debian package ({ecosystem})")
    release = _release(ecosystem)
    fixed = _fixed_in_release([v for v in vulns if v.get("id") in ids], name, ecosystem)
    analysis = group.get("experimental_analysis") or {}
    unimportant = any(isinstance(a, dict) and a.get("unimportant") for a in analysis.values())
    status = f"fixed in {release}: {', '.join(fixed)}" if fixed else f"no fix in {release}"
    if unimportant:
        return finding(REPORT, f"{status}, unimportant (Debian)")
    if fixed:
        return finding(FAIL, status)
    score = _cvss(severity)
    if score is None:
        return finding(REPORT, f"{status}, CVSS unknown")
    if score >= CVSS_LIMIT:
        return finding(FAIL, f"{status}, CVSS {severity} ≥ {CVSS_LIMIT}")
    return finding(REPORT, status)


def classify(report: Any) -> list[Finding]:
    """One finding per vulnerability group and package, deduplicated across binary packages."""
    results = _need(_need(report, dict, "the report").get("results"), list, "results")
    seen: dict[tuple[str, str], Finding] = {}
    for result in results:
        for entry in _need(_need(result, dict, "a result").get("packages"), list, "packages"):
            package = _need(_need(entry, dict, "a package").get("package"), dict, "package")
            _need(package.get("name"), str, "package.name")
            _need(package.get("ecosystem"), str, "package.ecosystem")
            vulns = _need(entry.get("vulnerabilities", []), list, "vulnerabilities")
            for group in _need(entry.get("groups", []), list, "groups"):
                found = _judge(package, _need(group, dict, "a group"), vulns)
                key = (found.vuln_id, str(package["name"]))
                if key not in seen or found.verdict == FAIL:
                    seen[key] = found
    return sorted(seen.values(), key=lambda f: (f.verdict != FAIL, f.package, f.vuln_id))


def _table(findings: list[Finding]) -> list[str]:
    rows = ["| Verdict | ID | Package | CVSS | Reason |", "|---|---|---|---|---|"]
    for f in findings:
        verdict = "**fail**" if f.verdict == FAIL else "report"
        rows.append(f"| {verdict} | {f.vuln_id} | {f.package} | {f.cvss} | {f.reason} |")
    return rows


def main(argv: list[str] | None = None) -> int:
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    args = sys.argv[1:] if argv is None else argv
    if not args or any("=" not in a for a in args):
        print("usage: osv-image-gate.py PLATFORM=REPORT.json …", file=sys.stderr)
        return 2
    lines = [
        "## Image scan gate",
        "",
        "Fails on: a finding outside the image's Debian packages; a Debian finding fixed in the "
        f"image's Debian release; an unfixed finding with CVSS ≥ {CVSS_LIMIT}. Findings Debian "
        "marks unimportant, and other unfixed Debian findings, are reported only. Exceptions: "
        "`osv-scanner.toml` only.",
        "",
    ]
    failed = False
    for arg in args:
        platform, _, path = arg.partition("=")
        try:
            findings = classify(json.loads(Path(path).read_text("utf-8")))
        except (OSError, ValueError) as exc:
            print(f"osv-image-gate.py: {platform}: {exc}", file=sys.stderr)
            return 2
        blocking = [f for f in findings if f.verdict == FAIL]
        failed = failed or bool(blocking)
        verdict = "fails" if blocking else "passes"
        lines += [
            f"### {platform}: {verdict} "
            f"({len(blocking)} blocking, {len(findings) - len(blocking)} reported)",
            "",
        ]
        lines += (_table(findings) if findings else ["No findings."]) + [""]
    lines.append(f"**Result: {'fails' if failed else 'passes'}.**")
    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
