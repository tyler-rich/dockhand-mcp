#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""uv.lock as a GitHub dependency-graph snapshot (plan S-09).

GitHub's own reading of uv.lock is Dependabot's graph job, and Dependabot does not support
`requires-python >=3.15` (dependabot-core#16524): the graph, and the Dependabot alerts judged
against it, stayed at v0.2.0's lockfile. dependency-submission.yml posts this snapshot for
manifest `uv.lock` on every push to main; a user submission outranks a Dependabot graph job's
entry for the same manifest, so it replaces the stale one. `ci` runs it on pull requests without
submitting.

Every locked package except the project itself is reported as `pkg:pypi/<name>@<version>`:

- `relationship`: `direct` for the project's dependencies, optional dependencies and dependency
  groups; `indirect` otherwise;
- `scope`: `runtime` when reachable from the project's dependencies or optional dependencies,
  `development` when reachable only from a dependency group. A package nothing reaches is
  reported as runtime, so an alert for it is never lost.

Environment markers are ignored (a package any platform installs is reported). An extra a parent
asks for (`{ name = "pyjwt", extra = ["crypto"] }`) adds that package's optional dependencies.
The project's name and version and the lock revision go in the manifest's metadata.

    dependency-snapshot.py [--lockfile uv.lock] [--output FILE|-] [--sha SHA] [--ref REF]
                           [--job-id ID] [--scanned ISO8601] [--detector-url URL]

The commit, ref and job default to GitHub Actions' GITHUB_SHA, GITHUB_REF and GITHUB_RUN_ID
(placeholders outside Actions; a dry run never submits). A summary goes to stderr.
"""

import argparse
import datetime
import json
import os
import re
import sys
import tomllib
from collections import deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any

MANIFEST = "uv.lock"
CORRELATOR = "dependency-submission uv.lock"
DETECTOR = {"name": "dockhand-mcp uv.lock snapshot", "version": "1.0.0"}
LOCK_VERSION = 1  # the lockfile format; `revision` changes within it are compatible
PROJECT_SOURCES = ("editable", "virtual")

Key = tuple[str, str]  # (normalised name, version)


class LockError(ValueError):
    """The lockfile is not one this script can read."""


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(key: Key) -> str:
    return f"pkg:pypi/{key[0]}@{key[1]}"


class Lock:
    def __init__(self, lock: dict[str, Any]) -> None:
        if lock.get("version") != LOCK_VERSION:
            raise LockError(f"lockfile version {lock.get('version')} (expected {LOCK_VERSION})")
        self.revision = lock.get("revision")
        self.packages: dict[Key, dict[str, Any]] = {}
        projects = []
        for package in lock.get("package", []):
            source = package.get("source", {})
            if any(source.get(kind) == "." for kind in PROJECT_SOURCES):
                projects.append(package)
                continue
            self.packages[(normalise(package["name"]), str(package["version"]))] = package
        if len(projects) != 1:
            raise LockError(f"expected exactly one project package, found {len(projects)}")
        self.project: dict[str, Any] = projects[0]
        self.by_name: dict[str, list[Key]] = {}
        for key in self.packages:
            self.by_name.setdefault(key[0], []).append(key)

    def resolve(self, ref: dict[str, Any], parent: str) -> Key:
        name = normalise(ref["name"])
        keys = self.by_name.get(name, [])
        if "version" in ref:
            keys = [key for key in keys if key[1] == str(ref["version"])]
        if len(keys) != 1:
            raise LockError(f"{parent}: dependency {ref['name']!r} matches {len(keys)} packages")
        return keys[0]


def _refs(groups: dict[str, list[dict[str, Any]]] | None) -> Iterable[dict[str, Any]]:
    for refs in (groups or {}).values():
        yield from refs


def _reach(lock: Lock, roots: list[tuple[Key, list[str]]], extras: dict[Key, set[str]]) -> set[Key]:
    """Every package reachable from `roots` (key, extras asked for); records activated extras."""
    seen: set[Key] = set()
    queue = deque(roots)
    while queue:
        key, asked = queue.popleft()
        new_extras = set(asked) - extras.setdefault(key, set())
        if key in seen and not new_extras:
            continue
        seen.add(key)
        extras[key] |= new_extras
        package = lock.packages[key]
        refs = list(package.get("dependencies", []))
        optional = package.get("optional-dependencies", {})
        for extra in sorted(extras[key]):
            refs.extend(optional.get(extra, []))
        for ref in refs:
            queue.append((lock.resolve(ref, package["name"]), list(ref.get("extra", []))))
    return seen


def build_manifest(data: dict[str, Any]) -> dict[str, Any]:
    lock = Lock(data)
    project = lock.project
    name = project["name"]

    def roots(refs: Iterable[dict[str, Any]]) -> list[tuple[Key, list[str]]]:
        return [(lock.resolve(ref, name), list(ref.get("extra", []))) for ref in refs]

    runtime_roots = roots(
        [*project.get("dependencies", []), *_refs(project.get("optional-dependencies"))]
    )
    dev_roots = roots(_refs(project.get("dev-dependencies")))
    extras: dict[Key, set[str]] = {}
    runtime = _reach(lock, runtime_roots, extras)
    reached = runtime | _reach(lock, dev_roots, extras)
    direct = {key for key, _ in runtime_roots + dev_roots}

    duplicated = {n for n, keys in lock.by_name.items() if len(keys) > 1}
    resolved: dict[str, Any] = {}
    for key in sorted(lock.packages):
        package = lock.packages[key]
        refs = list(package.get("dependencies", []))
        optional = package.get("optional-dependencies", {})
        for extra in sorted(extras.get(key, set())):
            refs.extend(optional.get(extra, []))
        deps = sorted({purl(lock.resolve(ref, package["name"])) for ref in refs})
        resolved[f"{key[0]}@{key[1]}" if key[0] in duplicated else key[0]] = {
            "package_url": purl(key),
            "relationship": "direct" if key in direct else "indirect",
            "scope": "runtime" if key in runtime or key not in reached else "development",
            "dependencies": deps,
        }

    metadata: dict[str, Any] = {"project": name}
    if "version" in project:
        metadata["project_version"] = str(project["version"])
    if lock.revision is not None:
        metadata["lock_revision"] = lock.revision
    return {
        "name": MANIFEST,
        "file": {"source_location": MANIFEST},
        "metadata": metadata,
        "resolved": resolved,
    }


def build_snapshot(
    data: dict[str, Any], *, sha: str, ref: str, job_id: str, scanned: str, detector_url: str
) -> dict[str, Any]:
    return {
        "version": 0,
        "sha": sha,
        "ref": ref,
        "job": {"correlator": CORRELATOR, "id": job_id},
        "detector": {**DETECTOR, "url": detector_url},
        "scanned": scanned,
        "manifests": {MANIFEST: build_manifest(data)},
    }


def summary(manifest: dict[str, Any]) -> str:
    resolved = manifest["resolved"].values()
    runtime = sum(1 for dep in resolved if dep["scope"] == "runtime")
    meta = manifest["metadata"]
    project = f"{meta['project']} {meta.get('project_version', '(no version)')}"
    return (
        f"{project}: {len(resolved)} packages ({runtime} runtime, "
        f"{len(resolved) - runtime} development), lock revision {meta.get('lock_revision')}"
    )


def main(argv: list[str] | None = None) -> int:
    env = os.environ
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo_url = f"{server}/{env.get('GITHUB_REPOSITORY', 'unknown/unknown')}"
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lockfile", type=Path, default=Path(MANIFEST))
    parser.add_argument("--output", default="-", help="file to write, or - for stdout")
    parser.add_argument("--sha", default=env.get("GITHUB_SHA", "0" * 40))
    parser.add_argument("--ref", default=env.get("GITHUB_REF", "refs/heads/dry-run"))
    parser.add_argument("--job-id", default=env.get("GITHUB_RUN_ID", "dry-run"))
    parser.add_argument(
        "--scanned",
        default=datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat(),
    )
    parser.add_argument(
        "--detector-url", default=f"{repo_url}/blob/main/scripts/dependency-snapshot.py"
    )
    args = parser.parse_args(argv)
    try:
        data = tomllib.loads(args.lockfile.read_text("utf-8"))
        snapshot = build_snapshot(
            data,
            sha=args.sha,
            ref=args.ref,
            job_id=args.job_id,
            scanned=args.scanned,
            detector_url=args.detector_url,
        )
    except (LockError, KeyError, tomllib.TOMLDecodeError) as err:
        print(f"::error file={args.lockfile}::cannot build a dependency snapshot: {err}")
        return 1
    text = json.dumps(snapshot, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        Path(args.output).write_text(text, "utf-8")
    print(summary(snapshot["manifests"][MANIFEST]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
