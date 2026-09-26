# SPDX-License-Identifier: Apache-2.0
"""Release notes and CHANGELOG sections from docs/ARCHIVE.md §14 (plan O-04).

An entry is a `### ` heading under `## §14 Decisions`; past entries are never edited, so an entry
is "new in a release" when its heading is in the ARCHIVE at the release tag and not in the ARCHIVE
at the previous release tag. The release workflow reads both files with `git show` and passes
them in; this script only reads files and prints Markdown. With no previous tag (the first tag of
a repository imported without its tags), the entries after the newest older release's entry are
new (`entries_since_release`).

Entries up to and including the "Public launch" entry were written in the private archive
repository, so their `#n` names that repository's items; on GitHub it would link to this
repository's item of the same number. They render as plain text, `archive PR n` / `archive issue n`
(`localise_references`). Later entries keep `#n`.

    release-notes.py previous-tag --current vX.Y.Z --tags-file tags.txt
    release-notes.py notes --tag vX.Y.Z --archive NEW [--previous-archive OLD --previous-tag vA.B.C]
                           --image ghcr.io/OWNER/NAME --digest sha256:… --repository OWNER/REPO
    release-notes.py changelog --version X.Y.Z --date YYYY-MM-DD --archive NEW
                               [--previous-archive OLD]
"""

import argparse
import io
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# GitHub caps a release body at 125 000 characters; stay well inside it.
MAX_NOTES_CHARS = 100_000

OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RELEASE_WORKFLOW = ".github/workflows/release.yml"

_SECTION = re.compile(r"^## §14\b")
_FENCE = re.compile(r"^(```|~~~)")
_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_DECISION = "**Decision:**"
_LABEL = re.compile(r"^\*\*[^*]+:\*\*")
_RELEASE_HEADING = re.compile(r"[\s,](v\d+\.\d+\.\d+)(?:\s+\(|$)")
_PUBLIC_LAUNCH = re.compile(r"^\d{4}-\d{2}-\d{2} — Public launch\b")
# `#n` or `PR #n` naming an item of this repository; not `owner/repo#n`, `x#1`, `&#39;` or `##`.
_REFERENCE = re.compile(r"(?<![\w/.&#-])(?:\b(PR)\s+)?#(\d+)\b")


@dataclass(frozen=True)
class Entry:
    """One ARCHIVE §14 entry: its heading text (without `### `) and the lines below it."""

    title: str
    body: str


def parse_entries(text: str) -> list[Entry]:
    """The §14 entries in file order. Headings inside fenced code blocks are not entries."""
    entries: list[Entry] = []
    title: str | None = None
    body: list[str] = []
    in_section = in_fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        if in_fence or _FENCE.match(line):
            if title is not None:
                body.append(line)
            continue
        if line.startswith("## "):
            in_section = bool(_SECTION.match(line))
            if title is not None:
                entries.append(Entry(title, "\n".join(body).strip()))
                title, body = None, []
            continue
        if not in_section:
            continue
        if line.startswith("### "):
            if title is not None:
                entries.append(Entry(title, "\n".join(body).strip()))
            title, body = line[4:].strip(), []
        elif title is not None:
            body.append(line)
    if title is not None:
        entries.append(Entry(title, "\n".join(body).strip()))
    return entries


def decision(entry: Entry) -> str:
    """The entry's `**Decision:**` paragraph (with any list directly under it), else its first."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", entry.body) if p.strip()]
    for paragraph in paragraphs:
        if paragraph.startswith(_DECISION):
            # Older entries put `**Why:**` on the very next line: a label ends the paragraph too.
            lines = paragraph[len(_DECISION) :].strip().splitlines()
            end = next((i for i, line in enumerate(lines) if i and _LABEL.match(line)), None)
            return "\n".join(lines[:end]).strip()
    return paragraphs[0] if paragraphs else ""


def new_entries(current: str, previous: str | None) -> list[Entry]:
    """Entries in `current` whose heading is not in `previous` (every entry when it is None)."""
    seen = {e.title for e in parse_entries(previous)} if previous is not None else set()
    return [e for e in parse_entries(current) if e.title not in seen]


def entries_since_release(text: str, tag: str) -> tuple[str | None, list[Entry]]:
    """The entries after the newest release entry below `tag`, and that release's tag.

    For a first tag with no previous tag to compare with, as in a repository imported without its
    history's tags. A release entry is one whose heading ends with the version it released, just
    before the `(PR …)` part ("…, v0.1.0 (PR #23, …)"); a version named elsewhere in a heading
    ("Fix the v0.1.0 label") does not count. Without such an entry, every entry is new.
    """
    now = _version(tag)
    if now is None:
        raise ValueError(f"release tag must look like vX.Y.Z: {tag!r}")
    entries = parse_entries(text)
    for index in range(len(entries) - 1, -1, -1):
        match = _RELEASE_HEADING.search(entries[index].title)
        if match is not None and (version := _version(match.group(1))) is not None:
            if version < now:
                return match.group(1), entries[index + 1 :]
    return None, entries


def archive_references(text: str) -> str:
    """`#n` / `PR #n` as plain `archive issue n` / `archive PR n`, which GitHub does not link."""
    return _REFERENCE.sub(lambda m: f"archive {'PR' if m.group(1) else 'issue'} {m.group(2)}", text)


def localise_references(entries: list[Entry], archive: list[Entry]) -> list[Entry]:
    """`entries` with archive references made plain in those written before the public import.

    Those are the entries of `archive` (the whole §14 log) up to and including its "Public launch"
    entry, whose own PR is an archive PR. Without such an entry nothing changes.
    """
    launch = next((i for i, e in enumerate(archive) if _PUBLIC_LAUNCH.match(e.title)), None)
    if launch is None:
        return list(entries)
    pre_public = {e.title for e in archive[: launch + 1]}
    return [
        Entry(archive_references(e.title), archive_references(e.body))
        if e.title in pre_public
        else e
        for e in entries
    ]


def _version(tag: str) -> tuple[int, int, int] | None:
    match = _TAG.match(tag)
    if match is None:
        return None
    major, minor, patch = (int(g) for g in match.groups())
    return major, minor, patch


def previous_tag(tags: list[str], current: str) -> str | None:
    """The highest `vX.Y.Z` tag below `current`; other tag shapes (pre-releases too) are ignored."""
    now = _version(current)
    if now is None:
        raise ValueError(f"release tag must look like vX.Y.Z: {current!r}")
    older = [(v, t) for t in tags if (v := _version(t.strip())) is not None and v < now]
    return max(older)[1] if older else None


def verify_command(image: str, digest: str, repository: str, tag: str) -> str:
    """The keyless `cosign verify` line for an image this repository's release workflow signed."""
    identity = f"https://github.com/{repository}/{RELEASE_WORKFLOW}@refs/tags/{tag}"
    return (
        f"cosign verify {image}@{digest} "
        f"--certificate-identity={identity} "
        f"--certificate-oidc-issuer={OIDC_ISSUER}"
    )


def _check(tag: str, image: str, digest: str, repository: str) -> None:
    if _version(tag) is None:
        raise ValueError(f"release tag must look like vX.Y.Z: {tag!r}")
    if not _IMAGE.match(image):
        raise ValueError(f"image must be a repository without a tag or digest: {image!r}")
    if not _DIGEST.match(digest):
        raise ValueError(f"digest must be sha256:<64 hex>: {digest!r}")
    if not _REPOSITORY.match(repository):
        raise ValueError(f"repository must be OWNER/REPO: {repository!r}")


def _entry_block(entry: Entry) -> str:
    return f"### {entry.title}\n\n{decision(entry)}\n"


def render_notes(
    *,
    tag: str,
    previous: str | None,
    entries: list[Entry],
    image: str,
    digest: str,
    repository: str,
) -> str:
    """The GitHub release body: image and digest, how to verify it, the changes, the licence."""
    _check(tag, image, digest, repository)
    version = tag[1:]
    head = "\n".join(
        [
            f"## dockhand-mcp {tag}",
            "",
            f"**Image:** `{image}:{version}@{digest}`",
            "",
            "Platforms: `linux/amd64`, `linux/arm64`. Both were scanned with OSV-Scanner before",
            "the push. The image is signed keylessly with cosign; its CycloneDX SBOM is attached",
            "to this release and attested to the image.",
            "",
            "Verify the signature (cosign v2 or later):",
            "",
            "```sh",
            verify_command(image, digest, repository, tag),
            "```",
            "",
            f"## Changes since {previous}" if previous else "## Changes (first release)",
            "",
            f"From [`docs/ARCHIVE.md`](https://github.com/{repository}/blob/{tag}/docs/ARCHIVE.md)"
            " §14, which has each decision's full reasoning.",
            "",
            "",
        ]
    )
    foot = "\n".join(
        [
            "",
            "---",
            "",
            "Licensed under Apache-2.0. `LICENSE` and `NOTICE` are attached to this release;"
            " third-party dependencies carry their own licenses, listed in the SBOM.",
            "",
        ]
    )
    blocks = [_entry_block(e) for e in entries] or ["No ARCHIVE entries since the last release.\n"]
    budget = MAX_NOTES_CHARS - len(head) - len(foot) - 200
    kept: list[str] = []
    for block in blocks:
        if sum(len(b) + 1 for b in kept) + len(block) > budget:
            dropped = len(blocks) - len(kept)
            kept.append(f"*…truncated: {dropped} more entries; see docs/ARCHIVE.md.*\n")
            break
        kept.append(block)
    return head + "\n".join(kept) + foot


def render_changelog(*, version: str, date: str, entries: list[Entry]) -> str:
    """One CHANGELOG.md section: `## [X.Y.Z] — YYYY-MM-DD` and each entry's decision."""
    if _version("v" + version) is None:
        raise ValueError(f"version must look like X.Y.Z: {version!r}")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
        raise ValueError(f"date must look like YYYY-MM-DD: {date!r}")
    lines = [f"## [{version}] — {date}", ""]
    for entry in entries:
        lines.append(_entry_block(entry))
    return "\n".join(lines).rstrip() + "\n"


def _read(path: str | None) -> str | None:
    return None if path is None else Path(path).read_text("utf-8")


def main(argv: list[str] | None = None) -> int:
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")  # ARCHIVE text is not ASCII; Windows consoles
    parser = argparse.ArgumentParser(prog="release-notes.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    prev = sub.add_parser("previous-tag", help="print the release tag before --current, if any")
    prev.add_argument("--current", required=True)
    prev.add_argument("--tags-file", required=True, help="one tag per line (git tag --list)")

    notes = sub.add_parser("notes", help="print the GitHub release body")
    notes.add_argument("--tag", required=True)
    notes.add_argument("--archive", required=True)
    notes.add_argument("--previous-archive")
    notes.add_argument("--previous-tag")
    notes.add_argument("--image", required=True)
    notes.add_argument("--digest", required=True)
    notes.add_argument("--repository", required=True)

    log = sub.add_parser("changelog", help="print one CHANGELOG.md section")
    log.add_argument("--version", required=True)
    log.add_argument("--date", required=True)
    log.add_argument("--archive", required=True)
    log.add_argument("--previous-archive")

    args = parser.parse_args(argv)
    try:
        if args.command == "previous-tag":
            tags = Path(args.tags_file).read_text("utf-8").splitlines()
            found = previous_tag(tags, args.current)
            if found:
                print(found)
            return 0
        paired = (args.previous_archive is None) == (getattr(args, "previous_tag", None) is None)
        if args.command == "notes" and not paired:
            parser.error("--previous-archive and --previous-tag go together")
        archive = Path(args.archive).read_text("utf-8")
        previous = getattr(args, "previous_tag", None)
        if args.previous_archive is not None:
            entries = new_entries(archive, _read(args.previous_archive))
        else:
            tag = args.tag if args.command == "notes" else "v" + args.version
            previous, entries = entries_since_release(archive, tag)
        entries = localise_references(entries, parse_entries(archive))
        if args.command == "notes":
            print(
                render_notes(
                    tag=args.tag,
                    previous=previous,
                    entries=entries,
                    image=args.image,
                    digest=args.digest,
                    repository=args.repository,
                ),
                end="",
            )
        else:
            print(render_changelog(version=args.version, date=args.date, entries=entries), end="")
    except (OSError, ValueError) as exc:
        print(f"release-notes.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
