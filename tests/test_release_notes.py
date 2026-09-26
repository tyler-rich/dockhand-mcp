# SPDX-License-Identifier: Apache-2.0
"""scripts/release-notes.py: GitHub release notes and CHANGELOG sections from ARCHIVE §14."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-notes.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "release-notes"
V010 = FIXTURES / "ARCHIVE-v0.1.0.md"
V020 = FIXTURES / "ARCHIVE-v0.2.0.md"

OWNER_REPO = "example-owner/dockhand-mcp"
IMAGE = "ghcr.io/example-owner/dockhand-mcp"
DIGEST = "sha256:" + "ab" * 32
ISSUER = "https://token.actions.githubusercontent.com"

ALPHA = "2026-01-02 — Alpha scaffold (PR #1, branch chore/alpha)"
BETA = "2026-01-05 — Beta read tools (PR #2, branch feat/beta)"
GAMMA = "2026-02-10 — Gamma write tools (PR #3, branch feat/gamma)"
DELTA = "2026-02-11 — Delta release pipeline, v0.2.0 (PR #4, branch chore/delta)"


@pytest.fixture(scope="module")
def rn() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["release_notes"] = module
    spec.loader.exec_module(module)
    return module


def test_entries_skip_the_format_block(rn: ModuleType) -> None:
    entries = rn.parse_entries(V010.read_text("utf-8"))
    assert [e.title for e in entries] == [ALPHA, BETA]


def test_decision_paragraph_with_its_list(rn: ModuleType) -> None:
    alpha = rn.parse_entries(V010.read_text("utf-8"))[0]
    assert rn.decision(alpha) == (
        "The alpha skeleton: a registry and a health tool.\n"
        "- first detail line;\n"
        "- second detail line."
    )


def test_decision_found_after_another_paragraph(rn: ModuleType) -> None:
    gamma = rn.parse_entries(V020.read_text("utf-8"))[2]
    assert rn.decision(gamma) == "Gamma writes, with read-back verification."


def test_decision_ends_at_the_next_label(rn: ModuleType) -> None:
    delta = rn.parse_entries(V020.read_text("utf-8"))[3]
    assert rn.decision(delta) == "Ship delta."


def test_entries_since_the_previous_tag(rn: ModuleType) -> None:
    new = rn.new_entries(V020.read_text("utf-8"), V010.read_text("utf-8"))
    assert [e.title for e in new] == [GAMMA, DELTA]


def test_first_release_takes_every_entry(rn: ModuleType) -> None:
    new = rn.new_entries(V010.read_text("utf-8"), None)
    assert [e.title for e in new] == [ALPHA, BETA]


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        ("v0.2.0", "v0.1.0"),
        ("v0.1.0", None),
        ("v0.10.0", "v0.9.1"),
        ("v1.0.0", "v0.10.0"),  # not yet in the list: the newest older tag
    ],
)
def test_previous_tag(rn: ModuleType, current: str, expected: str | None) -> None:
    tags = ["v0.2.0", "v0.1.0", "v0.10.0", "v0.9.1", "v0.3.0-rc1", "latest", "v0.9", ""]
    assert rn.previous_tag(tags, current) == expected


def test_previous_tag_rejects_a_non_release_tag(rn: ModuleType) -> None:
    with pytest.raises(ValueError, match=r"vX.Y.Z"):
        rn.previous_tag(["v0.1.0"], "v0.2.0-rc1")


def notes_v020(rn: ModuleType) -> str:
    text: str = rn.render_notes(
        tag="v0.2.0",
        previous="v0.1.0",
        entries=rn.new_entries(V020.read_text("utf-8"), V010.read_text("utf-8")),
        image=IMAGE,
        digest=DIGEST,
        repository=OWNER_REPO,
    )
    return text


def test_notes_carry_only_the_new_entries(rn: ModuleType) -> None:
    notes = notes_v020(rn)
    assert GAMMA in notes and DELTA in notes
    assert "Gamma writes, with read-back verification." in notes
    assert ALPHA not in notes and BETA not in notes
    assert "since v0.1.0" in notes


def test_notes_carry_digest_verify_line_and_license(rn: ModuleType) -> None:
    notes = notes_v020(rn)
    assert f"{IMAGE}:0.2.0@{DIGEST}" in notes
    verify = (
        f"cosign verify {IMAGE}@{DIGEST} "
        f"--certificate-identity=https://github.com/{OWNER_REPO}"
        "/.github/workflows/release.yml@refs/tags/v0.2.0 "
        f"--certificate-oidc-issuer={ISSUER}"
    )
    assert verify in notes
    assert "Licensed under Apache-2.0" in notes


def test_first_release_notes(rn: ModuleType) -> None:
    notes = rn.render_notes(
        tag="v0.1.0",
        previous=None,
        entries=rn.new_entries(V010.read_text("utf-8"), None),
        image=IMAGE,
        digest=DIGEST,
        repository=OWNER_REPO,
    )
    assert "first release" in notes
    assert ALPHA in notes and BETA in notes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("digest", "sha256:abc"),
        ("digest", "latest"),
        ("image", "ghcr.io/example-owner/dockhand-mcp:latest"),
        ("repository", "not a repo"),
        ("tag", "0.2.0"),
    ],
)
def test_notes_refuse_malformed_inputs(rn: ModuleType, field: str, value: str) -> None:
    kwargs = {
        "tag": "v0.2.0",
        "previous": "v0.1.0",
        "entries": [],
        "image": IMAGE,
        "digest": DIGEST,
        "repository": OWNER_REPO,
    }
    kwargs[field] = value
    with pytest.raises(ValueError):
        rn.render_notes(**kwargs)


def test_notes_are_capped(rn: ModuleType) -> None:
    body = "\n".join(
        f"### 2026-03-{i % 28 + 1:02d} — Entry {i}\n**Decision:** {'x' * 5000}\n" for i in range(60)
    )
    notes = rn.render_notes(
        tag="v0.2.0",
        previous=None,
        entries=rn.parse_entries("## §14 Decisions\n\n" + body),
        image=IMAGE,
        digest=DIGEST,
        repository=OWNER_REPO,
    )
    assert len(notes) <= rn.MAX_NOTES_CHARS
    assert "Licensed under Apache-2.0" in notes
    assert "truncated" in notes


def test_changelog_section(rn: ModuleType) -> None:
    section = rn.render_changelog(
        version="0.2.0",
        date="2026-02-11",
        entries=rn.new_entries(V020.read_text("utf-8"), V010.read_text("utf-8")),
    )
    assert section.startswith("## [0.2.0] — 2026-02-11\n")
    assert GAMMA in section and DELTA in section and ALPHA not in section


def test_cli_notes(rn: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    code = rn.main(
        [
            "notes",
            "--tag",
            "v0.2.0",
            "--archive",
            str(V020),
            "--previous-archive",
            str(V010),
            "--previous-tag",
            "v0.1.0",
            "--image",
            IMAGE,
            "--digest",
            DIGEST,
            "--repository",
            OWNER_REPO,
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert GAMMA in out and ALPHA not in out


def test_cli_previous_tag(
    rn: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("v0.1.0\nv0.2.0\n", "utf-8")
    assert rn.main(["previous-tag", "--current", "v0.2.0", "--tags-file", str(tags)]) == 0
    assert capsys.readouterr().out == "v0.1.0\n"
    assert rn.main(["previous-tag", "--current", "v0.1.0", "--tags-file", str(tags)]) == 0
    assert capsys.readouterr().out == ""


# A repository imported without its tags: the first tag has no previous tag, so the notes start
# after the ARCHIVE entry that released the newest older version.
IMPORT = FIXTURES / "ARCHIVE-public-import.md"
RELEASE_010 = "2026-01-10 — Release pipeline and docs, v0.1.0 (PR #2, branch chore/release)"
LABEL_FIX = "2026-01-12 — Fix the v0.1.0 image label (PR #3, branch fix/label)"
LAUNCH = "2026-01-20 — Public launch (PR #4, branch chore/public-launch)"
# How the notes render those headings: entries up to and including the public launch name the
# archive repository's PRs and issues, as plain text that GitHub does not link.
LABEL_FIX_OUT = "2026-01-12 — Fix the v0.1.0 image label (archive PR 3, branch fix/label)"
LAUNCH_OUT = "2026-01-20 — Public launch (archive PR 4, branch chore/public-launch)"


def test_without_a_previous_tag_entries_start_after_the_release_entry(rn: ModuleType) -> None:
    previous, entries = rn.entries_since_release(IMPORT.read_text("utf-8"), "v0.1.1")
    assert previous == "v0.1.0"
    # "Fix the v0.1.0 image label" names the version but did not release it.
    assert [e.title for e in entries] == [LABEL_FIX, LAUNCH]


def test_a_release_entry_at_the_current_version_is_not_a_baseline(rn: ModuleType) -> None:
    previous, entries = rn.entries_since_release(IMPORT.read_text("utf-8"), "v0.1.0")
    assert previous is None
    assert len(entries) == 4


def test_without_any_release_entry_every_entry_is_new(rn: ModuleType) -> None:
    previous, entries = rn.entries_since_release(V010.read_text("utf-8"), "v0.1.0")
    assert previous is None
    assert [e.title for e in entries] == [ALPHA, BETA]


def test_cli_notes_without_a_previous_tag(
    rn: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    code = rn.main(
        [
            "notes",
            "--tag",
            "v0.1.1",
            "--archive",
            str(IMPORT),
            "--image",
            IMAGE,
            "--digest",
            DIGEST,
            "--repository",
            OWNER_REPO,
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "## Changes since v0.1.0" in out
    assert "first release" not in out
    assert LABEL_FIX_OUT in out and LAUNCH_OUT in out
    assert RELEASE_010 not in out and "Alpha scaffold" not in out


def test_cli_changelog_without_a_previous_archive(
    rn: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    code = rn.main(
        ["changelog", "--version", "0.1.1", "--date", "2026-01-21", "--archive", str(IMPORT)]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert LAUNCH_OUT in out and LABEL_FIX_OUT in out
    assert RELEASE_010 not in out and "Alpha scaffold" not in out


# Before the public launch, `#n` named the private archive repository's items; on GitHub it would
# link to this repository's item of the same number. Those entries (the launch entry included,
# whose own PR is an archive PR) render references as plain text; later entries keep `#n`.
REFS = FIXTURES / "ARCHIVE-public-refs.md"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Fix #6: x (PR #8, branch b)", "Fix archive issue 6: x (archive PR 8, branch b)"),
        ("replaces PR #2)", "replaces archive PR 2)"),
        ("Fixes #9, which files #10.", "Fixes archive issue 9, which files archive issue 10."),
        ("filed as #17", "filed as archive issue 17"),
        ("see anthropics/claude-ai-mcp#153", "see anthropics/claude-ai-mcp#153"),
        ("`x#1`, a&#39;b, ## Heading, #anchor", "`x#1`, a&#39;b, ## Heading, #anchor"),
    ],
)
def test_archive_references_become_plain_text(rn: ModuleType, text: str, expected: str) -> None:
    assert rn.archive_references(text) == expected


def test_pre_public_entries_are_those_up_to_the_public_launch(rn: ModuleType) -> None:
    entries = rn.parse_entries(REFS.read_text("utf-8"))
    assert [e.title for e in rn.localise_references(entries, entries)] == [
        "2026-01-10 — Release pipeline and docs, v0.1.0 (archive PR 2, branch chore/release)",
        "2026-01-12 — Fix archive issue 5: stale label"
        " (archive PR 6, branch fix/label; replaces archive PR 3)",
        "2026-01-20 — Public launch (archive PR 7, branch chore/public-launch)",
        "2026-01-22 — Fix #3: after the launch (PR #4, branch fix/after)",
    ]


def test_without_a_public_launch_entry_references_are_unchanged(rn: ModuleType) -> None:
    entries = rn.parse_entries(V010.read_text("utf-8"))
    assert rn.localise_references(entries, entries) == entries


@pytest.mark.parametrize("command", ["notes", "changelog"])
def test_cli_renders_archive_references_as_plain_text(
    rn: ModuleType, capsys: pytest.CaptureFixture[str], command: str
) -> None:
    if command == "notes":
        args = ["notes", "--tag", "v0.1.1", "--archive", str(REFS), "--image", IMAGE]
        args += ["--digest", DIGEST, "--repository", OWNER_REPO]
    else:
        args = ["changelog", "--version", "0.1.1", "--date", "2026-01-23", "--archive", str(REFS)]
    assert rn.main(args) == 0
    out = capsys.readouterr().out
    pre, _, post = out.partition("### 2026-01-22")
    assert "Fix archive issue 5: stale label (archive PR 6," in pre
    assert "Fixes archive issue 5, filed after upstream owner/other#12." in pre
    assert "Public launch (archive PR 7," in pre
    assert "history stays in archive PR 1 through archive PR 7." in pre
    assert "#5" not in pre and "#6" not in pre and "#7" not in pre
    assert post.startswith(" — Fix #3: after the launch (PR #4, branch fix/after)")
    assert "Fixes #3, reported in this repository." in post
