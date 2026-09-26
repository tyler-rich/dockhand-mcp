# Contributing to dockhand-mcp

Thanks for helping. dockhand-mcp is a security tool first, so some things that would be
conveniences elsewhere are rules here. This page says what they are.

- **Security vulnerabilities:** report them privately, never in an issue or a PR
  ([`SECURITY.md`](SECURITY.md)).
- **Bugs:** open an issue with the bug report template.
- **Larger changes:** open an issue first. The locked decisions in [`plan.md`](plan.md) §2 and the
  rules in [`docs/SECURITY.md`](docs/SECURITY.md) (profiles, tiers, authentication, redaction,
  guardrails, approvals) change only after discussion. The `excluded` tier is permanent (D-007):
  a change that exposes an excluded endpoint, behind a flag or otherwise, won't be merged.

## Workflow

1. Fork the repository and branch off **`dev`**: `feat/…`, `fix/…`, `docs/…`, `sec/…` or
   `chore/…`.
2. Open the pull request **against `dev`**, never `main`. `main` holds the last release and
   changes only through a `dev → main` release PR. Pull requests are squash-merged by the
   maintainer.
3. Keep one concern per pull request, with conventional commit messages
   (`fix(stacks): …`, `feat(tools): …`), and fill in the PR template.

## Tests are required

- A behaviour change comes with tests that **fail without it**. For a guardrail, validator or
  redaction, commit the failing test first and name that commit in the PR.
- No test talks to a real DockHand: HTTP is mocked with `respx`, and DockHand responses live
  under `tests/fixtures/dockhand/`. Each fixture's `_comment` says whether it was invented from the
  spec or recorded and sanitised.
- Use the example values: `https://dockhand.example.test`, environment id `7`, and IP addresses
  from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Build fake secrets at runtime (`fake_dh_token()` and `fake_secret()` in `tests/conftest.py`)
  and never commit a token-shaped literal. gitleaks scans every commit of a pull request, and a
  later commit cannot clear a finding.

Run what `ci` runs before you push (with [uv](https://docs.astral.sh/uv/) and the latest stable
Python):

```sh
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src
uv run pytest -q
```

`ci` also runs gitleaks, OSV-Scanner on `uv.lock`, a dependency-freshness check, Semgrep on
`src/`, and a Docker build.

## Adding or changing a tool

Every tool has a pydantic input model (`extra='forbid'`, bounded lengths and ranges, a
description on every field), MCP annotations, a registration through `tools/registry.py` with
its tier and the DockHand endpoints it calls, a row in [`docs/TOOLS.md`](docs/TOOLS.md), and
tests. An endpoint's tier comes from [`docs/api/ENDPOINT-MAP.md`](docs/api/ENDPOINT-MAP.md), and
tests enforce that a tool calls nothing it didn't declare. Tool descriptions are one or two terse
sentences, with no instructions to the model and no deployment details. If a change alters the
tool catalogue, update the snapshots under `tests/fixtures/` in the same PR.

## Dependencies

- Everything is on its newest stable release (plan D-013): refresh with `uv lock --upgrade`.
  Pre-releases are never used, and GitHub Actions are pinned to the full SHA of their newest
  release.
- A new runtime dependency needs a reason in the PR. Its licence must be permissive and
  compatible with Apache-2.0 (no GPL, AGPL, LGPL, SSPL, BUSL or similar).

## Licence

- dockhand-mcp is licensed under the [Apache License 2.0](LICENSE). Under its Section 5, any
  contribution you intentionally submit is licensed under the same terms, with no additional
  terms or conditions. There is no CLA and no sign-off requirement.
- Every file you create under `src/`, `tests/` or `scripts/` starts with
  `# SPDX-License-Identifier: Apache-2.0` (after any shebang); `tests/test_spdx.py` checks it.
- Don't copy code from another project without saying in the PR where it comes from and under
  which licence. DockHand itself is licensed BUSL-1.1: don't copy its code or text into this
  repository.

## Decision log

A behaviour change gets a dated entry in [`docs/ARCHIVE.md`](docs/ARCHIVE.md) §14 (the format is at
the top of that section): what changed, why, and what was rejected. If you're unsure what to
write, say so in the PR and the maintainer will add it before merging.

## Keep your deployment out of it

Don't put your tokens, hostnames, IP addresses, container or stack names, or logs from your
deployment anywhere in a contribution: code, fixtures, commit messages, PR descriptions or
issues. DockHand's OpenAPI document (`docs/api/*.json`) is DockHand's own and stays out of the
repository (`.gitignore` excludes it).
