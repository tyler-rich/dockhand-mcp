## Summary

<!-- What changed and why. -->

Failing-test commit: <!-- hash of the commit where the new tests failed -->

## Definition of done (plan.md §7)

- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src` clean
- [ ] `uv run pytest -q` green; new behaviour has tests that were **verified to fail** before the implementation landed (the PR description names the commit where they failed)
- [ ] No new tool without: pydantic input model, annotations, tier + profile registration, permission strings documented in `docs/TOOLS.md`, an entry in `dockhand-mcp tools` output, and a test
- [ ] `docs/ARCHIVE.md` §14 entry, dated, with the decision and reasoning
- [ ] Every new or changed source file under `src/`, `tests/`, `scripts/` starts with `# SPDX-License-Identifier: Apache-2.0` (D-015)
- [ ] No secrets, internal hostnames, IPs or deployment-specific values in the diff (gitleaks passes)
- [ ] PR opened against `dev`, not merged, link posted; attribution footer stripped from the PR body (re-read the live body to confirm)
- [ ] Verification report posted in chat (CLAUDE.md Workflow step 11): local suite, failing-test proof, live checks the prompt required, attribution/identity, `ci` green
