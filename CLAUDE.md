# CLAUDE.md — dockhand-mcp

You are working on **dockhand-mcp**, a security-first MCP server that exposes a curated, profile-gated subset of the DockHand REST API to AI clients. Read this file fully before doing anything.

## Read first, every session

1. `plan.md` — the whole file: goals, **locked decisions D-001…D-015**, requirements, phases.
2. `docs/SECURITY.md` — threat model and the rules that override convenience.
3. `docs/TOOLS.md` — the tool catalogue (names, tiers, endpoints, permission strings).
4. `docs/api/ENDPOINT-MAP.md` — every DockHand endpoint with its tier. The tier column is a security decision.
5. `docs/ARCHIVE.md` §14 — **all** entries: what previous sessions decided and why.
6. The session prompt you were given (pasted as the first message), and any handoff doc it names.

The **source of truth for DockHand's API is `docs/api/dockhand-openapi-1.0.46.json`** (the raw `/api/docs` document). It is git-ignored and never committed; depending on the session it is either attached to your first message or already present at that path. If you need it and have neither, STOP and ask for it. Not the manual, not the reference implementation, not this file's paraphrases. When the prompt, an issue, or your own assumption disagrees with the spec, the spec wins — and if the spec looks wrong or ambiguous, STOP and ask.

## Hard rules (these are not preferences)

- **Never** add code that reads `/var/run/docker.sock`, shells out (`subprocess`, `os.system`), or mounts host paths. This server is an HTTP client of DockHand and nothing else (D-003).
- **Never** expose an endpoint whose tier is `excluded` in `docs/api/ENDPOINT-MAP.md` (D-007). Not behind a flag, not "for debugging". The only internal (non-tool) calls to excluded endpoints are the two listed in `docs/SECURITY.md` §4.
- **Never** log, echo, or include in a tool result: bearer tokens, `dh_` tokens, `Authorization` headers, full compose file contents in logs, `.env` values in logs, or DockHand request headers.
- **Never** register a tool outside its profile. Tools are registered at startup based on `DOCKHAND_MCP_PROFILE`; there is no runtime elevation path.
- **Never** hard-code hostnames, IPs, environment IDs, stack names, usernames, or file paths from any specific deployment. Tests use `https://dockhand.example.test` and environment id `7`.
- **Never** weaken a guardrail, a validator, a redaction, or a `confirm` gate to make a test pass. If a guardrail blocks something legitimate, STOP and ask.
- **Never** merge. Open the PR against `dev` and post the link.
- **Never** push to, branch from, or open a PR against `main`, unless your prompt explicitly asks for the `dev → main` release PR. `main` is the **default** branch, so `gh pr create` without `--base dev` targets `main` — always pass `--base dev`, and confirm the base with `gh pr view --json baseRefName` after creating the PR.
- **Never** commit `docs/api/*.json` (the DockHand OpenAPI document stays local; `.gitignore` already excludes it).

## STOP-and-ask conditions

Stop and ask the maintainer before continuing if you would need to:

- change any locked decision in `plan.md` §2;
- change a tier in `scripts/gen-endpoint-map.py` / `docs/api/ENDPOINT-MAP.md` / `docs/TOOLS.md`;
- change the auth flow, token handling, redaction, or rate-limit behaviour in a way the prompt did not explicitly ask for;
- add a runtime dependency (each one needs justification in the PR and ARCHIVE entry);
- pin anything below its newest stable release because the newest breaks something — report what breaks; the maintainer decides whether to wait or work around, and a temporary pin needs a dated ARCHIVE entry with a removal condition;
- change the config schema (env var names/semantics) after Phase 1;
- change the uniform result envelope or error shape after Phase 1;
- touch `deploy/` hardening flags (`user`, `read_only`, `cap_drop`, `security_opt`, ports);
- exceed the scope of the prompt by more than a small refactor (anything that would be its own PR is its own PR).

## Engineering standard

- Python: the **latest stable CPython series** (3.14 today; see `plan.md` D-001/D-013). `uv`, `ruff` (lint+format), `mypy --strict`, `pytest` + `pytest-asyncio` + `respx` for HTTP mocking. `uv run` for everything; never `pip install` into the system.
- **Latest-everything (D-013):** at the start of every session run `uv lock --upgrade && uv sync` and commit the lockfile change if any; check python.org for a newer stable minor than `requires-python` and, if one exists, bump `requires-python`, the base image, and CI in *this* PR (or STOP and ask if that bump breaks a dependency). Never add a dependency at anything but its newest stable version. Never pin a GitHub Action to anything but the SHA of its newest release. Never use a pre-release. Record the versions you ended up with in the ARCHIVE entry.
- Licensing (D-015): every source file you create under `src/`, `tests/` or `scripts/` starts with `# SPDX-License-Identifier: Apache-2.0` (after any shebang). Never edit `LICENSE` or `NOTICE`, never add a dependency whose license is not permissive and Apache-2.0-compatible (GPL/AGPL/LGPL/SSPL/BUSL and similar → STOP and ask), and never copy code from another project without stating its license and origin in the PR.
- Every tool declares, at registration, the DockHand `(method, path-template)` pairs it calls. The endpoint-map test and the respx tests enforce that a tool calls nothing it didn't declare and declares nothing above its tier.
- Every tool: pydantic v2 input model with `extra='forbid'`, bounded lengths and ranges, `Field(description=…)` on every field; MCP annotations set; registered through `tools/registry.py` with an explicit tier; documented in `docs/TOOLS.md`.
- Tool descriptions: one or two terse sentences, what it does and what it returns. No "IMPORTANT", no conditional instructions, no references to other tools by name, no deployment details.
- Uniform envelopes (defined in Phase 1, `client/envelope.py`): every result is JSON with `ok`, `environment_id` (when applicable), and either `data` or `error{code,message,dockhand_status?}`. Async operations add `operation{kind: job|sse|detached, id, status, waited_seconds, timed_out}`.
- Tests that prove a behaviour must **fail without it**. When adding a guardrail or validator, first commit the test failing, then the implementation. Say which commit had the failing test in the PR body.
- Contract tests use recorded DockHand responses in `tests/fixtures/dockhand/` (sanitized; no real IDs/hosts). When a fixture is invented rather than recorded, say so in a comment.
- Verify at the source. Do not trust: the summary line in the OpenAPI doc (check parameters and response schema), the reference implementation's tool behaviour, the manual's prose, or the prompt's framing. If a DockHand endpoint's real response shape is unknown, mark the tool `experimental` in `docs/TOOLS.md` and say so.

## Workflow

The maintainer reviews and merges; **you do all the running and checking** and prove it in a Verification report. Don't hand verification steps back to the maintainer unless they genuinely need a human (a GitHub UI setting, a release tag, a judgement call).

1. **Start clean.** `git fetch --prune`, `git checkout dev && git pull`, then delete local branches whose upstream is gone (`git branch -vv` shows `: gone]`; delete those with `git branch -D`). Then `git checkout -b <type>/<short-name>` (`feat/`, `fix/`, `docs/`, `sec/`, `chore/`). Check `git config user.name` / `user.email`: if either is `Claude` / `noreply@anthropic.com` or otherwise not the maintainer's GitHub identity, STOP and ask — never commit under a default or invented identity.
2. Do the work. Keep commits small and conventional (`feat(tools): add dockhand_list_stacks`). Commit failing tests before the code that makes them pass, and note that commit's hash.
3. Add the dated entry to `docs/ARCHIVE.md` §14: what changed, why, alternatives rejected, anything deferred.
4. Run the full local suite: `uv sync --frozen && uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src && uv run pytest -q`. Everything must pass before you open the PR.
5. **Prove the failing tests fail.** In a throwaway worktree, so your branch is untouched: `git worktree add ../dmcp-failcheck <failing-test-commit>`, run `uv run pytest -q` there, record the failure count and which tests failed, then `git worktree remove --force ../dmcp-failcheck`. If nothing fails at that commit, the tests aren't proving anything: fix them before continuing.
6. Run the **live checks** your prompt lists, if any (rules below).
7. `gh pr create --base dev --title "…" --body-file <file>`. Fill the PR template. Confirm the base with `gh pr view --json baseRefName`. **Do not merge.**
8. Strip any AI attribution footer from the PR body with **one** `gh pr edit --body-file` attempt, then re-read the live body (`gh pr view --json body -q .body`). The PR body describes the change only: never the session's own process (identity checks, footer status, merge permissions, stop-condition commentary). That belongs in your chat summary.
9. **Attribution and identity check:** confirm the live PR body contains none of `Generated with`, `Co-Authored-By`, `claude.ai/code`; confirm `git log origin/dev..HEAD --format='%an <%ae>%n%B'` shows only the maintainer's identity and none of those strings. If a footer survived, say so (don't retry).
10. Watch `ci` if your environment allows (`gh pr checks --watch`). If it doesn't (e.g. the Desktop app doesn't permit polling), read the status once, report it as pending in the Verification report, and add 'Confirm `ci` is green before merging' to Maintainer actions. If `ci` fails, fix it and push again until it's green.
11. Post in chat: the PR link, a 5–10 line summary, and a **Verification report** — a table with one row per check (local suite; failing-test proof with commit hash and failure count; each live check; attribution/identity; `ci` status and duration) showing the command you ran and the outcome. End with **"Maintainer actions"**: only the steps that genuinely need a human, numbered. For most PRs that is just "review and squash-merge".

### Live checks against DockHand

Some prompts ask you to exercise the server against the maintainer's real DockHand. The maintainer keeps connection settings in `secrets/dev-env.sh` (git-ignored). Load it with `set -a; . secrets/dev-env.sh; set +a` in the same shell command as the check.

- **Never** print, `cat`, `Read`, echo, or log the contents of anything under `secrets/`, and never put a token in a command line. The server reads token files itself via `*_FILE` variables.
- **Read-only unless the prompt says otherwise.** Use `DOCKHAND_MCP_PROFILE=read-only` except where a prompt explicitly authorises `operator` or `admin`. Write/destructive live checks run **only** against `DOCKHAND_MCP_TEST_ENVIRONMENT_ID` from `dev-env.sh`, and only on resources you created in that session, named with the prefix `mcp-smoke-`. If that variable is unset, skip the write checks and say so.
- Clean up everything you created, even if a check fails.
- **Never** run `dockhand_prune` or `dockhand_run_image_prune_now` live: a test environment may share a Docker daemon with production. Prune is covered by unit tests only.
- Real hostnames, container names, logs and other live data may appear in your chat report, but **never** in committed files, test fixtures, PR bodies or commit messages.
- If DockHand is unreachable or `secrets/dev-env.sh` is missing, report the live checks as "not run" with the reason. Don't block the PR on them.

## Definitions

- **Tier** — `read` / `operator` / `destructive` / `admin` / `excluded`; property of an endpoint→tool mapping (see `docs/api/ENDPOINT-MAP.md` legend).
- **Profile** — `read-only` / `operator` / `admin`; property of a running server; selects which tiers are registered.
- **Principal** — the authenticated MCP caller (name + profile ceiling). v1 has exactly one principal per server instance.
- **Read-back verification** — after a write to DockHand that persists content (compose, `.env` raw), immediately GET it back and compare (byte-equal, or hash); report `verified: true/false` and a diff summary on mismatch. Never report success without it.
