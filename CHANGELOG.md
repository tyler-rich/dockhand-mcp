# Changelog

Notable changes per release, generated from the decision log in [`docs/ARCHIVE.md`](docs/ARCHIVE.md) §14
by `scripts/release-notes.py changelog` (each entry's decision; the log has the reasoning).
Versions follow [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-10-30

Supported DockHand: 1.0.55. **Python 3.15 is required for source installs**; the Docker image is the recommended install.

- **New tools:** `dockhand_get_stack_stats` (read tier, #18), `dockhand_get_scheduled_actions` (read tier, #19) and `dockhand_set_scheduled_actions` (operator tier, #19).
- **Schedule allowlist:** `dockhand_run_schedule_now` and `dockhand_toggle_schedule` now accept `container_start` and `container_stop`.
- **Behaviour change:** `dockhand_update_containers` reports skipped, unverified and unknown containers, and returns `ok: false` when any requested container wasn't confirmed updated (#20).
- **New `check` problem:** "cannot identify own container", when the server runs in a container whose id it can't find and its profile registers `dockhand_set_scheduled_actions`.
- **Security:** `opentelemetry-api` ≥ 1.45.1 fixes unbounded tracestate parsing (the repository's first Dependabot alert).
- **Dependencies and tooling:** mcp 2.3.0 and a dependency refresh; GitHub Actions bumps `astral-sh/setup-uv` 10.3.2, `docker/login-action` 4.7.0 and `anchore/sbom-action` 0.24.3 (#17); the image's `uv` stage 0.13.6 (#22); release tooling OSV-Scanner v2.7.0, cosign v3.1.4 and syft v1.55.0 (#27).
- OAuth is not part of this release.

### 2026-10-28 — DockHand API 1.0.55 and dependency refresh (PR #21, branch chore/dockhand-api-1.0.55)

DockHand API 1.0.55 is the reference spec (`docs/api/dockhand-openapi-1.0.55.json`, git-ignored). The map and `env_required.py` are regenerated from it; the 26 new operations are classified and **no tool is added**. In the same PR: CPython 3.15, a full dependency refresh (which supersedes the open Dependabot uv PR), and the removal of `ToolsOnlyServer`, which mcp 2.3.0 made redundant. Supported DockHand: 1.0.55 (README, D-012, `CLAUDE.md`, `docs/api/README.md`, the bug-report placeholder, DOCKHAND-SETUP's Perm source).

### 2026-10-30 — uv build backend and deps-current coverage (branch chore/uv-toolchain)

`uv_build` moves to `>=0.13.6,<0.14`, and `ci`'s deps-current step gains `scripts/deps-current.py`, which fails when a hand-maintained pin is behind its newest stable release. The spec-dependent tests take the spec path from `DOCKHAND_MCP_SPEC_PATH`.

### 2026-10-30 — Fix #20: update_containers reports skipped and unverified containers (PR #24, branch fix/issue-20-update-skips)

`dockhand_update_containers` reports a container as `succeeded` only when DockHand says `success: true` and nothing in its result says otherwise. The call is `ok: true` only when every requested container `succeeded`; any other outcome is `operation_failed` (existing code), with the counts in the message, e.g. "1 of 2 containers were not confirmed updated: 1 skipped; see data.items". `data.items` and `data.summary` are still returned.

### 2026-10-30 — Fix #18: dockhand_get_stack_stats (branch feat/stack-stats)

One read-tier tool, `dockhand_get_stack_stats`, answers "which stack is using the most CPU or memory?" in one call instead of summing `dockhand_get_all_container_stats` by each entry's `stack`. It reads `GET /api/stack-stats?env` (`env` always sent) and declares that plus `GET /api/environments` for defaulting (F-09, as `dockhand_list_tags`). Registered `Tier.READ` (all three profiles), `title`, `readOnlyHint: true`, the page `outputSchema`, output through the usual redaction pass.

### 2026-10-30 — Fix #19: scheduled container start/stop (branch feat/scheduled-actions)

Two tools for DockHand 1.0.55's scheduled container start and stop. `dockhand_get_scheduled_actions` (read tier, all three profiles) returns a container's schedule. `dockhand_set_scheduled_actions` (operator tier) sets or clears it. `dockhand_run_schedule_now` and `dockhand_toggle_schedule` now also accept `container_start` and `container_stop`. Tools: 100 (53 read, 37 operator, 10 destructive).

### 2026-10-30 — Fix #19 follow-up: an unidentifiable own container is reported (branch feat/scheduled-actions)

**Decision (maintainer, review of the PR above):** when this server cannot find its own container id, the stop protection must not lapse silently. Stops are not refused because of it.

### 2026-10-30 — Release-tool pins and their deps-current coverage (branch chore/release-tool-pins)

The tools the workflows download move to their newest stable releases, and `scripts/deps-current.py` now fails when any of them falls behind.
- `OSV_SCANNER_VERSION` v2.6.0 → **v2.7.0** in `ci.yml`, `release.yml` and `image-scan.yml`. `OSV_SCANNER_SHA256` is the `osv-scanner_linux_amd64` line of v2.7.0's own `osv-scanner_SHA256SUMS`, fetched for this change; the downloaded binary hashes to it.
- `COSIGN_VERSION` v3.1.3 → **v3.1.4** and `SYFT_VERSION` v1.52.0 → **v1.55.0** in `release.yml`. They are installed by `sigstore/cosign-installer` and `anchore/sbom-action`, which take a version only; both actions are already at their newest releases.
- `GITLEAKS_VERSION` 8.30.1 is already the newest release.

### 2026-10-30 — Release v0.3.0 (branch chore/release-0.3.0)

Version 0.3.0 (`pyproject.toml`, `__version__`, `uv.lock`'s own entry). It ships the changes recorded since the v0.2.0 entry. New tools make this a minor release.
- **Python 3.15 is required for source installs** (`requires-python`). The Docker image is the recommended install; README and CHANGELOG say so.
- **Supported DockHand: 1.0.55.**
- **Three new tools:** `dockhand_get_stack_stats` (read, #18), `dockhand_get_scheduled_actions` (read, #19) and `dockhand_set_scheduled_actions` (operator, #19). Tools: 100 (53 read, 37 operator, 10 destructive).
- **Schedule allowlist:** `dockhand_run_schedule_now` and `dockhand_toggle_schedule` now accept `container_start` and `container_stop` (#19). Every other non-operator schedule type is still refused.
- **Behaviour change in `dockhand_update_containers` (#20):** a container is reported `succeeded` only when nothing in DockHand's result says otherwise. Skipped, unverified and unknown containers are reported, and the call is `ok: false` (`operation_failed`) when any requested container was not confirmed updated.
- **New `check` problem:** with a profile that registers `dockhand_set_scheduled_actions`, running in a container whose id this server cannot find is a `check` problem (outside a container, a warning).
- **Security fix:** `opentelemetry-api` ≥ 1.45.1 (now 1.45.2) fixes unbounded tracestate parsing (the repository's first Dependabot alert).
- Also since v0.2.0: mcp 2.3.0 and a dependency refresh (#21); the `ToolsOnlyServer` override removed (#21); Semgrep in `ci` runs on CPython 3.14 (#21); the `uv_build` 0.13 backend and `deps-current` coverage of hand-maintained pins (#23); the release tools OSV-Scanner v2.7.0, cosign v3.1.4 and syft v1.55.0, with `deps-current` now checking them and gitleaks (#27).
- **Dependabot PRs merged without their own entry:** #17 bumps the GitHub Actions `astral-sh/setup-uv` 10.2.0 → 10.3.2, `docker/login-action` 4.6.0 → 4.7.0 and `anchore/sbom-action` 0.24.2 → 0.24.3 (each pinned by SHA); the release workflow's registry login and SBOM steps run these versions for the first time in this release. #22 bumps the Dockerfile's `astral-sh/uv` stage 0.12.19 → 0.13.6.

## [0.2.0] — 2026-09-27

Supported DockHand: 1.0.49.

### 2026-09-27 — DockHand API 1.0.49 (PR #4, branch chore/dockhand-api-1.0.49)

DockHand API 1.0.49 is the reference spec (`docs/api/dockhand-openapi-1.0.49.json`, git-ignored). The generator's default, `CLAUDE.md`, `docs/api/README.md`, D-012's pinned value, the README's tested version, DOCKHAND-SETUP's Perm-column source and the bug-report placeholder now say 1.0.49. `docs/api/ENDPOINT-MAP.md` is regenerated from it. No existing operation changed tier, no tool was added, and no `src/` code changed. Mentions of 1.0.46 that record what was observed live at the time (ARCHITECTURE, TOOLS status notes, code comments, earlier entries) are history and stay.

### 2026-09-27 — Fix #5: env guard in client (PR #6, branch fix/issue-5-env-guard)

`client/dockhand.py` refuses, before anything is sent, a request to an operation whose environment query parameter DockHand requires when that parameter is missing, `None` or blank. The check is in `DockhandClient._admit`, which every request path already calls (`_request`, so `get_json`/`post_json`/`put_json`/`delete_json`/`raw`; `stream_sse`; `probe_status`, which sends no query and so is refused for any such operation), after the declared-endpoint and read-only-phase checks and before the recorder. No tool's inputs or outputs changed, and no tool needed a fix: every existing call already sends the parameter.

### 2026-09-27 — Fix #3: dockhand_list_tags (PR #7, branch feat/list-tags)

One read-tier tool, `dockhand_list_tags`, answers "what's tagged X?" and lets a client pick containers or stacks by tag before acting on them. It reads `GET /api/tags` (the global catalogue), `GET /api/container-tags?env` and `GET /api/stack-tags?env`, and returns in the uniform envelope:
- `tags`: the catalogue, `[{id, name, color}]`;
- `containers` and `stacks`: `{name: [tag names]}` for the environment, with untagged resources omitted;
- tag ids resolved to names through the catalogue; an id the catalogue lacks appears as `"#<id>"` and adds one warning listing the missing ids;
- a per-environment answer that is not a JSON object is shown as `{}` with a warning, never as silently empty.

### 2026-09-27 — Release v0.2.0 (PR #8, branch chore/release-0.2.0)

Version 0.2.0 (`pyproject.toml`, `__version__`, `uv.lock`'s own entry). It ships the changes recorded since the v0.1.1 entry: DockHand API 1.0.49 as the reference spec (the endpoint map regenerated; the two new container operations `exec/run` and `files/chown` excluded; tag reads `read`, container-tag assignment `operator`, tag catalogue writes `admin`), the client-level guard that refuses a request to an operation whose environment parameter DockHand requires when that parameter is missing (#5), and the new read-tier tool `dockhand_list_tags` (#3, experimental). A new tool makes this a minor release. **Supported DockHand: 1.0.49.** OAuth resource-server mode is not part of this release: `docs/handoff/oauth-resource-server.md` remains a design only, and no `oauth` auth mode exists.

## [0.1.1] — 2026-09-26

### 2026-09-26 — Fix archive issue 17: 5xx after save; scan after pull (archive PR 25, branch fix/issue-17)

The two questions S3f left open, deferred to after v0.1.0 as archive issue 17, are fixed for v0.1.1.
- A content write that DockHand answers with a 5xx, or whose connection drops after the request was sent, is read back once. The result says whether the content was saved.
- `dockhand_pull_image` with `scan_after_pull` reads the scan's outcome from the pull's own events. A pull whose scan failed is never a success.

### 2026-09-26 — Scoping: OAuth resource-server mode (archive PR 26, branch docs/scoping-oauth)

Phase 5 scoping only; no code or configuration changed. `docs/handoff/oauth-resource-server.md` holds the full design, evidence and test plan. Every claim in it carries a source fetched on 2026-09-26, marked verified or unverified. Recommendation:
- **Implement `oauth` mode now, as our own middleware** in the auth slot of the ARCHITECTURE §3 pipeline, beside `BearerAuthMiddleware`.
- **Validate JWT access tokens with PyJWT** (already in `uv.lock` through `mcp`). Serve RFC 9728 metadata at the path-inserted well-known URI, using the SDK's `ProtectedResourceMetadata` model.
- **Never combine it with bearer mode** in one instance (SECURITY §3 stands).
- **Ship it as experimental**, recommending the `operator` profile for connector-facing instances.
- **Model and effort** for the implementation session: Opus 5.5, high.

### 2026-09-26 — Public launch (archive PR 27, branch chore/public-launch)

The repository goes public as a **fresh repository imported from a clean squash** of this tree, not by changing this repository's visibility. History before the public import is kept in a **private archive repository**: every commit, PR, issue, review, run log and the v0.1.0 release. **v0.1.1 will be the first release in the public repository**; the v0.1.0 image stays published. This PR makes the tree clean for the import and does the rest of the launch preparation:
- deployment-specific values removed from the tree (below);
- DockHand's endpoint summaries dropped from `docs/api/ENDPOINT-MAP.md` (BUSL-1.1, below);
- `scripts/release-notes.py` works without a previous tag;
- public-facing docs: README status, root `SECURITY.md`, a new `CONTRIBUTING.md`;
- Dependabot version updates back to **daily**; CodeQL through GitHub's **default setup**;
- the `ci` concurrency group keyed by PR number.

### 2026-09-26 — Release v0.1.1 (PR #1, branch chore/release-0.1.1)

Version 0.1.1 (`pyproject.toml`, `__version__`, `uv.lock`'s own entry), the first release in the public repository `tyler-rich/dockhand-mcp`. It ships the changes recorded since the v0.1.0 entry: the fixes for archive issue 17 (read-back after a 5xx on a content write; a failed scan after a pull is never a success), the OAuth scoping document, and the public-launch changes. With it, at the maintainer's request:
- the deploy files and docs show a placeholder image, `ghcr.io/tyler-rich/dockhand-mcp:X.Y.Z@sha256:<digest>`, and say to copy the exact pinned `image:` line from the latest GitHub release notes;
- release notes and CHANGELOG sections render issue and PR numbers from entries written before the public import as plain text (`archive PR 25`, `archive issue 17`), never `#25`.

## [0.1.0] — 2026-09-26

### 2026-09-20 — Project inception and locked decisions D-001…D-012 (no PR; planning)

Build a new, generic, security-first DockHand MCP server in Python on the latest stable series (3.14; D-001) with a latest-everything dependency policy enforced in CI (D-013), using the official `mcp` SDK, authenticating to DockHand with a `dh_` API token only, exposing a profile-gated tool set (`read-only` default), with a permanent `excluded` tier for credential/identity/exec/filesystem endpoints. Tier assignment for all 375 operations in DockHand API v1.0.46 is recorded in `docs/api/ENDPOINT-MAP.md` and generated by `scripts/gen-endpoint-map.py` (the `/api/docs` JSON itself is not committed).

### 2026-09-24 — Pre-implementation review (no PR; planning)

(1) Target MCP revision `2026-07-28` (D-014): stateless core, Multi Round-Trip elicitation, protocol headers. (2) Destructive confirmation moves from a model-settable `confirm` flag to human elicitation with an HMAC-signed, single-use, argument-bound challenge, keeping `confirm` as a configurable fallback (D-006, `DOCKHAND_MCP_CONFIRM_MODE`). (3) MCP feature surface fixed in ARCHITECTURE §7: tools + outputSchema + elicitation (+ progress/cancellation if the SDK supports them); resources, prompts, sampling, completions, logging notifications refused. (4) Per-principal destructive rate limit (S-11) and header/body integrity (S-12). (5) Distroless dropped from S-08: distro Python lags the latest CPython series and would violate D-013. (6) Endpoint-map fixes: `POST /api/stacks/{name}/validate` and `/env/validate` → `read`; `POST /api/git/stacks/{id}/deploy-stream` → `operator`; `POST /api/batch` → new `split` tier. (7) `main` stays the default branch (D-010). (8) Missing config variables added to ARCHITECTURE §5.

### 2026-09-24 — License: Apache-2.0 (no PR; planning)

D-015 — Apache License 2.0, copyright holder `tyler-rich`, with `LICENSE` (verbatim text), `NOTICE`, SPDX headers on every source file, `license`/`license-files` in `pyproject.toml`, and the OCI `licenses` label. S0 writes the final files; there is no placeholder stage.

### 2026-09-24 — CI right-sized for a private repo on GitHub Pro (no PR; planning)

Replace the multi-job CI (pip-audit, Trivy, Grype, CodeQL/Semgrep as separate jobs, push + PR triggers, daily Dependabot) with: one required `ci` job on PRs only, with docs-only fast pass and path-conditional Semgrep and Docker build; **OSV-Scanner** as the single vulnerability scanner (lockfile at every PR, image gate at release, weekly scheduled scan of the published image); Dependabot weekly grouped (security updates still immediate); CodeQL and secret scanning deferred to public launch. D-013 and S-09 amended.

### 2026-09-24 — Sessions own verification (no PR; process)

Sessions run all verification themselves and post a Verification report (CLAUDE.md Workflow): local suite, failing-test proof in a throwaway worktree, prompt-specified live checks against DockHand via `scripts/smoke.py` and the git-ignored `secrets/dev-env.sh`, attribution/identity checks, and a green `ci` check. The maintainer's per-PR job is review and merge; human-only steps are listed explicitly under "Maintainer actions".

### 2026-09-24 — Scaffold: tooling, CI, hardened image, config validation, licensing (PR #1, branch chore/scaffold)

The repository skeleton every later session builds on: `uv`/ruff/mypy/pytest tooling; `config.py` implementing every ARCHITECTURE §5 variable (the Phase 5 `DOCKHAND_MCP_RESOURCE_URL`/`DOCKHAND_MCP_OAUTH_*` names are deliberately not parsed) with `*_FILE` secrets and the SECURITY §6 startup rules other than the DockHand reachability checks (S1); JSON-lines logging with redaction; the tool registry (tiers, profiles, endpoint declarations, `NO_ENDPOINTS`, empty); `/healthz` plus the SDK's stateless Streamable HTTP endpoint, mounted only in guarded `none` mode until bearer auth lands in S1; the `serve | check | tools` CLI; a hardened two-stage image; the single-job `ci` workflow; Dependabot; Apache-2.0 `LICENSE`/`NOTICE` and SPDX headers.

### 2026-09-24 — Core: bearer auth, transport and protocol hardening, DockHand client, async patterns, smoke client (PR #3, branch feat/core-auth-client-v2; replaces PR #2)

S1 makes the server a real authenticated MCP server with two tools (`dockhand_health`, `dockhand_get_operation`) and builds what S2/S3 call:
- `auth/principal.py`, `auth/bearer.py`: constant-time bearer auth.
- `transport/ratelimit.py`, `transport/protocol.py`, `transport/app.py`: the ARCHITECTURE §3 pipeline.
- `server.py`: a tools-only SDK server, plus tool dispatch and the audit line.
- `client/`: the DockHand client, the error mapping, the envelope and its `outputSchema`, the job poller, the SSE consumer and the operation registry.
- `startup.py`: the SECURITY §6 DockHand checks for `check` and `serve`.
- `scripts/smoke.py` and `scripts/smoke-plans/health.json`.

### 2026-09-24 — Read tier tools (PR #4, branch feat/read-tools)

S2 implements the whole read tier: 48 new tools (50 registered with S1's two), one module per domain, each `Tier.READ` with its exact `(method, path)` declarations. `dockhand_list_notifications` (optional) is skipped. New shared code:
- `guardrails/names.py`: validators and name-or-ID resolution.
- `guardrails/secrets.py`: key-based output redaction.
- `tools/_common.py`: F-09 defaulting, pagination, text caps, fan-out and value-level env redaction.
- `ToolSpec.data_schema`: specialises `data` in `outputSchema` (page and text shapes).
- `smoke.py`: values saved across steps (`save`, `"${name}"`), plus the `any_of` and `each_matches` expectations; `scripts/smoke-plans/read.json` uses them.
- The catalogue snapshot: `tests/fixtures/tool-catalogue-read.json`.

### 2026-09-25 — Operator tier tools (PR #5, branch feat/operator-tools)

S3a implements the operator tier: 36 tools, each `Tier.OPERATOR` with its exact `(method, path)` declarations (86 registered with the read tier's 50). The optional `dockhand_adopt_stacks`, `dockhand_scan_for_stacks` and `dockhand_test_notification` are not implemented. New shared code:
- `guardrails/compose.py`: the SECURITY §5 checks, with compose-style interpolation.
- `guardrails/dotenv.py`: `.env` parsing and in-place editing.
- `tools/_common.py`: `WriteInputs`, `write_budget`, `run_async_pattern` (job / SSE / detached), `read_back_verify`, `refuse_placeholders`.
- `tools/_stackguard.py`: stack variables from DockHand, and the `guardrails` result section.
- `tools/stack_files.py`: the content-persisting stack writes.
- `tools/batch.py`: the operator half of `POST /api/batch`.
- `scripts/smoke.py`: `cleanup`, write plans, the `includes` expectation, and `scripts/smoke-plans/operator.json`.
- `tests/fixtures/tool-catalogue-operator.json`.

### 2026-09-25 — Destructive tier and human approval (PR #7, branch feat/destructive-tools)

S3b implements D-006 and the destructive tier: 10 tools, each `Tier.DESTRUCTIVE` with its exact `(method, path)` declarations, registered only in the `admin` profile (96 tools there with the read tier's 50 and the operator tier's 36). New and changed shared code:
- `auth/approval.py`:
  - `mint_challenge` / `verify_challenge`: HMAC-SHA256, constant-time compare.
  - `args_sha256`: canonical JSON, sorted keys, no whitespace, approval fields excluded.
  - `ReplayCache`, `ClientView`, the mode matrix (`choose_path`).
  - `approve_or_request` → `Approved | InputRequired | Refused`.
- `tools/_common.py`: `DestructiveInputs` (`confirm: bool = False`), `run_destructive` / `DestructiveHandler`, `destructive_tool`, `dockhand_success`.
- `client/dockhand.py`: `read_only_phase()`, under which the client refuses any non-GET before it is sent.
- `server.py`: builds a `ClientView` per request, answers `input_required`, and refuses (at server build) a destructive tool whose handler is not `run_destructive` for that tool.
- `tools/prune.py` (new); the other nine tools live in their domain modules.
- `scripts/smoke-plans/destructive.json`; `tests/fixtures/tool-catalogue-destructive.json`.

### 2026-09-26 — Fix #6: batch per-item failures (PR #8, branch fix/batch-item-failures)

`dockhand_batch_containers` is `ok: true` only when DockHand's batch summary shows every item succeeded. The result now carries `data.summary` `{total, succeeded, failed}` and `data.items`: each container's id and name (from our own resolution, not DockHand's text), its `outcome` (`succeeded` / `failed` / `unknown`), and DockHand's per-item message, passed through `redact()` and truncated to 512 characters. `ok: false` with `dockhand_http_error` in these cases:
- any failed item, including all of them;
- a job that ends `failed` / `cancelled` / `error`;
- a result that is missing, not `{type: "complete", summary}`, has counts that are not non-negative whole numbers, has counts that don't add up, or has a total that differs from the number of items sent;
- a summary claiming no failures that a per-item `error` line contradicts.

### 2026-09-26 — Operation-output redaction and `operation_failed` (PR #10, branch sec/redact-operation-output)

Job and SSE output now goes through one redaction path before it can reach any tool result, and an operation DockHand accepted but reported as failed gets its own error code, `operation_failed`. Fixes #9, which files the gap S3c recorded in its "Deferred / follow-ups" (S3c never opened an issue for it).

### 2026-09-26 — Output redaction for direct answers; URL credentials in logs; SECURITY.md (PR #12, branch sec/redact-direct-answers)

Every DockHand answer a tool can return now passes S3d's `OutputRedactor`, with the same layer order. `logging.redact()` gains the URL-credential rule, and that rule now has one implementation. SECURITY.md gains an "Output redaction" subsection. Fixes #11, which files S3d's three follow-ups.

### 2026-09-26 — Compound writes report partial failure (PR #14, branch fix/compound-write-partial-failure)

A tool whose one call persists content and then starts or redeploys it is `ok: true` only when both happened. When the write happened (read back and verified) and the deploy did not, the result is `ok: false` with `operation_failed`, `verified: true`, `data.steps` and flags for what did happen. Nothing is rolled back. Fixes #13, which files S3e's follow-up.

### 2026-09-26 — Pre-release correctness: update_containers failures; stack environment scoping (PR #18, branch fix/pre-release-correctness)

Two correctness fixes before v0.1.0, and a robustness change to the read regression.
- `dockhand_update_containers` reports every failure DockHand's answer carries. Fixes #15.
- `dockhand_list_stacks` says which stacks DockHand tracks in the requested environment, and every write to an existing stack refuses one it does not track there. Fixes #16.
- `read.json` picks a readable, non-smoke stack.
- The two remaining S3f questions (a 5xx after a save; a failed scan after a pull) are filed as #17, labelled `after-v0.1.0`. No code change is made for them.

### 2026-09-26 — create_stack name-collision guard (PR #20, branch fix/create-stack-name-collision)

`dockhand_create_stack` refuses a name already in use as a compose project on the environment's Docker daemon. Before any other request (DockHand's validator included), it reads `GET /api/stacks?env` and refuses with `validation_error` when any listed item, tracked or only discovered, has the same name after Docker Compose's project-name normalisation. The message says the name is in use on this Docker daemon, names the matching project, and says whether it is tracked in this environment. No write request is sent. Fixes #19, which files S3g's follow-up.

### 2026-09-26 — Stopped-project collision guard; shared-daemon warning (PR #22, branch fix/stopped-project-collision)

`dockhand_create_stack`'s name-collision guard also reads every container in the requested environment, stopped ones included (`GET /api/containers?env&all=true`). It refuses a name that matches any container's `com.docker.compose.project` label, after the same compose-go normalisation. `dockhand-mcp check` warns when two DockHand environments share container ids, which means they point at one Docker daemon. Fixes #21, which files S3h's last follow-up.

### 2026-09-26 — Release pipeline, image gates, operator docs, v0.1.0 (PR #23, branch chore/release-pipeline)

S4 makes the server runnable by someone else and publishable: a final multi-arch image (linux/amd64, linux/arm64), a tag-driven release workflow (the `ci` checks, OSV-Scanner gate on both platforms before any push, push by digest, tags, CycloneDX SBOMs, cosign keyless signature and SBOM attestations, GitHub release with notes from this log), a weekly scan of the published image, the operator documents (README, DOCKHAND-SETUP, CLIENTS, `deploy/`), CODEOWNERS, issue templates, a root `SECURITY.md`, a CHANGELOG, and version 0.1.0. New scripts: `scripts/release-notes.py` (notes and CHANGELOG sections from §14) and `scripts/osv-image-gate.py` (the image gate policy).
