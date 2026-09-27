# dockhand-mcp — Project Plan

> Status: **v0.1.x — phases 0–4 shipped (v0.1.0), phase 5 (OAuth) scoped; public since the launch.** Last updated 2026-09-26.
> Read `CLAUDE.md` first, then this file, then `docs/ARCHITECTURE.md` and `docs/SECURITY.md`.

## 1. What this is

A **security-first MCP (Model Context Protocol) server for [DockHand](https://dockhand.pro)**. It lets AI clients (Claude Code, Claude Desktop, Claude.ai, and any other MCP-capable app) inspect and operate Docker environments *through DockHand's REST API* — never through the Docker socket.

Design goals, in priority order:

1. **Safe by default.** Ships read-only. Write capability is opt-in by profile. Destructive operations need a second, explicit confirmation. Whole categories of DockHand's API (auth, users, tokens, exec, host filesystem…) are never exposed at all.
2. **Generic.** Not tied to any one homelab. No hard-coded hosts, environment IDs, stack names, or paths. Everything is configuration.
3. **Deployable anywhere Docker runs.** One hardened container image; works under plain `docker run`, Docker Compose, DockHand, Portainer, Komodo, etc. Also runnable as a stdio subprocess for local clients.
4. **Connectable by any MCP client.** Streamable HTTP transport with bearer-token auth in v1; OAuth 2.1 resource-server mode (required by Claude.ai custom connectors) as a scoped follow-on.
5. **Publishable.** Clean repo, CI, signed images, SBOM, docs — so it can be flipped from private to public without a rewrite.

### Prior art (read, don't copy)

- `strausmann/mcp-dockhand` (TypeScript, MIT): 130+ tools, 1:1 endpoint mapping, **username/password login stored in env vars**, session-cookie auth, no server-side auth on the MCP endpoint, binds `0.0.0.0` unconditionally. Useful as a coverage checklist; its security model is what we are explicitly *not* doing.
- The maintainer's earlier self-built Python DockHand MCP (private, homelab-specific, not in this repo). Lessons carried forward as requirements (§4): job-polling vs fire-and-forget patterns, read-back verification after `.env`/compose writes, name-or-ID container resolution, the DockHand `PUT …/compose` large-payload silent no-op, `set` shadowing the Python builtin. **Do not port its code**; it was never designed for publication.
- `raetha/ha-dockhand` (Home Assistant): confirms `dh_` bearer tokens are the intended machine-auth path since DockHand 1.0.26.

## 2. Locked decisions (change only via a STOP-and-ask + ARCHIVE §14 entry)

| ID | Decision | Rationale |
|---|---|---|
| D-001 | **Language: Python — always the latest stable CPython series (3.14 as of 2026-09; 3.15 when it ships in October 2026), official `mcp` SDK (its low-level `Server`, chosen for a tools-only capability surface; Streamable HTTP + stdio), `httpx`, `pydantic` v2, `uv` for dependency management.** `requires-python` tracks the latest stable minor; there is no backwards-compatibility window. | Matches the maintainer's existing Python codebase (Scrye, on 3.14) and prior DockHand MCP experience; official SDK has `TokenVerifier`/resource-server auth hooks and `TransportSecuritySettings` for DNS-rebinding protection. TypeScript is the other defensible choice (see `docs/ARCHITECTURE.md` §1.1); switching is allowed only before Session 1 starts. |
| D-002 | **Auth to DockHand: `dh_…` API token only. No username/password, no session cookies, no auto-login.** | Tokens are Argon2id-hashed on DockHand's side, revocable, expirable, and inherit RBAC on Enterprise. Passwords in container env are the #1 anti-pattern in the reference implementation. `POST /api/auth/tokens` requires a session, so token creation is a human, in-UI step — by design. |
| D-003 | **The MCP server never touches `/var/run/docker.sock`, never mounts host paths, never shells out.** It is a pure HTTP client of DockHand. | Keeps the image trivially hardenable (non-root, read-only FS, `cap_drop: ALL`, no capabilities added). |
| D-004 | **Authentication is required on the MCP endpoint before *any* response, including `initialize` and `tools/list`.** `none` mode exists only for stdio and for loopback-bound HTTP with an explicit `DOCKHAND_MCP_ALLOW_UNAUTHENTICATED=true`. | Unauthenticated `tools/list` enumeration is a documented, mass-exploited MCP weakness. |
| D-005 | **Tool exposure is governed by a server-side profile: `read-only` (default) < `operator` < `admin`.** Profile is set by configuration, not by the client, and tools outside the profile are not registered (invisible to `tools/list`), not merely rejected. | Least privilege at the protocol level; a compromised client cannot discover or call what the operator did not enable. |
| D-006 | **Destructive operations require a human confirmation the model cannot produce.** Primary mechanism: MCP **elicitation** (form mode) returned as a Multi Round-Trip `input_required` result (spec 2026-07-28), carrying a server-minted, HMAC-signed, single-use, 120-second challenge bound to principal + tool + SHA-256 of the canonical arguments; the retry must return the same challenge and an explicit approval. Fallback, when the client does not declare the elicitation capability: a `confirm: bool` argument (default `false`) — weaker, because the model can set it. `DOCKHAND_MCP_CONFIRM_MODE` = `auto` (default: elicitation when supported, else `confirm`) / `elicitation` (strict: refuse destructive calls from clients without elicitation) / `param` (always `confirm`). Every destructive result and audit line records which method approved it. Where the API offers a preview, the unapproved path returns it. MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) are set on every tool. | A `confirm` flag is a speed bump for a well-behaved model, not a control against a prompt-injected one; elicitation puts the decision in front of the human. The signed challenge is what makes it hold on a stateless server: without it a client could send an approval on the first call without ever being asked. `auto` exists because client support for the 2026-07-28 elicitation flow is still rolling out; `elicitation` is the recommended setting once your client supports it. |
| D-007 | **The `excluded` tier in `docs/api/ENDPOINT-MAP.md` is permanent.** No profile, flag, or fork of this project exposes: auth providers, API/hawser tokens, users/roles/MFA, license, container `exec`/file browser, DockHand host filesystem, secret providers, git/registry credentials, image export/load/push, volume file browsing, self-update, webhooks. | These are either credential material, code execution on the host, or exfiltration paths. If someone needs them, they need the DockHand UI, not an LLM. |
| D-008 | **Tool names are prefixed `dockhand_`, snake_case, verb-first.** Descriptions are terse, contain no hostnames/IPs/IDs, and never instruct the model to call other tools. | Namespace safety when co-installed with other servers; tool descriptions are injected into model context and are an injection surface. |
| D-009 | **Structured JSON logging to stderr/stdout; no secrets, no full env values, no log bodies in logs.** | SIEM-friendly; stdio transport reserves stdout for the protocol. |
| D-010 | **`main` is the default branch and the release branch; `dev` is the integration branch.** One PR per concern: every session works on its own branch off `dev`, opens a PR into `dev`, never merges. Feature PRs are squash-merged into `dev`. Nothing touches `main` except a `dev → main` release PR (regular merge, not squash), opened only when a prompt explicitly asks for one. No hotfixes, config-only PRs, or direct commits on `main`. | Same model as the maintainer's other projects: the default branch always shows the last released state to visitors, while all work lands on `dev` first. |
| D-011 | **Every merged behaviour change gets a dated entry in `docs/ARCHIVE.md` §14.** | Institutional memory for future sessions and for the public changelog. |
| D-012 | **Supported DockHand API version is pinned to the spec (`1.0.49`).** The OpenAPI document (`/api/docs`) is the source of truth but is **not committed** (`docs/api/*.json` is git-ignored); the maintainer attaches it to the sessions that need it. Newer features are added only after a newer spec is obtained and `docs/api/ENDPOINT-MAP.md` is regenerated. | The spec is auto-generated from DockHand's route tree; it is the source of truth, not the manual and not the reference implementation. It is DockHand's own document, so it is kept out of the repository. |
| D-013 | **Latest-everything policy.** Every runtime dependency, dev dependency, base image, GitHub Action, and tool is pinned to the **newest stable release available at the time the change is made**, and CI fails when anything falls behind. Concretely: `uv.lock` committed; a `deps-current` CI job runs `uv lock --upgrade` against a scratch copy and fails if the lockfile would change; Dependabot version updates run **daily**, grouped (one PR per ecosystem), for `uv`, `github-actions` and `docker`, while Dependabot **security** updates arrive immediately regardless of schedule; every session starts by running `uv lock --upgrade` and `uv sync` and records the resulting versions in its ARCHIVE entry; the base image is the latest `python:<latest-minor>-slim` by digest and is bumped in the same PR that bumps `requires-python`; GitHub Actions are pinned to the SHA of their newest release. Pre-releases (alpha/beta/rc) are never used. | The maintainer's standing rule: no outdated packages or dependencies at all. Making it a CI gate means it is enforced rather than remembered. The cost — CI going red when an upstream ships, and occasional breaking bumps — is accepted; Dependabot PRs are the fix, not ignores. Cadence: weekly from 2026-09-24 to conserve a private repo's Actions minutes; daily again from the public launch (2026-09-26), since minutes are unmetered on public repositories. Freshness is enforced at every change regardless, by the session's `uv lock --upgrade` and the `deps-current` gate. |
| D-014 | **MCP protocol revision: `2026-07-28`** (stateless core: no `initialize` handshake, no `Mcp-Session-Id`; per-request `_meta` capabilities; Multi Round-Trip Requests for elicitation; `Mcp-Method`/`Mcp-Name` headers). Backwards compatibility with `2025-11-25` clients only if the official Python SDK provides it; we write no compatibility shims of our own. Any cross-call state is a server-minted handle passed as an ordinary tool argument (our `op_id`s), bound to the principal that created it. | It is the current stable revision, and its stateless design matches this server's architecture exactly. Claude products are still rolling out support, so the SDK's back-compat, if any, is what keeps today's clients working. |
| D-015 | **License: Apache License 2.0**, copyright holder `tyler-rich`. `LICENSE` holds the unmodified Apache-2.0 text fetched from apache.org; `NOTICE` holds `dockhand-mcp` / `Copyright 2026 tyler-rich`. `pyproject.toml` declares `license = "Apache-2.0"` and `license-files = ["LICENSE", "NOTICE"]`; the image carries `org.opencontainers.image.licenses=Apache-2.0`; every source file under `src/`, `tests/` and `scripts/` starts with `# SPDX-License-Identifier: Apache-2.0`. | Decided before any code exists, so the first release, image and every file ship under the final license rather than a placeholder. Apache-2.0 over MIT for a security tool meant for public use: an explicit patent grant and patent-retaliation clause, a stated trademark carve-out (relevant next to the DockHand name), and Section 5 making contribution terms explicit without a CLA. It is permissive and compatible with the MIT/BSD/Apache dependency stack, and matches the scanners in the maintainer's other project (Trivy and Grype are Apache-2.0). |

## 3. Non-goals (v1)

- Multi-tenant / per-user credential mapping (one DockHand token per server instance; run more instances if you need more identities).
- Real-time streaming (log tails, live stats, SSE feeds) surfaced as MCP streams. Tools return snapshots with bounded size.
- DockHand configuration management (`admin` tier: environments, git repos, backup destinations, notifications config, scanner settings). Explicitly deferred; see §6.
- Container creation with arbitrary bind mounts (deferred to v1.1 with a bind-source deny-list).
- Any Docker CLI or socket usage.
- A web UI.

## 4. Requirements

### 4.1 Functional

| # | Requirement |
|---|---|
| F-01 | Streamable HTTP transport at `POST /mcp`, MCP revision `2026-07-28` (stateless; D-014), plus `--transport stdio`. |
| F-02 | Unauthenticated `GET /healthz` returning `200 {"status":"ok"}` and nothing else (no version, no DockHand reachability, no config). Used by container healthchecks. |
| F-03 | Configuration exclusively via environment variables (with `*_FILE` variants for secrets). Validated at startup with actionable errors; the process refuses to start on an insecure combination (see `docs/SECURITY.md` §6). |
| F-04 | Tool profiles `read-only` / `operator` / `admin` (D-005). Plus `DOCKHAND_MCP_DISABLE_TOOLS` (comma list) to remove individual tools from any profile. There is no allow-list that can add tools above the profile. |
| F-05 | Tool catalogue as specified in `docs/TOOLS.md`. Read tools cover: environments, containers (list/inspect/logs/stats/top/compose/sizes/pending updates), stacks (list/compose/env/deploys), images (list/history/scan results), volumes, networks, jobs, dashboard/host/system/disk, activity, audit (Enterprise), schedules & executions, auto-update settings, vulnerabilities, registry browsing, git repos/stacks (read). |
| F-06 | Operator tools: container lifecycle (start/stop/restart/pause/unpause/rename), batch image update, update check, stack lifecycle (start/stop/restart/deploy), compose & `.env` edits **with read-back verification**, stack create with compose guardrails, validate compose/env, image pull/tag/scan, volume create/clone, network create/connect/disconnect, schedule run/toggle, per-container auto-update, git stack sync/deploy, job cancel, batch start/stop/restart. |
| F-07 | Destructive tools (admin profile, `confirm=true`): remove container/image/volume/network, stack down/delete (with `delete-preview` as dry-run), prune (scoped), batch remove/down, run image-prune now, clear activity log. |
| F-08 | Every container-scoped tool accepts either a container ID or a name and resolves it via `GET /api/containers?env=…` (exact name match; ambiguous or missing → error listing candidates). |
| F-09 | Every environment-scoped tool takes `environment_id: int`. If the server is configured with `DOCKHAND_DEFAULT_ENVIRONMENT_ID`, the parameter becomes optional. If exactly one environment exists and no default is set, tools may auto-select it and say so in the result. |
| F-10 | Long-running DockHand operations follow one of three documented patterns (see `docs/ARCHITECTURE.md` §4): job-poll (`{jobId}` → `GET /api/jobs/{id}`), SSE-consume (read the event stream to the final `result` event), or detached (in-process operation registry with `op_id`, for endpoints that block synchronously). Every write tool takes `wait: bool` and `timeout_seconds: int` (bounded) and returns a uniform envelope. |
| F-11 | All list tools support `limit`/`offset` (or pass through DockHand's) and return `{items, count, total?, has_more}`. Logs are capped by `tail` (≤ 5000) and `max_bytes` (≤ 1 MiB) with truncation flagged. |
| F-12 | Results are structured JSON (`structuredContent` + a text rendering). Errors are returned as tool errors (`isError: true`) with an actionable message and the DockHand HTTP status, never as protocol errors. DockHand error bodies are passed through truncated (≤ 2 KiB) and never include request headers. |
| F-13 | A tiny CLI: `dockhand-mcp serve`, `dockhand-mcp check` (validates config and tests DockHand reachability + token, prints the effective profile and tool list), `dockhand-mcp tools` (prints the catalogue as JSON for review/diffing — rug-pull detection aid). |
| F-14 | MCP surface is deliberately small (full rationale: `docs/ARCHITECTURE.md` §7). **Used:** tools only, with `title`, annotations, `inputSchema`, `outputSchema` + `structuredContent`; elicitation (form mode, via `input_required`) for destructive confirmation; progress notifications during `wait=true` operations and honouring client cancellation, *if* the SDK supports them on the stateless transport. **Not used:** resources, resource templates/subscriptions, prompts, sampling, roots, completions, logging notifications, `list_changed`, MCP Apps, resource links. The tasks extension is a Phase 6 candidate to replace the detached-operation registry. |

### 4.2 Security (summary — full treatment in `docs/SECURITY.md`)

| # | Requirement |
|---|---|
| S-01 | MCP endpoint auth modes: `bearer` (static token, constant-time compare, from `DOCKHAND_MCP_TOKEN_FILE`/`DOCKHAND_MCP_TOKEN`), `oauth` (JWT resource-server validation: issuer, JWKS, `aud` = configured resource URL, RFC 9728 protected-resource metadata — **Phase 3**), `none` (guarded, see D-004). |
| S-02 | DNS-rebinding protection: `Host`/`Origin` allow-list via the SDK's `TransportSecuritySettings`; default allow-list is `localhost`, `127.0.0.1`, and the container's own service name is *not* auto-added — operators set `DOCKHAND_MCP_ALLOWED_HOSTS`. |
| S-03 | Rate limit auth failures (default 10/min/IP → 429 for 5 min, mirrors DockHand's own policy) and total requests (default 120/min/IP). Request body cap 1 MiB. |
| S-04 | Outbound: only `DOCKHAND_URL`. TLS verification on by default; `DOCKHAND_CA_BUNDLE` for private CAs; `DOCKHAND_TLS_INSECURE=true` allowed but logs a WARN on every startup. No redirects followed cross-origin. Connect timeout 10 s, read timeout per tool budget. |
| S-05 | Input validation with pydantic (`extra='forbid'`, bounded lengths, regex for names/IDs, integer ranges). Path segments are URL-encoded; stack names validated against `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`; container IDs `^[0-9a-f]{12,64}$` or a name. |
| S-06 | Output hygiene: `inspect` payloads have `Config.Env` redacted by default (`redact_env=true`); stack env tools never unmask `***`; logs and DockHand error bodies are size-capped; tool descriptions contain no environment-specific data. |
| S-07 | Compose/stack guardrails on `create_stack`/`update_stack_compose`: run DockHand's own `POST /api/stacks/{name}/validate` first and refuse on **errors**; additionally refuse (configurable, default on) any service with `privileged: true`, a bind mount whose source is in the deny-list (`/`, `/var/run/docker.sock`, `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/var/lib/docker`), `network_mode: host`, `pid: host`, or `cap_add: [SYS_ADMIN|ALL]`. Return the findings, don't silently strip. |
| S-08 | Container image: multi-stage build on the latest official `python:<minor>-slim` image (3.14 today; bumped to each new stable minor per D-013), pinned by digest, for **both** stages. Distroless Python is not an option: its images ship the Debian distribution's Python, which lags the latest CPython series and would violate D-013. Non-root UID 10001, runtime stage contains only the virtualenv and the app, `HEALTHCHECK` via the Python binary (no curl/wget), read-only root FS, `cap_drop: ALL`, `no-new-privileges`, memory/CPU/pids limits in the reference compose. |
| S-09 | Supply chain. Sized while the repo was private on GitHub Pro (3,000 Actions minutes/month) and kept lean since the public launch. **One required CI job (`ci`)** on pull requests into `dev`/`main` only (no push trigger; `concurrency: cancel-in-progress`): a first step classifies changed paths so docs-only PRs pass in seconds (the job always reports a status, so the required check never hangs); otherwise `uv sync --frozen`, ruff, ruff format, `mypy --strict`, pytest, gitleaks, `deps-current` (D-013), **OSV-Scanner** on `uv.lock` (fails on any known vulnerability), **Semgrep CE** (`p/python`, `p/security-audit`) when `src/` changed, and a Docker build check (with layer cache) only when `Dockerfile`/`pyproject.toml`/`uv.lock`/`src/` changed. **Release workflow** (tags): build → **OSV-Scanner image scan gate before push** → push → CycloneDX SBOM → cosign keyless sign + attest. **Weekly scheduled workflow**: OSV-Scanner scan of the published `latest` image (catches CVEs disclosed after release; a failure emails the maintainer). **Image gate policy** (release and weekly, both platforms, `scripts/osv-image-gate.py`; maintainer decision 2026-09-26): a finding fails when it is outside the image's Debian packages, when it is a Debian finding with a fixed version in the image's Debian release (trixie today), or when it has no such fix and CVSS ≥ 9.0; findings Debian triages as unimportant (OSV-Scanner's own exit-code rule) and other unfixed Debian findings are listed in the job summary without failing. The lockfile scan at every PR stays strict (any finding fails). Exceptions live only in `osv-scanner.toml`, each with a `reason` and an `ignoreUntil` ≤ 90 days, and each is a STOP-and-ask plus an ARCHIVE entry; they are the only way to pass a blocking image finding. Also: `uv.lock` committed, Dependabot (daily grouped version updates, immediate security updates, `target-branch: dev`), base image pinned by digest. **Since the public launch:** CodeQL (Python + Actions) runs through GitHub's code scanning **default setup**, enabled in the repository settings, with no workflow file in the repository; Semgrep CE stays in `ci`. Secret scanning and push protection are enabled in the repository settings. |
| S-10 | Audit trail: every tool invocation logged as one JSON line: timestamp, principal name, tool, sanitized arguments (IDs/names only; never compose/env contents), DockHand status, duration, outcome. |
| S-11 | Destructive-call rate limit per principal (default 10/min, `DOCKHAND_MCP_DESTRUCTIVE_PER_MIN`) independent of the global limit, so a looping or injected model cannot burn through a prune/remove series even with approvals auto-accepted by a misconfigured client. |
| S-12 | Protocol-header integrity: when the `Mcp-Method` / `Mcp-Name` HTTP headers are present they must match the JSON-RPC body; mismatch → 400. A gateway that authorizes on headers must not be bypassable by a body that says something else. `MCP-Protocol-Version` must be a supported revision. (Verify the exact normative requirements in the 2026-07-28 spec and SDK; implement whatever the SDK does not.) |

### 4.3 Operability

| # | Requirement |
|---|---|
| O-01 | Reference `docker-compose.yml` (hardened), `.env.example`, and a DockHand/Portainer-friendly stack snippet in `deploy/`. |
| O-02 | Client config snippets in `docs/CLIENTS.md`: Claude Code (`claude mcp add --transport http … --header "Authorization: Bearer …"`), Claude Desktop (stdio + HTTP), Claude.ai (Phase 3, OAuth), generic. |
| O-03 | `docs/DOCKHAND-SETUP.md`: creating a dedicated DockHand user + `dh_` token; on Enterprise, the minimal custom role per profile (permission strings from `docs/api/ENDPOINT-MAP.md`); on Free, the explicit warning that a token is full-admin and the MCP profile is the only control. |
| O-04 | Semantic versioning; `CHANGELOG.md` generated from `docs/ARCHIVE.md` §14 at release time. |

## 5. Phased delivery (each phase = 1–2 Claude Code sessions = 1–2 PRs)

| Phase | Sessions | Outcome | Prompt (kept by the maintainer outside the repo) |
|---|---|---|---|
| **0 — Scaffold** | S0 | Repo skeleton, tooling (`uv`, `ruff`, `mypy --strict`, `pytest`), CI (lint/type/test/audit/scan), docs skeleton, hardened Dockerfile stub, empty tool registry that boots and serves `/healthz`. | Prompt S0 |
| **1 — Core** | S1 | Config loader + startup validation, MCP auth middleware (bearer), transport security, rate limiting, DockHand HTTP client (auth header, timeouts, redaction, error mapping), job poller + SSE consumer + operation registry, structured logging, `check`/`tools` CLI. Zero DockHand tools yet except `dockhand_health`. | Prompt S1 |
| **2 — Read tools** | S2 | Entire `read` tier from `docs/TOOLS.md`. Name→ID resolution. Pagination. Env redaction. Contract tests against a recorded DockHand fixture set. | Prompt S2 |
| **3 — Write tools** | S3a (operator), S3b (destructive) | `operator` tier with read-back verification and compose guardrails; then `destructive` tier with `confirm` + previews. Two sessions, two PRs. | Prompts S3a, S3b |
| **4 — Ship** | S4 | Final Dockerfile, compose, GHCR release workflow (multi-arch, OSV-Scanner image gate, SBOM, cosign), weekly published-image scan, docs (`CLIENTS.md`, `DOCKHAND-SETUP.md`, `README.md`), `v0.1.0` release PR `dev → main`. | Prompt S4 |
| **5 — OAuth scoping** | S5 (scoping only → handoff doc) | Design for `oauth` auth mode so Claude.ai custom connectors can connect: RS metadata (RFC 9728), JWKS validation, `aud` binding, which IdPs support DCR/CIMD (Pocket ID? Authentik? Keycloak?), token→profile mapping. **No implementation in this session.** | Prompt S5 |
| 6 — Later | — | Backups (read + run/preview), `admin` tier behind a separate profile, multi-token principals, container create with guardrails, multi-arch tests, public launch checklist. | (write when reached) |

## 6. Deferred decisions (need a scoping session or maintainer input)

- **Multi-token principals** (per-client token → per-client profile). Design is reserved for in `auth/principal.py`; implementation after Phase 4.
- **OAuth AS choice for the maintainer's own deployment.** Not this project's problem, but Phase 5 must verify that at least one self-hostable IdP satisfies Claude.ai's DCR/CIMD requirement before we commit to the `oauth` mode design.
- **Backups tier.** Valuable but sprawling (31 endpoints). Read + run + preview only; restore stays destructive+confirm.
- **MCP tasks extension** (`io.modelcontextprotocol/tasks`, 2026-07-28): polling via `tasks/get` maps directly onto our job-poll/detached patterns. Scope once the Python SDK and Claude clients support it; until then `op_id` + `dockhand_get_operation` stay.
- **Public launch** (resolved 2026-09-26, ARCHIVE §14 "Public launch"): CodeQL (Python + Actions) through GitHub's default setup, not a workflow; secret scanning, push protection and private vulnerability reporting enabled in the repository settings; CODEOWNERS and `SECURITY.md` (90-day coordinated disclosure) in place; Dependabot back to daily; `CONTRIBUTING.md` added. (License decided: D-015.)

## 7. Definition of done (per PR)

- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src` clean
- [ ] `uv run pytest -q` green; new behaviour has tests that were **verified to fail** before the implementation landed (the PR description names the commit where they failed)
- [ ] No new tool without: pydantic input model, annotations, tier + profile registration, permission strings documented in `docs/TOOLS.md`, an entry in `dockhand-mcp tools` output, and a test
- [ ] `docs/ARCHIVE.md` §14 entry, dated, with the decision and reasoning
- [ ] Every new or changed source file under `src/`, `tests/`, `scripts/` starts with `# SPDX-License-Identifier: Apache-2.0` (D-015)
- [ ] No secrets, internal hostnames, IPs or deployment-specific values in the diff (gitleaks passes)
- [ ] PR opened against `dev`, not merged, link posted; attribution footer stripped from the PR body (re-read the live body to confirm)
- [ ] Verification report posted in chat (CLAUDE.md Workflow step 11): local suite, failing-test proof, live checks the prompt required, attribution/identity, `ci` green

## 8. Repository layout (target after Phase 1)

```
dockhand-mcp/
├── CLAUDE.md                     # session operating rules (read first)
├── plan.md                       # this file
├── README.md
├── LICENSE                       # Apache-2.0, verbatim (D-015)
├── NOTICE                        # Apache-2.0 attribution notice (D-015)
├── pyproject.toml / uv.lock
├── src/dockhand_mcp/
│   ├── __main__.py               # CLI: serve | check | tools
│   ├── config.py                 # env parsing + startup validation
│   ├── logging.py                # JSON logger, redaction helpers
│   ├── auth/                     # principal.py, bearer.py, approval.py (S3b), (oauth.py in Phase 5)
│   ├── transport/                # http app factory, security settings, rate limit, /healthz
│   ├── client/                   # dockhand.py (httpx), jobs.py, sse.py, operations.py, errors.py
│   ├── tools/                    # registry.py (profiles/tiers), one module per domain
│   │   ├── environments.py, containers.py, stacks.py, images.py, volumes.py,
│   │   │   networks.py, jobs.py, system.py, activity.py, schedules.py,
│   │   │   updates.py, vulnerabilities.py, registry.py, git.py, batch.py, prune.py
│   └── guardrails/               # compose.py (bind-mount/privileged checks), names.py
├── tests/                        # unit + contract tests (respx fixtures under tests/fixtures/dockhand/)
├── deploy/                       # docker-compose.yml, .env.example, dockhand-stack.yml
├── docs/
│   ├── ARCHITECTURE.md, SECURITY.md, TOOLS.md, CLIENTS.md, DOCKHAND-SETUP.md
│   ├── ARCHIVE.md                # §14 decision log
│   └── api/                      # generated ENDPOINT-MAP.md (+ git-ignored local OpenAPI JSON when attached)
├── scripts/gen-endpoint-map.py, smoke.py (S1+: live MCP smoke test used in Verification reports)
├── Dockerfile, .dockerignore
├── osv-scanner.toml              # vulnerability exceptions: reason + ignoreUntil ≤ 90 days, each an ARCHIVE entry
└── .github/                      # workflows/ci.yml (one job), workflows/release.yml, workflows/image-scan.yml (weekly), dependabot.yml
```
