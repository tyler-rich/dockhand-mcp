# Security design & threat model

This document is normative. Where it conflicts with convenience, it wins. Changing anything here is a STOP-and-ask.

## 1. Assets and trust boundaries

| Asset | Where | Who can touch it |
|---|---|---|
| DockHand `dh_` token | Container env / secret file / process memory | Only `client/dockhand.py`. Never logged, never returned, never in `check` output (masked to prefix `dh_xxxx…`). |
| MCP bearer token(s) | Secret file / process memory | Only `auth/bearer.py`. Compared in constant time. |
| Compose files, `.env` contents, container env, logs | DockHand → tool results | Returned to the model on request (they are the point), but **never logged**, size-capped, and secrets masked where DockHand masks them. |
| DockHand itself | Reachable from the container | Only over `DOCKHAND_URL`. No other egress is needed; restrict it at the network layer. |

Trust boundaries: (a) MCP client ↔ dockhand-mcp (untrusted client until authenticated; the *model* is untrusted even after — it can be prompt-injected); (b) dockhand-mcp ↔ DockHand (trusted server, but responses are data, not instructions); (c) container ↔ host (hardened image, no privileges).

## 2. Threats and mitigations (STRIDE/OWASP-LLM mapping)

| Threat | Vector here | Mitigation |
|---|---|---|
| **Unauthenticated tool enumeration** | `tools/list` without auth | Auth before any response (D-004). `/healthz` returns nothing informational. |
| **Credential exposure** | Tokens in compose/env/logs/image layers | `*_FILE` secrets, masked `check` output, `.dockerignore`, gitleaks in CI, no `ENV` secrets in Dockerfile, `read_only` FS. |
| **Prompt injection via tool output** (LLM01) | Container logs, compose comments, `.env` comments, image labels, activity messages can contain "instructions" | Structured JSON results; tool descriptions never tell the model to act on content; results carry no imperative text of ours; size caps limit payload. The *client* must still treat results as data — we document this in `docs/CLIENTS.md`. |
| **Excessive agency** (LLM08) | Model calls a destructive tool | Profiles (D-005): destructive tools do not exist in `read-only`/`operator`. Human approval via elicitation, `confirm` fallback, dry-run previews (D-006); per-principal destructive rate limit (S-11). `destructiveHint` annotations so clients prompt. |
| **Confused deputy** | One DockHand token, many possible callers | v1: one principal per instance; run separate instances per profile if multiple callers need different ceilings. DockHand token belongs to a dedicated least-privileged user (Enterprise: custom role). Documented in `DOCKHAND-SETUP.md`. |
| **Tool poisoning / rug pull** | Our own tool descriptions change over versions | `dockhand-mcp tools` prints a deterministic catalogue (name, description, schema hash) for operators to diff; descriptions are code-reviewed; image digests pinned. |
| **DNS rebinding** | Browser on the operator's LAN reaches `http://localhost:8080/mcp` | Host/Origin allow-list (SDK `TransportSecuritySettings`); bind loopback by default outside Docker. |
| **Brute force on MCP token** | Online guessing | ≥ 256-bit tokens enforced, constant-time compare, 10 failures/5 min/IP → 429 for 5 min, global rate limit. |
| **SSRF / redirect abuse** | DockHand (or a MITM) answers with a redirect to an internal host | `follow_redirects=False`; only same-origin redirects would ever be considered, and we don't consider any in v1. `DOCKHAND_URL` is validated once at startup. |
| **Compose-level host takeover** | Model writes a compose that mounts `/` or the Docker socket, or runs `privileged` | Guardrails (§5) run before any compose/stack write; `strict` refuses, `warn` returns findings; there is no `off`. DockHand's own validator is also run. |
| **Data exfiltration through tools** | `exec`, file browser, volume browser, image export, host FS | `excluded` tier — never exposed (D-007). |
| **Denial of service** | Huge log tails, unbounded polling, SSE floods | Caps: `tail ≤ 5000`, `max_bytes ≤ 1 MiB`, `timeout ≤ 300 s`, SSE ring buffer 50 events, operation registry 100 entries/1 h, body ≤ 1 MiB, rate limits. |
| **Supply chain** | Malicious/buggy dependency or base image | `uv.lock`; OSV-Scanner on the lockfile at every PR (any finding fails), on both platforms of the image before every release, and weekly on the published image. The image gate fails on any finding outside the Debian base packages, on a Debian finding fixed in the image's Debian release, and on an unfixed finding with CVSS ≥ 9.0; Debian-unimportant and other unfixed Debian findings are listed, not failed (plan S-09); Semgrep SAST in `ci`, and CodeQL through GitHub's code scanning default setup; gitleaks; Dependabot (daily grouped version updates, immediate security updates) + the `deps-current` freshness gate (nothing is ever behind its newest stable release — D-013); pinned base image digest on the latest Python series; cosign-signed images; SBOM. (plan S-09) |
| **Container breakout** | Vulnerability in Python/httpx | Non-root, `cap_drop: ALL`, `no-new-privileges`, `read_only`, tmpfs `/tmp` `noexec`, pids/memory limits, no socket, no host mounts. Blast radius = the DockHand token. |
| **Session / handle hijacking** | Stateful sessions; guessable operation handles | MCP `2026-07-28` has no sessions (D-014). `op_id`s are uuid4, bound to the creating principal, TTL 1 h. (Phase 5 OAuth uses short-lived JWTs, `aud`-bound.) |
| **Forged or replayed approval** | Client sends an elicitation approval that was never asked for, reuses one, or changes arguments after approval | HMAC-signed, single-use, 120 s challenge bound to principal + tool + argument hash (ARCHITECTURE §7). The residual risk is a client that auto-approves without showing the human; that is a client-trust problem we document, not one a server can solve. |
| **Header/body smuggling** | A gateway authorizes on `Mcp-Method`/`Mcp-Name` while the body calls something else | S-12: mismatch → 400. |
| **Server-initiated abuse of the client** | Sampling, roots, logging notifications | None of these are used (ARCHITECTURE §7); the server never asks the client's model to do anything. |
| **Log injection** | Newlines/ANSI in names or DockHand messages | JSON logging escapes everything; free-text fields truncated to 512 chars. |

### Output redaction

Whatever DockHand says can reach the model: operation output, answers to writes, error bodies, and the free text of read results. It all passes one redactor (`client/redaction.py`, `OutputRedactor`), whose layers run in this order:

1. **Structured values:** the key-based pass (`guardrails/secrets.py`). A sensitive key's value (`password`, `token`, `secret`, `apiKey`, …, and any name ending in `secret`/`token`/`password`) becomes `<redacted>`; the key stays, and `null` and booleans are left alone.
2. **Every string:**
   1. the call's context values (a stack's own variable values, below), longest first → `<redacted>`;
   2. `logging.redact()`: credentials embedded in URLs (`scheme://user:pass@host` and `scheme://token@host` → `scheme://<redacted>@host`; the userinfo cannot cross `/`, `?`, `#` or whitespace), the configured MCP and DockHand tokens, `token=`/`password=` pairs, `Authorization` values (the scheme is kept), `Bearer …` and `dh_…` tokens.
3. **Caps, after redaction:** 512 characters per job line or progress entry, 2 KiB per error body, so a secret cut at the cap cannot survive as a fragment.

It is enforced in shared code, not per tool:

| What | Where | Layers |
|---|---|---|
| Job lines, SSE progress entries, a job's or stream's final result or error, batch per-item messages | `client/jobs.py`, `client/sse.py`, `client/batch.py` | all |
| DockHand's answer to every non-GET request: synchronous writes and detached operations, including results kept in the operation registry and read back with `dockhand_get_operation` | `client/dockhand.py` | all; a top-level `jobId` is kept as sent, because it is polled |
| DockHand's error bodies (`error.detail`) | `client/dockhand.py`, `client/errors.py` | all, before the 2 KiB cap |
| DockHand's free text in every tool result: values under `message`, `error`, `status`, `output`, `stdout`/`stderr`, `reason`, `detail(s)`, `warning(s)` and `hint` keys (whole names or suffixes, case-insensitive) | the tool dispatcher, after the key-based pass | 1, then 2.2 (no context values) |

GET answers are not redacted inside the client: tools read them to resolve names, interpolate guardrail variables, compare read-backs and follow job status, and redaction must not change any of those decisions. Content a tool exists to return is not free text and gets only the key-based pass: logs, compose files, `.env` content, stack variables, and container environments (`redact_env` governs those).

**Stack values (precondition).** Stack operations (start, stop, restart, deploy, down, delete, and the compose and `.env` writes) read the stack's variables (`GET …/env/raw`, `GET …/env`) before they write, and mask every value of at least 8 characters: `.env` values as written and as interpolated, the new `.env` values a write saves, and DockHand's stored variables. `dockhand_create_stack` and `dockhand_validate_stack_compose` use the `env_vars` they were given. If the variables cannot be read, the operation is not started. The values live only in that call's redactor and are never logged.

**Limits.** Not masked by the stack-values layer: values shorter than 8 characters (they would mask ordinary words); values DockHand masks as `***` (their real value is never seen here); values that are not in the stack's environment (DockHand's process environment, image defaults); anything returned by read tools other than `dockhand_validate_stack_compose`, and by `dockhand_get_job` and `dockhand_deploy_git_stack` (no stack context), which get the pattern layers only. The patterns match common credential shapes; a secret in free text that matches none of them (a bare password in a message) passes. Names shaped like a `dh_` token are masked wherever they appear in free text.

**Logs.** Every log line, its message and every field, passes `logging.redact()`, the same function as layer 2.2 (the URL-credential rule has one implementation), and free text is truncated to 512 characters. Context values never reach a log line: nothing logs them.

## 3. Authentication modes (MCP side)

| Mode | When | Rules |
|---|---|---|
| `bearer` (default) | Claude Code, Claude Desktop, scripts, other MCP clients that can send a header | Token from `DOCKHAND_MCP_TOKEN_FILE` (preferred) or `DOCKHAND_MCP_TOKEN`. Minimum 43 chars (32 bytes base64url). Startup fails otherwise. Generate with `python -c "import secrets;print(secrets.token_urlsafe(48))"` (documented) or `dockhand-mcp token` (Phase 4 nicety). |
| `oauth` (Phase 5) | Claude.ai custom connectors and any OAuth-capable client | Resource-server only (we never issue tokens). Validate `iss`, `aud` (= `DOCKHAND_MCP_RESOURCE_URL`), `exp`, signature via JWKS with caching; serve `/.well-known/oauth-protected-resource`. Map scopes/claims → profile ceiling (never above the server's configured profile). |
| `none` | stdio (client is a local subprocess), or loopback-only HTTP for development | HTTP requires **both** `DOCKHAND_MCP_ALLOW_UNAUTHENTICATED=true` and bind ∈ {`127.0.0.1`, `::1`}. Otherwise startup fails with the reason. |

Two of the three may not be combined in v1 (no "OAuth or bearer" fallback) — a single instance has a single mode.

## 4. The `excluded` tier — why each family is out forever

"Excluded" means **never reachable through a tool, in any profile**. Two public or status-only calls are allowed from *internal* code (startup validation and `dockhand-mcp check`), never from a tool: `GET /api/auth/settings` (public; reads `authEnabled`) and `GET /api/roles` (edition probe; only the HTTP status is used, the body is discarded unread). No other excluded endpoint is called from anywhere.

| Family | Endpoints (examples) | Reason |
|---|---|---|
| Auth providers & settings | `/api/auth/**` (login, OIDC/LDAP config, settings) | Credential material; several are **public** routes on DockHand's side; letting an LLM edit IdP config is a takeover path. |
| API & agent tokens | `/api/auth/tokens`, `/api/hawser/**` | Minting or listing tokens from an LLM session defeats the token model. |
| Users, roles, MFA, profile | `/api/users/**`, `/api/roles/**`, `/api/profile/**` | Identity administration is a human task with a UI and an audit trail. |
| License, legal | `/api/license`, `/api/legal/**` | Not operational. |
| In-container code execution & files | `/api/containers/{id}/exec`, `/shells`, `/files/**` | Arbitrary command execution and read/write of any file in any container → host compromise via privileged containers. |
| DockHand host filesystem | `/api/system/files/**` | Reads the DockHand host's disk (data dir, `.encryption_key`). |
| Secret providers, git/registry credentials | `/api/secret-providers/**`, `/api/git/credentials/**`, `/api/registries` (write), `/api/registry/image` (delete) | Vault/registry credentials and destructive registry writes. |
| Backup destination detail & key rotation | `GET /api/backup/destinations/{id}` (can return decrypted cloud creds), `/rotate-key` | Credential material. |
| Volume file browsing, image export/load/push | `/api/volumes/{name}/browse/**`, `/api/images/{id}/export`, `/load`, `/push` | Bulk data exfiltration / import of untrusted images. |
| Raw streams | `/api/events`, `/api/*/stream`, `/api/logs/merged`, `/api/activity/events`, `/api/audit/events` | Not a tool shape; unbounded. Snapshot tools cover the need. |
| UI cosmetics | icons, dashboard/sidebar/grid preferences, theme, navigation, config-sets, templates, labels | No operational value; increases surface for nothing. |
| Self-update, debug, metrics, webhooks | `/api/self-update/**`, `/api/debug/**`, `/metrics`, `/api/git/**/webhook` | Replacing the DockHand binary from an LLM session; memory diagnostics; webhook secrets. |
| Git env preview | `POST /api/git/preview-env`, `POST /api/git/stacks/{id}/env-files` | Returns parsed env values from a repo checkout, including secrets committed to git. |

## 5. Compose guardrails (`guardrails/compose.py`)

Run on `dockhand_create_stack`, `dockhand_update_stack_compose`, on `.env` writes (`dockhand_update_stack_env_raw`, `dockhand_modify_stack_env`) against the stack's current compose, and (in `warn` mode only, for information) on `dockhand_get_stack_compose` when `lint=true` and in `dockhand_validate_stack_compose`. Parse with `yaml.safe_load` (which resolves anchors, aliases and `<<:` merge keys, so a setting hidden in an `x-` anchor is checked where it lands); refuse non-mapping documents, documents over 512 KiB, and documents whose aliases expand beyond 200 000 values or 64 levels. A document the guardrails cannot evaluate is refused in every mode.

| Check | Severity (`strict` refuses on **error**) |
|---|---|
| `privileged: true` | error |
| Bind mount source (quotes stripped, `..` resolved lexically, trailing `/` dropped) **equal to, a parent of, or inside** any of: `/`, `/var/run/docker.sock`, `/run/docker.sock`, `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/var/lib/docker`, `/var/lib/containerd` (`/` counts only when equal). Checked in short and long volume syntax, in `local` volumes whose `driver_opts.o` includes `bind` (`device`), in top-level `configs`/`secrets` `file:`, and in service `env_file` paths. The finding notes that host-side symlinks cannot be resolved from here. | error |
| Read-only exceptions (fixed, not configurable): exactly `/etc/localtime`, `/etc/timezone`, `/etc/ssl/certs`, `/etc/ca-certificates`, `/etc/pki/ca-trust/extracted` are allowed when mounted read-only (short syntax `:ro`, long syntax `read_only: true`). The same paths read-write, and anything else inside `/etc`, are errors. | — |
| Bind source starting with `~` | error |
| Relative bind source that, after lexical `..` resolution, leaves the stack directory (starts with `..`) | error |
| `network_mode: host`, `pid: host`, `ipc: host`, `userns_mode: host` | error |
| `cap_add` containing `ALL`, `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `NET_ADMIN`* (case-insensitive, `CAP_` prefix ignored) | error (*`NET_ADMIN` is `warning` — VPN containers legitimately need it) |
| `security_opt` containing `seccomp:unconfined` or `apparmor:unconfined` (`:` or `=`) | error |
| Content the guardrails cannot see: `extends` with `file:`, top-level `include`, `volumes_from: container:…` | error |
| `devices:` present | warning |
| Image tag `latest` or untagged (a digest-pinned image is fine) | warning |
| Any `environment:` value that looks like a credential (`PASSWORD`, `SECRET`, `TOKEN`, `KEY` in name, not ending `_FILE`, with a value that is not just a `${…}` reference) | warning — the tool never echoes the value in the finding, only the key name |
| Ports published on all interfaces for common DB ports (5432, 3306, 6379, 27017, 9200) | warning |

**Variables.** Values are interpolated the way docker compose does before the checks run: `${VAR}`/`$VAR` → the value, or an empty string when unset; `${VAR:-d}`/`${VAR-d}` and `${VAR:+r}`/`${VAR+r}` per the compose spec (nested defaults too); `$$` → `$`; `${VAR:?e}`/`${VAR?e}` unset → error (`variable_required_unset`). The variables are real: for `dockhand_create_stack`, its `env_vars`; for writes to an existing stack, DockHand's current `.env` (`GET …/env/raw`) and stack variables (`GET …/env`), with the proposed change applied on top. A variable whose only value is DockHand's masked `***` (a secret, or an injected provider key) cannot be seen: using it in a bind source is an error (`bind_source_unresolvable`), and so is using it where another check needs the value (`value_unresolvable`); a source that is empty after substitution is `bind_source_unresolvable` too. `.env` writes are refused (strict) when the new values introduce an error against the stack's current compose — e.g. `DATA_DIR=/` when a bind source is `${DATA_DIR}` — and are not refused for errors the stack already had. Findings name variables and show the resolved bind path, never other values. **Residual risk:** variables that DockHand's own process environment supplies at deploy time are invisible here and are treated as unset.

Additionally, DockHand's `POST /api/stacks/{name}/validate` is called before compose writes and its **errors** block in `strict` mode. Both finding sets are returned in the result's `data.guardrails` (ours under `findings`, DockHand's under `dockhand`); the envelope itself is unchanged.

Allow-listing a path for a legitimate need is a **deployment** decision: `DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND=/srv/media,/srv/data` (normalised prefixes matched on whole path components). It can lift only the configurable denials (`/root`, `/var/lib/containerd` and paths inside them). Never allow the socket, `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/var/lib/docker` — these are not configurable, nothing inside them can be allowed (other than the fixed read-only exceptions above), and the configuration refuses entries that overlap them.

**Placeholder write-back guard.** Read results replace secrets with `<redacted>` and DockHand masks stack secrets as `***`. Any write that accepts content (compose, raw `.env`, `set_vars` values and rename targets, `env_vars` values) refuses content containing either marker, before any request, so placeholder text never overwrites real values.

## 6. Startup validation (fail closed)

The process exits non-zero, with a one-line reason, when:

- `DOCKHAND_URL` missing/invalid, or `http://` without `DOCKHAND_ALLOW_HTTP=true`.
- `AUTH_MODE=bearer` and no token, or token < 43 chars.
- `AUTH_MODE=none` over HTTP without `ALLOW_UNAUTHENTICATED=true`, or with a non-loopback bind.
- `TRANSPORT=stdio` with `AUTH_MODE=oauth` (meaningless).
- `PROFILE=admin` together with `DOCKHAND_TLS_INSECURE=true` unless `DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS=true` (a deliberately ugly variable).
- `DOCKHAND_TOKEN` missing **and** DockHand reports auth enabled (`GET /api/auth/settings` is public and returns `authEnabled`). If DockHand auth is disabled, the server starts but logs a WARN on every startup that the MCP profile is the only control.
- `dockhand-mcp check` additionally performs `GET /api/health`, `GET /api/environments` with the token, and reports edition (Free/Enterprise) and whether the token's permissions look sufficient for the profile (best-effort: try one representative read per domain).
- `dockhand-mcp check` also warns (stderr, exit code unchanged) when two DockHand environments list the same container ids, i.e. share one Docker daemon, where stacks collide across environments.

## 7. Deployment hardening (reference `deploy/docker-compose.yml`)

```yaml
services:
  dockhand-mcp:
    image: ghcr.io/<owner>/dockhand-mcp:0.1.0@sha256:<digest>
    restart: unless-stopped
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:size=16m,noexec,nosuid,nodev
    ports:
      - "127.0.0.1:8080:8080"          # or omit and put it on your reverse-proxy network
    environment:
      DOCKHAND_URL: https://dockhand.example.test
      DOCKHAND_TOKEN_FILE: /run/secrets/dockhand_token
      DOCKHAND_MCP_TOKEN_FILE: /run/secrets/mcp_token
      DOCKHAND_MCP_PROFILE: read-only
      DOCKHAND_MCP_BIND: 0.0.0.0        # inside the container; exposure is controlled by `ports`
      DOCKHAND_MCP_ALLOWED_HOSTS: localhost,127.0.0.1,mcp.example.test
    secrets: [dockhand_token, mcp_token]
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    deploy:
      resources:
        limits: { cpus: "0.50", memory: 256M, pids: 128 }
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
secrets:
  dockhand_token: { file: ./secrets/dockhand_token }
  mcp_token: { file: ./secrets/mcp_token }
```

Notes for the docs: DockHand's stack editor injects secrets as env at runtime — `DOCKHAND_TOKEN` (non-`_FILE`) is acceptable there because the value lives in DockHand's encrypted store, not in the compose file. Portainer users should use Portainer secrets or its env editor. Never put the values in the YAML.

TLS: terminate at a reverse proxy (Caddy/Traefik/nginx) or a VPN. The MCP server speaks plain HTTP on an internal network only; `DOCKHAND_MCP_TRUST_PROXY=true` only behind that proxy.

## 8. Disclosure

Vulnerabilities are reported privately through GitHub private vulnerability reporting, under the 90-day coordinated disclosure policy in the root [`SECURITY.md`](../SECURITY.md).
