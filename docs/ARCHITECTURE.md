# Architecture

## 1. Shape of the system

```
┌──────────────┐  Streamable HTTP (/mcp)  ┌──────────────────────────────┐   HTTPS + Bearer dh_… ┌──────────┐
│ MCP client   │ ───── Bearer / OAuth ───▶│ dockhand-mcp (this project)  │ ─────────────────────▶│ DockHand │──▶ Docker hosts
│ Claude Code, │ ◀──── JSON results ───── │  auth → profile → tool →     │ ◀── JSON / {jobId} /  │  REST    │    (socket / TCP /
│ Desktop, .ai │                          │  client → envelope           │     SSE ──────────────│  API     │     Hawser)
└──────────────┘  or stdio (local)        └──────────────────────────────┘                       └──────────┘
```

Three properties fall out of this shape:

- **No Docker access.** The container has no socket, no capabilities, no host mounts. Compromise of the MCP server yields, at most, what the configured DockHand token can do — which is why the DockHand token should belong to a dedicated, least-privileged DockHand user (see `docs/DOCKHAND-SETUP.md`).
- **DockHand is the policy enforcement point for Docker; dockhand-mcp is the policy enforcement point for the LLM.** Two independent gates. On DockHand Enterprise, RBAC on the token is the first gate; on Free, the token is full-admin and the MCP profile is the *only* gate — the docs say this loudly.
- **The MCP server is stateless** across requests, as MCP revision `2026-07-28` requires (no handshake, no `Mcp-Session-Id`; D-014). The only in-memory state is the rate limiters, the single-use elicitation-challenge replay cache (§7), and the detached-operation registry (§4.3), both bounded and TTL'd.

### 1.1 Why Python (D-001)

| | Python (`mcp` SDK / FastMCP) | TypeScript (`@modelcontextprotocol/sdk`) |
|---|---|---|
| Maintainer familiarity | High (Scrye backend, prior DockHand MCP) | Medium |
| Auth hooks | `TokenVerifier` + `AuthSettings` (resource-server mode, RFC 9728 metadata), custom Starlette middleware | `requireBearerAuth`, `ProxyOAuthServerProvider` (more batteries for OAuth) |
| DNS-rebinding protection | `TransportSecuritySettings` in SDK | `enableDnsRebindingProtection` in SDK |
| Runtime image size | ~60 MB slim (distroless ruled out: lags latest CPython, D-013) | ~50 MB alpine |
| Ecosystem | `httpx`, `pydantic`, `respx` for tests | `zod`, `undici`, `msw` |

Both are fine. Python was chosen for maintainer velocity. The project always targets the latest stable CPython series (D-001/D-013) — 3.14 at inception — and moves to each new minor when it ships. If Phase 5 finds the Python SDK's OAuth resource-server support lacking, the fallback is a sidecar auth proxy (e.g. oauth2-proxy / a tiny AS), **not** a rewrite.

## 2. Components

| Module | Responsibility | Notes |
|---|---|---|
| `config.py` | Parse env → `Settings` (pydantic-settings). Validate combinations at startup. `*_FILE` variants for secrets. | Refuses to start on insecure combos (`docs/SECURITY.md` §6). Prints effective config with secrets masked on `check`. |
| `auth/principal.py` | `Principal(name, profile)` dataclass. | Reserved seam for multi-token and OAuth. |
| `auth/bearer.py` | Starlette middleware: extract `Authorization: Bearer`, constant-time compare against configured token, attach `Principal`. 401 with `WWW-Authenticate: Bearer` on failure; increments limiter. | Applies to `/mcp` only. `/healthz` bypasses. |
| `auth/approval.py` (S3b) | Destructive-call approval (D-006, §7): mint/verify HMAC-signed challenges, single-use replay cache (bounded, TTL = challenge lifetime), build the elicitation `input_required` result, fall back to `confirm` per `DOCKHAND_MCP_CONFIRM_MODE`. The only code path that can let a destructive tool execute. | Pure functions + one small cache; exhaustively unit-tested. |
| `auth/oauth.py` (Phase 5) | JWT verification (JWKS cache, `iss`, `aud`, `exp`, `nbf`), RFC 9728 `/.well-known/oauth-protected-resource`, scope→profile mapping. | Uses SDK `TokenVerifier` if adequate. |
| `transport/app.py` | Builds the Starlette app: SDK Streamable HTTP transport for MCP `2026-07-28` (stateless; whatever response mode the SDK uses for progress/`input_required` results), `TransportSecuritySettings(allowed_hosts, allowed_origins)`, rate-limit middleware, body-size middleware, `/healthz`. | Binding address from `DOCKHAND_MCP_BIND` (default `127.0.0.1` outside Docker; the reference compose sets `0.0.0.0` inside the container and restricts exposure with the host port mapping). |
| `client/dockhand.py` | `DockhandClient(httpx.AsyncClient)`: base URL, `Authorization: Bearer dh_…`, `Accept: application/json` default, TLS settings, timeouts, retry (idempotent GETs only, 3×, jittered), error mapping → `DockhandError(status, code, message)`. | Never logs bodies or headers. Truncates error bodies to 2 KiB. Refuses to follow redirects to a different origin. |
| `client/jobs.py` | `poll_job(job_id, budget)` → `GET /api/jobs/{id}` every 2 s until `status ∈ {done, completed, failed, cancelled, error}` or budget exhausted. Live DockHand 1.0.46 ends every job with `done`; success or failure is in `result`. | Returns `lines` (capped) and `result`, both redacted (`client/redaction.py`). |
| `client/sse.py` | `consume_sse(request, budget)` → iterate `text/event-stream`, collect `progress` (capped ring buffer), return final `result`/`error` event. | For endpoints that only stream (pull, scan, prune images, git deploy, scan-all). Progress and the final payload are redacted (`client/redaction.py`). |
| `client/operations.py` | In-memory registry for **detached** operations: `create_task`, `op_id` (uuid4), TTL 1 h, max 100, statuses `running/completed/failed`. | For endpoints that block synchronously for a long time (container restart/stop on slow containers). |
| `client/redaction.py` (S3d; S3e) | The one redaction path for what DockHand says. Order: the key-based pass on structured values; on every string the call's context values, then `logging.redact()` (which holds the URL-credential rule, `scheme://<redacted>@host`); then the 512-character line cap. Applied to operation output (job lines, SSE progress, final result/error payloads, batch per-item messages) inside `jobs.py`, `sse.py` and `batch.py`; to every non-GET answer and every error body inside `dockhand.py` (S3e); and, by the dispatcher, to DockHand's free text in every result (message, error, status, output, reason, detail, warning and hint keys; no context values; S3e). A call's redactor is bound with `redacting()` and is `PLAIN` otherwise. docs/SECURITY.md "Output redaction". | Context values: a stack's own variable values (≥ 8 characters, not `***`), read by the stack operations and the compose/`.env` writes before they write (`env_vars` for create and validate); held for that call only, never logged. GET answers stay unredacted in the client: tools read them for names, variables, read-back and job status. |
| `client/envelope.py` | `ok(...)`, `err(...)`, `async_op(...)` builders producing the uniform result. | Single place to change shape. |
| `tools/registry.py` | `register(tool, tier, endpoints)` — every tool declares the DockHand `(method, path-template)` pairs it may call, and a test checks each against `docs/api/ENDPOINT-MAP.md` (none `excluded` or `admin`; a `read` tool calls only `read` endpoints; `split` only with the permitted operations); at startup, registers only tiers ≤ profile and not in `DISABLE_TOOLS`. Emits the catalogue for `dockhand-mcp tools`. | Tiers → profiles: read→all; operator→operator,admin; destructive→admin. `admin` tier not registered in v1 regardless of profile. |
| `tools/<domain>.py` | One module per DockHand domain; thin: validate → resolve names → client call → envelope. | No business logic in tool bodies beyond what `docs/TOOLS.md` specifies. |
| `guardrails/compose.py` | YAML parse (safe loader) + checks (`docs/SECURITY.md` §5). Returns findings; the tool decides refuse/allow. | Runs **in addition to** DockHand's `POST /api/stacks/{name}/validate`. |
| `guardrails/names.py` | Regexes for stack names, container names, image refs, volume/network names; container, network and image name→ID resolution with ambiguity detection (TOOLS.md contract). | Resolves through the list endpoint on every call; nothing cached. |
| `guardrails/secrets.py` | Key-based secret redaction the dispatcher applies to every tool's `data`: sensitive key names (one list, one module) keep their key, and their non-null, non-boolean value becomes `"<redacted>"`. | Added in S2. Independent of the value-level redactions (`Config.Env`, compose `environment:`) and the fail-closed credential canaries. |
| `logging.py` | JSON lines; `redact()` helper (URL credentials, configured secrets, `token=`/`password=` pairs, `Authorization`, bearer, `dh_…`; its URL rule is the one output redaction uses); request-scoped context (principal, tool, request id). stdio mode logs to stderr only. | |

## 3. Request lifecycle (HTTP)

1. Body-size check (≤ 1 MiB) → 413.
2. Global rate limit (token bucket per client IP; `X-Forwarded-For` honoured only when `DOCKHAND_MCP_TRUST_PROXY=true`, and then only its **right-most** entry — the address your proxy appended. The left-most entries are supplied by the client and are spoofable) → 429.
3. Transport security (Host/Origin allow-list) → 421/403.
4. Bearer/OAuth auth → 401 (counted; 10 failures/5 min/IP → 429 for 5 min).
5. Protocol checks: supported `MCP-Protocol-Version`; `Mcp-Method`/`Mcp-Name` headers, when present, match the body (S-12) → 400.
6. SDK dispatch (`tools/list`, `tools/call`, and any discovery call the revision defines). Only registered tools exist.
7. Tool: pydantic validation → guardrails → (destructive: per-principal destructive rate limit S-11, then the preview with GETs only, then approval via §7) → DockHand client → envelope. Every step's failure becomes a tool error, not a transport error; a destructive call awaiting approval answers `input_required` (§7).
8. Audit log line.

## 4. Async patterns (F-10)

DockHand has three behaviours for long operations; each tool declares which one it uses (see the **Async** column in `docs/api/ENDPOINT-MAP.md`).

### 4.1 Job-poll
Endpoint returns `{jobId}` (e.g. `POST /api/stacks/{name}/start|stop|down`, `POST /api/batch`, `POST /api/containers/check-updates`). Sending `Accept: application/json` makes some of these block and return the final result synchronously — **we do not rely on that**, because a proxy in front of DockHand may cut the connection; we take the `jobId` and poll `GET /api/jobs/{id}` within the tool's budget. We ask with `Accept: application/json, text/event-stream`. Live DockHand 1.0.46 (S3a) ends jobs with status `done` (success or failure in `result`); a job's `lines` are `{event, data}` records.

```
wait=true  → poll up to timeout_seconds (default 60, max 300) → the job's final result, or {timed_out: true, operation.id}
wait=false → return {operation.kind: "job", id} immediately
follow-up  → dockhand_get_job(job_id)
```

### 4.2 SSE-consume
Endpoint only streams (`POST /api/images/pull`, `POST /api/images/scan`, `POST /api/prune/images`, `POST /api/git/stacks/{id}/deploy`, `POST /api/vulnerabilities/scan-all`; the spec also describes `POST /api/stacks/{name}/deploy|restart` as streams, but live they answer with a job, below). We open the stream, keep the last N progress events (N = 50, each ≤ 512 chars), and return the terminal `result` (or `error`) event. On budget exhaustion the stream is closed and the tool returns `timed_out: true` with the last progress lines; the operation continues on DockHand.

Live DockHand 1.0.46 (S3a) answered the streaming stack endpoints (deploy, restart) with a JSON `{jobId}` rather than a stream, even when asked for `text/event-stream`; the job's `lines` are the stream's events (`progress` with `{status}` or `{type: "line", line}`, then `result` with `{success, output}`). The consumer handles both: a JSON answer carrying a job id is polled as in §4.1, so every SSE tool also declares `GET /api/jobs/{id}`. The consumption runs in the operation registry (§4.3), so a wait that times out still returns an `op_id`.

Where an SSE endpoint *also* accepts `Accept: application/json` for a synchronous answer (marked `accept-json` in the map), prefer the job/SSE path for the same proxy-timeout reason; use the sync path only when the budget is ≤ 30 s and the client explicitly asks (`sync=true`).

### 4.3 Detached (operation registry)
Endpoint blocks until done and returns `{success}` (e.g. `POST /api/containers/{id}/restart|stop`). Slow containers can exceed any client-side tool timeout. With `wait=false` we spawn an `asyncio` task, return `{operation.kind: "detached", id}` and the client checks with `dockhand_get_operation(op_id)`. Registry is bounded (100 entries, 1 h TTL) and lost on restart — the tool result says so. In S3a every write tool that is not job-based runs through it (even fast ones), so `wait=false` and timeouts behave the same everywhere; a full registry answers `not_available`.

## 5. Configuration (all env; `*_FILE` reads the value from a file, e.g. a Docker secret)

| Variable | Default | Notes |
|---|---|---|
| `DOCKHAND_URL` | *(required)* | e.g. `https://dockhand.example.test`. Must be absolute; scheme `https` unless `DOCKHAND_ALLOW_HTTP=true`. |
| `DOCKHAND_ALLOW_HTTP` | `false` | Boolean (`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`). When not true, an `http://` `DOCKHAND_URL` fails startup. |
| `DOCKHAND_TOKEN` / `DOCKHAND_TOKEN_FILE` | *(required unless DockHand auth is disabled — see SECURITY §6)* | `dh_` API token of a dedicated DockHand user. |
| `DOCKHAND_CA_BUNDLE` | — | PEM path for private CAs. |
| `DOCKHAND_TLS_INSECURE` | `false` | Disables verification. WARN at startup. |
| `DOCKHAND_DEFAULT_ENVIRONMENT_ID` | — | Makes `environment_id` optional in tools. |
| `DOCKHAND_MCP_PROFILE` | `read-only` | `read-only` / `operator` / `admin`. |
| `DOCKHAND_MCP_DISABLE_TOOLS` | — | Comma list of tool names to remove. |
| `DOCKHAND_MCP_TRANSPORT` | `http` | `http` / `stdio`. |
| `DOCKHAND_MCP_BIND` / `DOCKHAND_MCP_PORT` | `127.0.0.1` / `8080` | Compose sets bind to `0.0.0.0` inside the container. |
| `DOCKHAND_MCP_PATH` | `/mcp` | |
| `DOCKHAND_MCP_AUTH_MODE` | `bearer` | `bearer` / `oauth` (Phase 5) / `none`. |
| `DOCKHAND_MCP_TOKEN` / `DOCKHAND_MCP_TOKEN_FILE` | *(required in bearer mode)* | ≥ 32 bytes of entropy enforced (min length 43 base64url chars). |
| `DOCKHAND_MCP_ALLOW_UNAUTHENTICATED` | `false` | Required to be `true` for `AUTH_MODE=none` over HTTP; additionally bind must be loopback. |
| `DOCKHAND_MCP_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Host-header allow-list (DNS rebinding). Add your public hostname. |
| `DOCKHAND_MCP_ALLOWED_ORIGINS` | *(empty = no browser origins)* | Origin allow-list. |
| `DOCKHAND_MCP_TRUST_PROXY` | `false` | Honour `X-Forwarded-For` for rate limiting. |
| `DOCKHAND_MCP_RATE_LIMIT_PER_MIN` | `120` | Per client IP. |
| `DOCKHAND_MCP_DEFAULT_TIMEOUT` / `_MAX_TIMEOUT` | `60` / `300` | Seconds, for `wait=true`. |
| `DOCKHAND_MCP_LOG_LEVEL` / `_LOG_FORMAT` | `info` / `json` | |
| `DOCKHAND_MCP_GUARDRAILS` | `strict` | `strict` / `warn` (findings returned but not blocking) — `off` does not exist. |
| `DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND` | — | Comma list of extra bind-mount source prefixes to allow (SECURITY §5). The non-configurable deny set can never be allowed. Implemented in S3a; parsed and validated from S0. |
| `DOCKHAND_MCP_CONFIRM_MODE` | `auto` | `auto` / `elicitation` / `param` (D-006, `auth/approval.py`). `auto`: elicitation when the request declares form elicitation on MCP 2026-07-28, else `confirm`; `elicitation`: refuse destructive calls otherwise; `param`: always `confirm`. 2025-11-25 requests never elicit (§7). |
| `DOCKHAND_MCP_CHALLENGE_KEY` / `_FILE` | *(random per process)* | HMAC key for elicitation challenges. Optional: if unset, a random 32-byte key is generated at startup (challenges then don't survive a restart, which is fine at a 120 s lifetime). If set, ≥ 32 bytes. |
| `DOCKHAND_MCP_DESTRUCTIVE_PER_MIN` | `10` | Per-principal destructive-call rate limit (S-11). Every destructive `tools/call` counts, the approval round included, and is checked before the preview. Over the limit: `not_available`. |
| `DOCKHAND_MCP_I_UNDERSTAND_ADMIN_OVER_INSECURE_TLS` | `false` | Deliberately ugly escape hatch; see SECURITY §6. |
| `DOCKHAND_MCP_RESOURCE_URL` and `DOCKHAND_MCP_OAUTH_*` | — | **Phase 5 only.** Not parsed before the OAuth implementation session; listed so the names are reserved. |

## 6. Result envelope

```json
{
  "ok": true,
  "environment_id": 7,
  "data": { ... },
  "operation": { "kind": "job", "id": "…", "status": "completed", "waited_seconds": 4.2, "timed_out": false },
  "verified": true,
  "warnings": ["…"]
}
```
```json
{ "ok": false, "error": { "code": "dockhand_http_error", "message": "…", "dockhand_status": 403 } }
```

Error `code` values (closed set, defined in Phase 1): `validation_error`, `not_found`, `ambiguous_name`, `dockhand_http_error`, `dockhand_unreachable`, `unexpected_redirect` (DockHand answered 3xx; never followed), `guardrail_blocked`, `confirmation_required`, `timeout`, `operation_unknown`, `profile_denied` (should be unreachable — tools outside profile aren't registered — but exists for defence in depth), `not_available` (the feature needs a DockHand edition this instance does not have, e.g. the Enterprise-only audit log; added in S2), `verification_failed` (a write was accepted, but reading the content back did not match; `verified: false` and a count-only diff summary; added in S3b), `operation_failed` (the HTTP calls succeeded but DockHand reported the operation failed: a job ending `failed`/`cancelled`/`error`, a result of `success: false`, an SSE `error` event, any failed batch item, the deploy half of a compound write whose save succeeded (`data.steps` says which step failed; S3f), a content write DockHand answered with a 5xx whose content reads back as sent (`data.saved: true`; #17), a pull whose scan after it failed (`data.scanned: false`; #17); added in S3d. `dockhand_http_error` is for HTTP-level failures: 4xx/5xx and answers that can't be read; a content write's 5xx carries `data.saved: false` or `"unknown"` from its read-back). Besides `code` and `message`, `error` may carry `dockhand_status`, `retry_after` (seconds, from a DockHand 429) and `detail` (DockHand's error body, truncated to 2 KiB and redacted). The envelope's JSON Schema (`client/envelope.py`) is every tool's `outputSchema`.

## 7. MCP feature surface (F-14) — what we use, what we refuse, and why

Target revision `2026-07-28` (D-014). Every capability we don't need is surface area we don't have to secure.

| Feature | Decision | Why |
|---|---|---|
| **Tools** | Used — the only primitive in v1 | The whole product. |
| `title`, annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) | Used on every tool | Clients use them to decide when to prompt. Hints, not security. |
| `outputSchema` + `structuredContent` | Used on every tool (the envelope schema, specialised per tool where cheap) | Clients can validate results; the model gets structure, not prose. |
| Tool `icons` | Not used | No value; one more field to review. |
| Deterministic `tools/list` order; no `list_changed` | Used / never emitted | The catalogue is fixed per process (profile set at startup). Stable order keeps client caches valid and makes `dockhand-mcp tools` diffs meaningful (rug-pull detection). |
| **Elicitation (form mode, via `input_required` / MRTR)** | Used for destructive confirmation only (D-006) | Puts the decision in front of the human. Never used to collect secrets — the spec forbids form-mode elicitation for credentials. |
| Elicitation challenge integrity | Server-minted challenge: `base64url(json{nonce, principal, tool, args_sha256, exp})` + `.` + base64url(HMAC-SHA256 over that text); single-use (replay cache, bounded, TTL = lifetime); 120 s lifetime; must match on retry. Carried as the MRTR `requestState`; the form is the one `inputRequests` entry, `dockhand_approval`. `args_sha256` covers the validated arguments (defaults filled, environment resolved, `confirm`/`scope_all_acknowledged` excluded) and the preview's resolved target IDs | The server is stateless, so it must be able to prove the approval on the retry answers *its own* question about *these exact* arguments. Arguments changed between ask and retry, or a name that now resolves to something else → new challenge. |
| Progress notifications | Used during `wait=true` job/SSE/detached waits, **if** the SDK supports them on the stateless transport (verify in S1) | Long operations otherwise look hung. Progress messages carry our text only (phase, elapsed), never raw DockHand output. |
| Cancellation | Honoured: stop waiting and return the `op_id`/job id | Cancelling our wait never cancels the DockHand operation. That would be a write the user did not ask for; `dockhand_cancel_job` exists for that. |
| Server-minted handles for cross-call state | Used (`op_id`), bound to the creating principal | This is the spec's own replacement for sessions (SEP-2567). Another principal asking for your `op_id` gets `operation_unknown`. |
| Tasks extension | Deferred (plan §6) | Right shape for our async patterns, but adopt when SDK + Claude clients support it. |
| Resources / resource templates / subscriptions | Not used | Duplicates tools. Some clients pull resource contents into context automatically, which amplifies prompt-injection from compose files and logs. |
| Prompts | Not used | Server-authored prompt templates are an injection vector and add no capability here. |
| Sampling | Never | Server-initiated model calls spend the user's tokens and open a server→model injection path. |
| Roots | Not applicable | We don't touch the client's filesystem. |
| Completions | Not used in v1 | Nice for `stack`/`environment_id` arguments, but an enumeration convenience we can revisit. |
| Logging notifications | Never emitted | Logs go to stderr/stdout JSON. The 2026-07-28 rule (no `notifications/message` unless the request set a log level) is satisfied trivially. |
| MCP Apps (UI extension), resource links | Not used | No UI; no link-outs. |
