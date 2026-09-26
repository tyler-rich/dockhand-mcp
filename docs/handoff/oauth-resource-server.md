# Handoff: OAuth resource-server mode (custom connectors)

> Scoping document from session S5 (plan §5, Phase 5), 2026-09-26. It proposes; it changes nothing.
> No code under `src/` and no configuration was changed. Every design choice below that touches a
> locked decision, the config schema, SECURITY.md or a dependency is listed again under
> [Open questions](#8-open-questions-for-the-maintainer).

**How to read the evidence tags.** Every factual claim carries a source tag such as `[M1]`, listed
in [Sources](#sources) with its URL. All sources were fetched on **2026-09-26** in this session,
with the web fetcher, the GitHub API, or (for the SDK) by reading the installed package source.

- **V** means *verified*: the statement was found in that source.
- **U** means *unverified*: no source was found, or the sources disagree. The text says which.
- Statements with no tag are this document's own proposals or reasoning.

## Summary

- **The spec agrees with our locked rule.** MCP 2026-07-28 makes an MCP server an OAuth 2.1
  resource server [M1 V]. It allows but never requires the authorization server (AS) to be
  co-hosted [M1 V], and mentions proxying only as a pattern with extra duties [M4 V]. SECURITY §3's
  "resource server only, we never issue tokens" holds, so the first STOP condition does not apply.
- **The 2026-07-28 changes don't touch the resource server.** RFC 9207 issuer validation, the
  deprecation of Dynamic Client Registration (DCR) in favour of Client ID Metadata Documents
  (CIMD), and the new AS-metadata issuer check all fall on the client and the AS [M5 V, M2 V, R3 V].
- **Claude's custom connectors can use this design** (claude.ai, Desktop's Connectors, mobile):
  - Discovery: a `401` carrying `WWW-Authenticate: Bearer resource_metadata=…`, then RFC 9728
    metadata [A1 V].
  - Registration: CIMD, DCR, or a client ID the user enters [A1 V, A5 V].
  - Tokens: PKCE S256, and RFC 8707 `resource` on both authorize and token requests [A1 V, A3 V].
  - Network: everything reaches us from Anthropic's cloud, source range `160.79.104.0/21` [A1 V, A8 V].
- **Connectors do not speak MCP 2026-07-28 and do not elicit (as far as the docs say).** Claude
  follows the 2025-03-26, 2025-06-18 and 2025-11-25 authorization specs [A2 V], and elicitation on
  claude.ai is an open feature request [G5 V]. Over a connector, D-006's approval therefore falls
  back to `confirm`, or is refused under `DOCKHAND_MCP_CONFIRM_MODE=elicitation`.
- **Self-hosted IdPs verifiably work, so the second STOP condition does not apply.**
  - **Pocket ID 2.16** does everything we need with stable features: `resource` → `aud`, JWT access
    tokens, RFC 8414, RFC 9207, CIMD, and public clients with PKCE [P1–P4 V].
  - **Keycloak 26.7.4** works through an Audience mapper, or with experimental CIMD [K1 V].
  - Authelia and Authentik work only with a pre-registered client and a fixed audience.
  - Zitadel cannot put our URL in `aud` [Z1 V].
- **Recommendation: implement now**, as our own middleware in the auth slot of the pipeline. Use
  PyJWT (already in `uv.lock` through `mcp`) and the SDK's metadata model; don't use the SDK's
  auth wiring. Never combine it with bearer mode in one instance. Document it as experimental
  until a live connector run succeeds. Model and effort: Opus 5.5, high.
- **Single biggest risk: an IdP that grants our audience too broadly.** A token carrying our `aud`
  is a key to the Docker control plane, and the server is internet-facing. Two cases:
  - IdPs without RFC 8707 (Keycloak, Authentik, Authelia) put our URL into `aud` through
    admin-configured mappers. If the mapper sits in a default scope, every token of every client
    in the realm is accepted.
  - With open DCR and a consenting user, a token minted for an attacker's client is too.

  The design's answers are the mandatory subject allow-list and the optional client allow-list
  (§4.3), plus a hardened IdP runbook (§6.3).

---

## 1. Protocol requirements (MCP 2026-07-28)

### 1.1 What the server must serve

| Requirement | Level | Source |
|---|---|---|
| Implement RFC 9728 Protected Resource Metadata (PRM) | MUST | [M1 V] |
| PRM contains `authorization_servers` with at least one AS | MUST | [M2 V] |
| Offer discovery through at least one of: `resource_metadata` in the 401's `WWW-Authenticate`, or the well-known URI, path-inserted (`/.well-known/oauth-protected-resource/<path>`) or at the root. Clients try the header first, then path-inserted, then root | MUST (one of) | [M2 V] |
| PRM `resource` is identical to the identifier the well-known URL was built from; otherwise the client must not use it | MUST (RFC 9728 §3.3) | [R1 V] |
| `scope` parameter in the 401 `WWW-Authenticate` | SHOULD | [M1 V] |
| Invalid or expired token → HTTP 401 | MUST | [M1 V] |
| Valid token with too little scope → 403, `error="insufficient_scope"`, `scope=…`, `resource_metadata` | SHOULD | [M1 V] |
| New in 2026-07-28: put every scope the operation needs in one challenge | SHOULD | [M1 V] |
| New in 2026-07-28: honour scope hierarchies (a broader scope implies narrower ones) | MUST | [M1 V] |
| New in 2026-07-28: no `offline_access` in `WWW-Authenticate` scope or in `scopes_supported` | SHOULD NOT | [M1 V] |
| `scopes_supported` is the minimal set for basic functionality | guidance | [M1 V] |

Claude-specific constraints on top of the spec, all [A1 V]:
- Only a `401` starts sign-in; a `WWW-Authenticate` on a `200` is ignored.
- Only the first `authorization_servers` entry is used, with no fallback.
- `resource` must equal the URL exactly as the user enters it, path included.
- The scope Claude requests is the 401's `scope`, else PRM `scopes_supported`. Claude appends
  `offline_access` when the AS lists it.
- A 403 other than `insufficient_scope` is a terminal error [A4 V].

### 1.2 What validation must check

| Check | Rule | Source |
|---|---|---|
| General | Validate as OAuth 2.1 §5.2 describes | [M1 V] |
| Audience | The token must have been issued for this server "as the intended audience, according to RFC 8707 Section 2". Reject tokens that don't list us in `aud` | [M1 V, M4 V] |
| Other tokens | "MUST NOT accept or transit any other tokens" | [M1 V] |
| JWT access tokens (RFC 9068 §4) | `typ` is `at+jwt` or `application/at+jwt`; `iss` exactly equals the expected issuer; `aud` contains our resource indicator; reject `alg: none`; `exp` in the future; errors are `invalid_token` | [R5 V] |
| Algorithms (RFC 8725) | Allow-list them; defend against `none` and RS→HS confusion; check the keys belong to the issuer (§3.8); validate the audience (§3.9); explicit typing (§3.11); never follow `jku`/`x5u` (§3.10) | [R6 V] |
| RFC 9207 `iss` | A client-side check on the *authorization response*: the client must reject a response whose `iss` doesn't match. RFC 9207 places no obligation on a resource server | [R3 V, M5 V] |
| Canonical resource URI | Lowercase scheme and host, no fragment, preferably no trailing slash. Servers SHOULD accept an upper-case scheme and host | [M1 V] |
| State handles | Bind handles to the user ID taken from the verified token (`<user_id>:<handle>`); never treat holding a handle as authentication | [M6 V] |
| Introspection (RFC 7662) | Not mentioned in the MCP auth pages. It is our choice within OAuth 2.1 §5.2 | [M1 U: absence] |

### 1.3 What we must never do

- **Token passthrough.** "The MCP server MUST NOT pass through the token it received from the MCP
  client" [M4 V]. Here, DockHand is only ever called with the `dh_` token (D-002), so there is
  nothing to pass through. §6.1 adds a test that makes this structural rather than incidental.
- **Accept tokens minted for someone else.** That covers a token for the AS itself (userinfo, the
  admin API), a token for another API, and an ID token. Any token without our resource URL in
  `aud` is refused [M1 V, M6 V].
- **Proxy the authorization flow, or act as an AS.** The spec's proxy pattern [M4 V, M6 V] is out
  of scope by our own rule (SECURITY §3), not by the spec's.

## 2. Custom-connector client behaviour (Anthropic docs)

| Topic | Behaviour | Source |
|---|---|---|
| Surfaces | claude.ai, Desktop, mobile, Claude Code and Cowork share the same connector auth infrastructure | [A1 V] |
| Discovery | 401 + `resource_metadata` → PRM → the AS's metadata: RFC 8414 `/.well-known/oauth-authorization-server` first, then OIDC `/.well-known/openid-configuration` | [A1 V, A3 V] |
| Discovery without a pointer | Probes `/.well-known/oauth-protected-resource/<mcp-path>`, then the root | [A1 V] |
| Discovery cache | About 5 minutes | [A4 V] |
| Redirect URI, hosted apps | `https://claude.ai/api/mcp/auth_callback` exactly | [A1 V] |
| Redirect URI, Claude Code | Loopback (`http://localhost:<port>/callback` and `http://127.0.0.1:<port>/callback`), matched with the port ignored | [A1 V] |
| Possible future `https://claude.com/api/mcp/auth_callback` | Not in the current docs; only in a retired help article (404 today) | [U] |
| Registration: pre-registered client | "Use your own OAuth client": enter a client ID; leave the secret blank unless the AS needs one (Claude is then a public client) | [A5 V, A1 V] |
| Registration: CIMD | The recommended option. Anthropic hosts Claude's metadata document. Selected only if the AS advertises `client_id_metadata_document_supported: true` **and** `none` in `token_endpoint_auth_methods_supported`; otherwise Claude falls back to DCR | [A1 V, A5 V] |
| Registration: DCR | Registers a new client on every fresh connection | [A1 V] |
| CIMD URL of the hosted apps | Not published. Only Claude Code's (`https://claude.ai/oauth/claude-code-client-metadata`) is | [A1 V for Claude Code; U for the hosted apps] |
| Changing auth settings | Not possible after the connector is added | [A5 V] |
| Tokens | PKCE S256 always. RFC 8707 `resource` on authorize and token requests, set to the canonical MCP URL. Refresh reactively on 401, and proactively up to 5 minutes before expiry. Timeouts: 10 s for discovery, registration and token; 30 s for refresh. `client_credentials` is not supported | [A1 V, A3 V] |
| Audience | Validate that `aud` equals the `resource` value you advertise | [A4 V] |
| Static headers (beta) | `static_headers`: an organization **Owner** enters a fixed API key or bearer token. "Beta, for a limited set of organizations"; if the Request headers section is missing, the org doesn't have it | [A1 V, A5 V] |
| Protocol revision | Claude follows the 2025-03-26, 2025-06-18 and 2025-11-25 authorization specs. 2026-07-28 is not mentioned. It doesn't support "advanced or draft capabilities", resource subscriptions or sampling | [A2 V; 2026-07-28: U] |
| Elicitation (form mode) | Not documented for the hosted apps. The open feature request asks for it on claude.ai | [G5 V; U as to support] |
| Tool permissions | Per tool or per group: **Always allow**, **Needs approval** or **Blocked** | [A9 V, A7 V] |
| Annotations | Tools must declare `readOnlyHint` and `destructiveHint` (we already do) | [A10 V] |
| Limits | About 150,000 characters per tool result, 240 s per tool call (claude.ai and Desktop) | [A2 V] |
| Network | Connections come from Anthropic's cloud, not the user's device, and that includes Desktop's Connectors. Egress is `160.79.104.0/21`, "will not change without notice". The AS's discovery and token endpoints are called from the same range, so a WAF in front of the IdP can break the flow. The `/authorize` page opens in the user's browser | [A6 V, A7 V, A1 V, A8 V] |
| Unreachable deployments | IPv4 only; a hostname with only `AAAA` records can't be reached; private, CGNAT and split-horizon addresses are refused; servers behind a VPN or firewall won't connect | [A3 V, A6 V] |
| Plans | Custom connectors on Free (one connector), Pro, Max, Team and Enterprise. On Team and Enterprise only Owners add them | [A6 V] |
| Mobile | "Installing connectors on mobile is currently in beta" | [A7 V] |
| Transport | Streamable HTTP; legacy HTTP+SSE is being deprecated | [A2 V] |

**Consequences for D-006 (destructive approval over a connector).**
- A connector client never declares form elicitation on 2026-07-28 [A2, G5].
- So under `auto` every destructive call takes the `confirm` path, where the model can set
  `confirm=true` and the only human checkpoint is Claude's **Needs approval** setting.
- Under `elicitation`, destructive tools are refused over a connector.
- This design recommends running connector-facing instances at `operator` (§7, Q5).

**Exposure.** A connector-reachable server is by definition reachable from the internet, at least
from `160.79.104.0/21`, and the IdP's discovery and token endpoints must be too [A1]. Anyone with a
Claude account can add our URL as a connector: Anthropic does no review for custom connectors [A2].
So the unauthenticated surface (§5.8) is reachable by arbitrary Claude users *through Anthropic's
addresses*.

**Top three open custom-connector OAuth issues** on `anthropics/claude-ai-mcp`, ranked by 👍 among
open issues matching `oauth` that describe an OAuth failure (feature requests and
directory-only connectors excluded), read from the GitHub API on 2026-09-26:

1. **[#228](https://github.com/anthropics/claude-ai-mcp/issues/228)** "OAuth token refresh never
   attempted for custom connectors via mcp-proxy.anthropic.com" (18 👍, 15 comments) [G1 V].
   Expired access tokens are not refreshed, so users reconnect about daily. With a self-hosted IdP,
   short access-token lifetimes make this worse. It contradicts [A1]'s proactive refresh, so
   re-test during the manual run.
2. **[#341](https://github.com/anthropics/claude-ai-mcp/issues/341)** "MCP OAuth flow ignores PRM
   authorization_servers and user is redirected to <mcp_host>/authorize → 404" (7 👍) [G2 V]. This
   is exactly our split deployment: the AS on another host. The newer
   [#1047](https://github.com/anthropics/claude-ai-mcp/issues/1047) reports the same symptom with
   Authelia when the resource and the AS are on different domains or ports [G4 V]. [A1]'s
   troubleshooting ties this fallback to Claude failing to read the PRM, so check PRM
   reachability from `160.79.104.0/21` first.
3. **[#632](https://github.com/anthropics/claude-ai-mcp/issues/632)** "Custom connector cannot
   authenticate to first-party Microsoft Entra MCP servers … OAuth succeeds but Claude never
   exchanges the code at /token" (4 👍, 35 comments) [G3 V]. Reported against Entra; the same
   symptom recurs in lower-vote issues.

Also useful: the pinned diagnostic issue [#125](https://github.com/anthropics/claude-ai-mcp/issues/125)
"OAuth completes but 'token never sent' … known causes" [G6 V], and the open request for
elicitation, [#153](https://github.com/anthropics/claude-ai-mcp/issues/153) [G5 V].

## 3. IdP matrix

Latest stable versions as of 2026-09-26. The critical column is **audience**: can the operator get
our resource URL, and only for the intended clients, into `aud`? "Opaque" means RFC 7662
introspection: one AS round trip per request (or per cache window), plus an introspection
credential on our side (§5.6).

| | CIMD | DCR | Audience / RFC 8707 | Access token | RFC 9207 `iss` | Refresh |
|---|---|---|---|---|---|---|
| **Pocket ID 2.16.0** (BSD-2-Clause, single Go binary, passkey-only) [P5 V] | **Yes**, public clients only, PKCE automatic. Explicit allow-list of metadata URLs in the admin UI; an empty list blocks CIMD [P1 V]. Since 2.13.0 [P5 V]. The env var for the allow-list (`CIMD_URL_ALLOWLIST`, as the research pass reported) was not found on the docs page [U] | **No**, no `registration_endpoint` [P4 V] | **Yes.** `resource` → `aud` (trailing slash dropped) against admin-defined "APIs" [P2 V]. With identity scopes the issuer is also added to `aud` (per the source commit) [P4 V], so we must accept an array | JWT, RFC 9068 (`typ: at+jwt`) per the source [P4 V]; the docs only say "standard JWT" [P2]. Introspection exists [P4 V] | **Yes** (`authorization_response_iss_parameter_supported`) [P4 V] | Issued; rotated on use (a 2.5-era advisory) [P6 V]. 2.16 lifetimes [U] |
| **Keycloak 26.7.4** (Apache-2.0, JVM plus a database) [K7 V] | **Experimental**: `--features=cimd` plus a client-policy executor [K1 V, K4 V]. Promotion planned for 26.8, unreleased [K4 V] | **Yes.** Anonymous RFC 7591, effectively off by default (empty Trusted Hosts); policies; initial access tokens [K2 V] | **No** native `resource` ("cannot recognize `resource` parameter"). Workaround: a client scope with an Audience mapper whose `Included Custom Audience` is our URL [K1 V]. RFC 8707 issue open for 27.0 [K3 V]; experimental `resource-indicators` exists [K4 V] | JWT by default [K1 V] | **Yes** [K5 V] | Public clients get refresh tokens; rotation defaults [U] |
| **Authelia 4.39.28** (Apache-2.0, Go) [L1 V] | **No**, not on the roadmap [L1 V] | **No**, planned for 4.40 [L1 V] | **Partial.** `resource` must be in the client's `audience` list; regressed in 4.39.21–22, fixed 4.39.23 [L3 V]. Whether `resource` lands in `aud` [U] | **Opaque by default**; per-client `access_token_signed_response_alg` switches to RFC 9068 JWT [L2 V] | **Yes** [L1 V] | [U] |
| **Authentik 2026.8.3** (MIT core plus an enterprise licence; Python/Go plus Postgres) [N3 V] | **No** [N2 V] | **Yes, new in 2026.8**, but only with a bearer token carrying the DCR scope, which Claude can't get [N1 V] | **No** `resource` support; `aud` = the provider's `client_id` [N2 V] | Signed JWT (asymmetric, or HS256 with the client secret if no key is set; we must refuse HS256) [N3 V] | Not advertised [N2 V] | Only with `offline_access`; rotation mentioned [N3 V]; defaults [U] |
| **Zitadel 4.19.1** (**AGPL-3.0**) [Z3 V] | **No** (listed as follow-up work) [Z3 V] | **Yes** (4.17.0); `allowUnauthenticated=true` needed for MCP, and the docs name claude.ai [Z1 V] | **No.** "The `resource` parameter is accepted … but ignored"; `aud` = project ID plus every client ID in the shared DCR project [Z1 V, Z2 V] | Opaque or JWT per app; DCR apps reportedly opaque by default [Z4 V third-party] | [U] | [U] |
| **Auth0** (hosted, proprietary) [H1 V] | **Partial**: an admin imports each CIMD URL; nothing is fetched at `/authorize` [H2 V] | **Yes, open** ("anyone on the internet can create applications"); tighter controls on Enterprise [H3 V] | **Yes**, via the "Resource Parameter Compatibility Profile" toggle: `resource` defines `aud` [H4 V] | JWT, `aud` = the API identifier (our URL) [H1 V] | Toggle "Include Issuer in Authorization Responses" [H4 V] | Rotation with reuse detection [H5 V] |

Brief notes on the other hosted options:
- **Okta:** CIMD is admin-initiated, on custom authorization servers only [H6 V].
- **Microsoft Entra:** no DCR and no CIMD; a v2 token's `aud` is the client-ID GUID, not our URL
  [H7 V]. Poor fit.

**Can a Claude custom connector register, and do we get a JWT we can validate against JWKS whose
`aud` is our resource URL?**

| IdP | Verdict |
|---|---|
| Pocket ID | **Yes, with stable features.** Use a pre-registered public client (redirect `https://claude.ai/api/mcp/auth_callback`) or CIMD. With CIMD, the allow-list needs Claude's hosted CIMD URL, which is **not published** (§2 [U]); pre-registration avoids it. |
| Keycloak | **Yes.** DCR (Trusted Hosts), pre-registration, or experimental CIMD, plus a **dedicated, non-default** client scope whose Audience mapper names our URL. |
| Authelia | **Only pre-registered**, with JWT access tokens configured per client and our URL in `audience`. `aud` content is [U]. |
| Authentik | **Only pre-registered**, with `aud` = `client_id` rather than our URL. That violates "aud = our resource identifier" unless we accept an operator-configured audience (Q3). |
| Zitadel | **No**: `aud` can never be our URL, and DCR clients share one audience. |
| Auth0 | **Yes** (hosted). |

**Discovery.** Claude tries RFC 8414, then OIDC [A3 V]. The following serve RFC 8414:
- Pocket ID, since 2.14 [P4 V];
- Keycloak, path-inserted, since 26.4 [K6 V];
- Authentik, path-inserted [N4 V];
- Authelia [L1 V].

Zitadel serves OIDC discovery only [Z3 V], which Claude's fallback handles.

## 4. Proposed `auth/oauth.py` design

### 4.1 SDK helpers or our own middleware

From the installed SDK source (`mcp` 2.2.0, read 2026-09-26) [S1 V]:
- The low-level `Server.streamable_http_app(...)` **does** accept `auth: AuthSettings` and
  `token_verifier: TokenVerifier`. Auth is not tied to `MCPServer`.
- `TokenVerifier` is only a protocol (`verify_token(token) -> AccessToken | None`). **The SDK has no
  JWT or JWKS verifier on the server side.** The verification logic is ours either way.
- With a verifier, the SDK does three things:
  - Adds Starlette `AuthenticationMiddleware` (`BearerAuthBackend`) as **app-level middleware of
    its own Starlette app**.
  - Wraps the MCP route in `RequireAuthMiddleware`. Its 401 carries `error`, `error_description`
    and `resource_metadata`, **but no `scope`**. It records no failure.
  - Serves PRM through `create_protected_resource_routes`: `authorization_servers=[issuer]` only,
    and **CORS `allow_origins="*"`**.
- `BearerAuthBackend` checks `aud` only through the verifier's `AccessToken.resource`, and only
  with `validate_token_resource=True`. Otherwise a `MCPDeprecationWarning` says 3.0 will default
  it to `True`.

**Proposal: our own `OAuthAuthMiddleware` in the slot `BearerAuthMiddleware` occupies today**
(ARCHITECTURE §3 step 4, `transport/app.py`'s `authenticate(...)`). Why:

1. **The pipeline order is ours** (body cap → rate limit → Host/Origin → auth → protocol). The
   SDK's auth sits inside the SDK app, behind our route. Passing `token_verifier=` would also make
   the SDK register its own `/mcp` route and PRM route, next to ours.
2. **We need what `RequireAuthMiddleware` lacks:** `scope` in the 401 [M1 SHOULD], failure
   accounting (§5.8), 503 when verification is impossible (§4.6), and the principal attached where
   `server._principal` already looks for it (`request.state.principal`).
3. **PRM needs control the SDK route doesn't give:** no `*` CORS unless
   `DOCKHAND_MCP_ALLOWED_ORIGINS` says so, and the same Host allow-list, body cap and rate limit as
   everything else.

Reused from the SDK, all public and all present in 2.2.0 [S1 V]:
- `mcp.shared.auth.ProtectedResourceMetadata`, the RFC 9728 pydantic model, which keeps empty
  paths exact;
- `mcp.server.auth.routes.build_resource_metadata_url`, which does the RFC 9728 §3.1 path
  insertion;
- optionally `mcp.server.auth.provider.AccessToken` as the verifier's return type, which keeps a
  later move to the SDK's backend cheap.

**JWT library: PyJWT 2.15.0, already in `uv.lock` through `mcp`'s own dependency
`pyjwt[crypto]>=2.10.1`**, with `cryptography` 50.0.1 [S1 V, S2 V].
- MIT licence [S2 V].
- Declaring it as a *direct* runtime dependency is still a CLAUDE.md STOP-and-ask (Q1), even
  though it adds nothing to the lock or the image.
- Relevant behaviour, read from its source [S2 V]:
  - `decode()` requires an explicit `algorithms` list, **except** when the key is a `PyJWK`, where
    `algorithms=None` infers the algorithm from the key (`api_jws.py`). We must always pass the
    allow-list.
  - The HMAC algorithm refuses PEM-shaped asymmetric keys (the RS→HS confusion guard).
  - `leeway`, `issuer`, `audience` and `options={"require": [...]}` are supported.
  - `PyJWKClient` fetches with blocking `urllib`. So the **JWKS fetch is ours**, async, over
    `httpx` (our existing dependency), and PyJWT only parses (`PyJWKSet`/`PyJWK`) and verifies.

**The `oauth` request path, end to end:**

```
POST /mcp
  1 body cap            (unchanged)
  2 global rate limit   (unchanged; see §5.8 for connector traffic)
  3 Host/Origin         (unchanged)
  4 OAuthAuthMiddleware
      no/other-scheme Authorization  -> 401 challenge (not counted as a failure)
      token > 8 KiB, 2+ headers      -> 401 invalid_token
      JWT header: alg in allow-list, typ ok, kid present, no crit we don't understand
      key = JWKS cache[kid]  (miss -> single-flight refresh, at most one per 60 s)
      verify signature; iss ==; aud ∋ RESOURCE_URL; exp/nbf/iat ±skew; sub present
      allowed subject / email domain / client  -> else 403 (not a challenge; §4.3)
      scopes -> scope profile; none mapped    -> 403 insufficient_scope
      principal = Principal("oauth:" + sub, min(server profile, scope profile))
  5 protocol checks     (unchanged)
  6 SDK
GET /.well-known/oauth-protected-resource<path>   (steps 1–3 only, no auth)
```

### 4.2 Configuration (the reserved names; ARCHITECTURE §5 is not edited here)

All are parsed only when `DOCKHAND_MCP_AUTH_MODE=oauth`. Setting any of them in another mode is a
startup error, so a leftover setting can't give a false sense of protection.

| Variable | Default | Proposal |
|---|---|---|
| `DOCKHAND_MCP_RESOURCE_URL` | *(required)* | Our resource identifier, exactly as users enter it in Claude, e.g. `https://mcp.example.test/mcp`. `https`; lowercase scheme and host; no userinfo, query or fragment; no trailing slash; path equal to `DOCKHAND_MCP_PATH`; host in `DOCKHAND_MCP_ALLOWED_HOSTS`. It is compared exactly with `aud` entries, since `aud` is a case-sensitive string (RFC 7519). |
| `DOCKHAND_MCP_OAUTH_ISSUER` | *(required)* | The AS issuer, compared with the token's `iss` and the metadata's `issuer` **byte for byte** (a trailing slash matters). `https` only. |
| `DOCKHAND_MCP_OAUTH_JWKS_URL` | *(from AS metadata)* | Override for `jwks_uri`. `https`, and **same origin as the issuer** unless Q7 decides otherwise (§5.5). A WARN at every startup names its host. |
| `DOCKHAND_MCP_OAUTH_ALGORITHMS` | `RS256,PS256,ES256,EdDSA` | Allow-list. Any `HS*` and `none` are refused at config time. RSA keys < 2048 bits are refused when loaded. |
| `DOCKHAND_MCP_OAUTH_REQUIRED_SCOPES` | *(required, ≥ 1)* | Scopes every token must carry to be served at all (they go into the 401's `scope` and PRM `scopes_supported`). E.g. `dockhand:read`. Scope names are IdP-defined, so no default is assumed. |
| `DOCKHAND_MCP_OAUTH_SCOPE_PROFILES` | *(unset: every accepted token gets the server's profile)* | Comma list `scope=profile`, e.g. `dockhand:read=read-only,dockhand:operate=operator,dockhand:admin=admin`. A token's scope profile is the highest mapped profile among its scopes; the effective profile is `min(DOCKHAND_MCP_PROFILE, scope profile)`. A mapping above the server profile is a startup error. Hierarchy: holding a higher mapped scope implies the lower ones [M1 MUST]. |
| `DOCKHAND_MCP_OAUTH_ALLOWED_SUBJECTS` | — | Comma list of exact `sub` values. |
| `DOCKHAND_MCP_OAUTH_ALLOWED_EMAIL_DOMAINS` | — | Comma list; matched on the `email` claim **only with `email_verified: true`** in the *access token*. Many IdPs don't put `email` in access tokens [U per IdP], so it is best effort. **At least one of the two allow-lists is required**; startup fails otherwise (§5.3). |
| `DOCKHAND_MCP_OAUTH_ALLOWED_CLIENTS` | — (any) | Optional: exact values of `client_id` (RFC 9068), or `azp` if absent. Pins the connector's client (pre-registered ID, or Claude's CIMD URL once known). Useless with DCR, where every connection is a new client [A1]. |
| `DOCKHAND_MCP_OAUTH_REQUIRE_TYP` | `true` | Require `typ` `at+jwt`/`application/at+jwt` [R5]. Pocket ID sets it [P4]. Keycloak's `typ` is [U]. `false` is an escape hatch; the `aud` check still rejects ID tokens (their `aud` is a client ID), unless a client ID *is* our URL, which startup refuses when `ALLOWED_CLIENTS` contains `RESOURCE_URL`. |
| `DOCKHAND_MCP_OAUTH_CLOCK_SKEW` | `30` | Seconds of leeway for `exp`/`nbf`/`iat`; 0–60 (60 is the prompt's ceiling). |
| `DOCKHAND_MCP_OAUTH_INTROSPECTION_URL`, `…_INTROSPECTION_CLIENT_ID`, `…_INTROSPECTION_CLIENT_SECRET[_FILE]` | — | **Reserved, not implemented in v1** (§4.7). |

Startup combinations to refuse, in addition to SECURITY §6's existing "stdio with oauth":
- `oauth` with `DOCKHAND_MCP_TOKEN[_FILE]` set (no bearer fallback; §7);
- an `http://` issuer, resource or JWKS URL;
- neither allow-list set;
- `DOCKHAND_MCP_BIND` loopback while `RESOURCE_URL` names a non-loopback host is **not** an error.
  A proxy in front is the normal case.

### 4.3 Principal, profile ceiling, and what binds to them

- **Name:** `Principal.name = "oauth:" + sub`. `sub` is unique only per issuer [S1 V: the SDK's
  `AccessToken.subject` comment]. With exactly one configured issuer, the issuer needs no
  encoding. A second issuer would be a new design (§5.2).
- **Limits:** `sub` is capped at 255 characters. A `sub` with control characters is refused (401
  `invalid_token`), because it lands in logs and challenges.
- **Existing bindings keep working unchanged:**
  - `op_id` ownership compares the whole `Principal` (`operations.get`: `op.principal !=
    principal`). A user whose effective profile changes between calls (new scopes after a
    refresh) loses access to their earlier `op_id`s. That fails closed, and is acceptable.
  - Approval challenges bind `principal.name` (`approval.mint_challenge`/`verify_challenge`).
    Another user's approval can't be replayed, and a refreshed token for the same `sub` still
    matches.
  - The destructive rate limit (S-11) keys on `principal.name`, so it becomes per user, as
    intended.
- **Profile ceiling (touches D-005; Q2).** Tools are registered for `DOCKHAND_MCP_PROFILE` at
  startup, as today. The effective profile is per request:
  - `list_tools` filters to `tier ≤ principal.profile`;
  - `call_tool` answers a tool above it exactly like an unregistered tool (JSON-RPC `-32602`
    "Unknown tool"), so a lower-profile user can't discover it;
  - `profile_denied` stays the defence-in-depth code, never reached.
  - A token can never raise anything above the server's profile; it can only lower it.
  - The IdP, not the client, decides which scopes a user gets, so D-005's "set by configuration,
    not by the client" still holds.
- **Allow-list failures:** a valid token whose subject, email domain or client is not allowed →
  **403** with a JSON error and **no** `insufficient_scope` challenge. Claude treats it as terminal
  [A4 V] instead of re-running consent. It counts toward the auth-failure accounting (§5.8).
- **Multiple principals:** this is the first mode where one instance serves several human
  principals. They all act through the one DockHand token (plan §3 non-goal; SECURITY §2
  "confused deputy"). The allow-lists are what keep that set small and deliberate.

### 4.4 JWKS caching and rotation

- **Source:** `jwks_uri` from the AS metadata fetched at startup, or `DOCKHAND_MCP_OAUTH_JWKS_URL`.
- **Fetching:**
  - `httpx.AsyncClient(trust_env=False, follow_redirects=False)`, TLS verified;
  - `DOCKHAND_CA_BUNDLE` is not reused: a separate `DOCKHAND_MCP_OAUTH_CA_BUNDLE` is an option
    (Q8);
  - connect 5 s, read 5 s;
  - body ≤ 64 KiB; `application/json` only.
- **Keys used:**
  - keys with `use` = `sig` or absent;
  - `kty` RSA (≥ 2048 bits), EC P-256/P-384, OKP Ed25519;
  - an `alg` on the key, if present, must be in the allow-list;
  - at most 20 keys kept;
  - a token must carry a `kid`, and its header `alg` must equal the key's `alg` when the key has
    one.
- **TTL:** 10 minutes (the SDK and PyJWT use 5 minutes by default [S2 V]; ten halves the traffic
  and is well inside common rotation overlaps). An upstream `Cache-Control: max-age` is honoured,
  clamped to 1–60 minutes. A proactive refresh starts when the TTL lapses; requests keep using the
  cached set while it runs.
- **Unknown `kid`:**
  - one single-flight refresh, **at most one per 60 s**, process-wide;
  - a second unknown `kid` within that minute is `401 invalid_token` without a fetch;
  - so an attacker spraying random `kid`s causes at most one JWKS fetch a minute.
- **Staleness ceiling:** if refreshes fail, the last good set keeps verifying for at most
  **24 hours** past its TTL (Q6). After that every request is **503** (§4.6).
- **Rotation behaviour:** a new key appears on the next refresh or on the first token that uses
  it (the `kid` miss). A removed key stops verifying at the next successful refresh.
- **Logging:** the JWKS body is never logged, only key counts and `kid`s (truncated to 64
  characters).

### 4.5 Validation rules, in order (each failure → 401 `invalid_token` unless noted)

1. **Header:** exactly one `Authorization` header, scheme `Bearer`, the token ≤ 8 KiB, three
   base64url segments.
2. **JOSE header:**
   - `alg` in the allow-list; never `none`, never `HS*`;
   - `typ` rule (§4.2);
   - `kid` present;
   - `crit` absent, or naming only understood parameters;
   - `jku`, `x5u`, `jwk` and `x5c` ignored and never fetched [R6 §3.10].
3. **Signature** with the JWKS key for `kid` (§4.4).
4. **Claims:**
   - `iss` equals the issuer exactly;
   - `aud` (string or array) contains `DOCKHAND_MCP_RESOURCE_URL` exactly;
   - `exp` required and `> now - skew`;
   - `nbf`, if present, `≤ now + skew`;
   - `iat`, if present, `≤ now + skew`;
   - `sub` required and non-empty.
5. **Allow-lists** (§4.3) → 403.
6. **Scopes:**
   - read from `scope` (a space-separated string, RFC 9068) or `scp` (an array, as Okta and Entra
     use; [U] per IdP);
   - `REQUIRED_SCOPES` all present, else **403 `insufficient_scope`** with
     `scope="<required> <mapped>"` and `resource_metadata` [M1];
   - then the profile map (§4.2).

**The challenge.** Every 401 carries:

```
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp", scope="dockhand:read"
```

- `error="invalid_token"` is added when a token was presented.
- `error_description` is a fixed string per failure class. It never echoes claim values.
- `REALM` is dropped from the oauth challenge: RFC 6750 makes it optional, and it tells an
  unauthenticated caller nothing useful.

**PRM document**, at `GET /.well-known/oauth-protected-resource<DOCKHAND_MCP_PATH>`:
- Contents: `{"resource": RESOURCE_URL, "authorization_servers": [ISSUER], "scopes_supported":
  REQUIRED_SCOPES + mapped scopes, "bearer_methods_supported": ["header"]}`.
- No `resource_name`, documentation, policy or `jwks_uri` fields: nothing about the deployment.
- Never `offline_access` [M1].
- `Cache-Control: public, max-age=3600` (the SDK's value [S1 V]).
- `GET` only; no CORS headers unless the request's `Origin` is in `DOCKHAND_MCP_ALLOWED_ORIGINS`.
- The root `/.well-known/oauth-protected-resource` is **not** served: its `resource` would have to
  be the origin, not our identifier [R1 §3.3]. The header pointer is what Claude uses first [A1].
- **Scope choice:** listing only `REQUIRED_SCOPES` in the 401 would make Claude request just those,
  and the user would get `read-only` even where the IdP would grant `operator`. Listing every mapped
  scope asks the IdP for all of them and lets it grant what the user may have (Q4).

### 4.6 Startup, `check`, and the IdP being down

- **`serve`** (oauth), before binding:
  1. Fetch the AS metadata, as the spec's client order does [M2 V]: for an issuer with a path,
     RFC 8414 path-inserted, then OIDC path-inserted, then OIDC path-appended; without a path,
     RFC 8414, then OIDC.
  2. Require `issuer` to equal the configured issuer exactly [M2 V].
  3. Read `jwks_uri` (or the override) and fetch the JWKS.
  4. Require at least one usable key for the algorithm allow-list.
  5. Any failure → exit non-zero with a one-line reason (SECURITY §6 style).

  **An unreachable IdP means the server does not start** (fail closed).
- **At runtime, the IdP being down:**
  - tokens whose `kid` is cached keep verifying until the staleness ceiling (§4.4);
  - an unknown `kid` is 401;
  - past the ceiling, every `/mcp` request gets **503** `{"error":"temporarily_unavailable"}`,
    with `Retry-After` and no `WWW-Authenticate`, so clients don't start a sign-in loop they
    can't finish;
  - `/healthz` stays `200 {"status":"ok"}` (F-02 says it reports nothing else). Q6 asks whether
    that is still right.
- **`dockhand-mcp check`** (oauth) adds an `oauth` section to its JSON:
  - the resource URL;
  - the issuer and whether the metadata's `issuer` matches;
  - the discovery path that worked;
  - the `jwks_uri` host;
  - key count and algorithms;
  - AS capability flags read from the metadata:
    - `client_id_metadata_document_supported`;
    - `none` in `token_endpoint_auth_methods_supported`;
    - `registration_endpoint` present;
    - `authorization_response_iss_parameter_supported`;
    - `code_challenge_methods_supported` includes `S256`.

  From those flags it prints which registration path Claude would take [A1 V]. A failure is a
  `problem` (exit 1).
  - It **cannot** check that the IdP honours `resource`: that needs a real authorization. The
    manual runbook (§6.3) covers it.
  - Never printed: tokens, the JWKS body, introspection secrets.

### 4.7 Opaque tokens and introspection (not in v1)

Pocket ID, Keycloak, Auth0, Authentik and Authelia (configured per client) can all issue JWTs, so
v1 supports JWT access tokens only. An opaque token fails as `invalid_token` (it isn't three
segments). If a later version adds RFC 7662:
- the RS authenticates to the AS [R7 V], so we would hold a new secret, with `_FILE`, masked in
  `check`, and never logged;
- every uncached request costs an AS round trip, with the IdP on the hot path (a down IdP means
  immediate 503);
- responses may be cached only up to the token's `exp` [R7 V] (and we'd cap that at 60 s, keyed by
  a SHA-256 of the token, never the token itself).

### 4.8 Audit and logs

- **The `tool_call` audit line gains** `auth_mode: "oauth"` (and `"bearer"`/`"none"` in the other
  modes), `principal` (`oauth:<sub>`), `client_id`, `scopes` (the granted scopes that are mapped or
  required, capped at 16), `effective_profile`, and `token_id`: the first 12 hex digits of
  SHA-256 over `jti`, or over the token if there is no `jti`.
  - That is enough to correlate calls made with one token, and useless as a credential.
  - The token, its signature, `aud`/`iss` values from a *failed* token, and any other claims are
    never logged.
- **One `auth_failure` line per refused token:** reason code (`malformed`, `alg`, `typ`,
  `unknown_kid`, `signature`, `iss`, `aud`, `expired`, `not_yet_valid`, `no_sub`,
  `subject_not_allowed`, `client_not_allowed`, `insufficient_scope`), client IP, truncated `kid`.
  - It never logs a claim value from a token that failed signature verification: those are
    attacker text.
- **One `oauth_keys` line per JWKS refresh:** outcome, key count, and `kid`s added and removed.
- **`sub` is personal data** when an IdP uses email-like subjects (Pocket ID's and Keycloak's are
  UUIDs by default [U]). Q9 asks whether to log a hash of it instead.

### 4.9 `scripts/smoke.py`

- **`--access-token-file` (or `DOCKHAND_MCP_ACCESS_TOKEN_FILE`):** a pre-obtained access token is
  sent as the same `Authorization: Bearer` header. Like the bearer token, it is never printed and
  never taken from argv.
- **New subcommand `oauth-probe`:**
  - an unauthenticated POST → expect 401 with a `resource_metadata` and a `scope` parameter;
  - fetch the PRM → `resource` equals `--url`, and `authorization_servers` is exactly one entry;
  - a runtime-built garbage JWT → 401 `invalid_token`;
  - a `HEAD`/`GET` of `/healthz` → 200.

  It prints only statuses and the PRM's non-secret fields.
- **Optional (CI only):** obtain a token through the SDK's `ClientCredentialsOAuthProvider` [S1 V]
  against Pocket ID's `client_credentials` grant [P2 V]. The resulting `sub` is
  `client-<client_id>` [P7 V], so the test instance allows that subject.
  - Never use this against a production IdP. Claude itself never uses `client_credentials` [A1 V].

## 5. Threat review

### 5.1 Audience confusion
- **Threat:** a token issued for something else (the IdP's own userinfo or admin API, another
  resource server on the same IdP, an ID token) is presented to us.
- **Mitigations:** exact-match `aud` containing our resource URL, plus the `typ` check.
- **Residual risk:** IdPs without RFC 8707 add our URL through admin mappers (Keycloak, Authelia)
  or use a fixed `client_id` audience (Authentik).
  - If a Keycloak Audience mapper sits in a *default* client scope, every token the realm issues
    carries our `aud`, whatever client asked. That is exactly the confusion `aud` exists to stop.
  - Mitigations: the runbook requires a dedicated optional scope; the subject allow-list;
    optionally `ALLOWED_CLIENTS`.
  - Pocket ID binds `aud` from `resource` itself [P2], which is the best case.

### 5.2 Mix-up attacks across authorization servers (RFC 9207)
- **Threat:** a client talking to several ASes is tricked into sending a code or token to the
  wrong one [R3 V]. The defence is client-side `iss` validation, now a client MUST in 2026-07-28
  when `iss` is present [M5 V].
- **Our part:**
  - list exactly one AS in the PRM (Claude uses only the first anyway [A1 V]);
  - require `iss` to equal that issuer;
  - never accept tokens from a second issuer.
- **Recommendation:** pick an IdP that advertises `authorization_response_iss_parameter_supported`
  (Pocket ID, Keycloak, Authelia, Auth0 with its toggle).
- **Out of scope:** multi-issuer support. It would need principals keyed by `(iss, sub)` and a
  choice of AS per client, which Claude doesn't make.

### 5.3 Open registration on the IdP, and why it matters to us
- **Client registration (DCR/CIMD) creates clients, not users.** By itself it grants nothing. But:
  - **Consent phishing.** An attacker registers a client (open DCR, or a CIMD URL the IdP
    accepts) and lures one of our users through consent. The resulting token carries our `aud`,
    because the attacker's client asked for our `resource`. That is a working token for our tools
    in the attacker's hands.
  - Mitigations:
    - prefer a **pre-registered** client or a **CIMD allow-list** (Pocket ID's is explicit [P1])
      over open DCR, and pin it with `ALLOWED_CLIENTS`;
    - require consent screens that show the redirect host [A1];
    - with Keycloak DCR, restrict Trusted Hosts [K2] and require consent.
  - Open DCR can't be pinned by client ID (every Claude connection is a new client [A1]), so it is
    the weakest option.
- **User self-registration** on the IdP is the bigger hole: anyone who can create an IdP account
  can get a token. This is why an allow-list (subjects or email domains) is **mandatory** in our
  design. It holds even when the IdP is misconfigured.

### 5.4 Token replay across two instances
- **Threat:** two dockhand-mcp instances on one IdP (e.g. an `operator` instance and an `admin`
  instance). A token for the operator instance, replayed to the admin instance, must fail.
- **Mitigation:**
  - distinct `DOCKHAND_MCP_RESOURCE_URL`s (host or path), each an exact `aud`;
  - the IdP must bind `aud` per resource: Pocket ID does it from `resource` [P2]; with Keycloak,
    use one Audience-mapper scope **per instance**.
- **Residual risk:** one realm-wide mapper listing both URLs defeats this. The runbook says so.
- `check` could warn when two instances share a resource URL, but it can't see the other
  instance. That is operator documentation only.

### 5.5 JWKS override abuse
- **Threat:** `DOCKHAND_MCP_OAUTH_JWKS_URL` pointed at attacker-controlled keys lets the attacker
  mint any token. It is configuration, so it carries the same trust as the issuer. The risk is
  misconfiguration, or an injected environment variable.
- **Mitigations:**
  - `https` only;
  - no redirects;
  - **same origin as the issuer by default** (Q7);
  - a WARN at every startup naming the host;
  - `check` reports it;
  - RFC 8725 §3.8 wants keys that belong to the issuer [R6 V]: the metadata's `jwks_uri` gives
    that provenance, and an override removes it.
- **Never fetched:** `jku`/`x5u` from token headers, which would let the attacker choose [R6 V].

### 5.6 Introspection credential handling
- Not implemented in v1 (§4.7).
- If added: the credential is a secret like the MCP token.
  - It goes through `_FILE` only in docs, is masked in `check`, is added to `logging.redact()`'s
    configured secrets, and is sent only to the configured introspection URL (same origin as the
    issuer).
  - Responses are cached by token hash only.
  - Its compromise lets an attacker probe token validity and read claims; it does not mint tokens.

### 5.7 IdP down → fail closed
- **At startup:** the server refuses to start (§4.6).
- **At runtime:** cached keys keep working up to the staleness ceiling; after that, 503.
- **Never:** "accept without verifying", "fall back to bearer" or "skip signature checks while the
  IdP is down". None of these paths exists.
- **Revocation:** a JWT stays valid until `exp` even if the IdP revokes it. The runbook asks for
  short access-token lifetimes (5–15 minutes), traded against #228's missing refresh [G1].

### 5.8 Internet exposure: the unauthenticated surface, rate limits, DoS
**What an unauthenticated caller reaches:**
- `/healthz` (`{"status":"ok"}`);
- the PRM document (our resource URL, the issuer URL, scope names);
- a 401 challenge on `/mcp`.

**What stays behind auth:** `tools/list`, `server/discover` and every other MCP method (D-004).

The PRM reveals which IdP protects the server. That is unavoidable, since clients need it, and
acceptable.

**Pre-auth cost per request:**
- body cap (1 MiB);
- token ≤ 8 KiB;
- one base64 decode and one signature verification against a cached key (sub-millisecond for
  RS256/ES256);
- the JWKS refresh capped at one per minute, so an attacker cannot make us hammer the IdP.

**Rate limits and connectors (design change; Q10).** Every connector request arrives from
`160.79.104.0/21` [A1 V]. That includes discovery traffic caused by *anyone* who adds our URL to
their own Claude account. So:
- **The global limit (120/min per IP) becomes shared** by all our connector users *and* any
  stranger's connector.
- **The auth-failure block** (10 failures in 5 min → IP blocked for 5 min) lets anyone who can make
  Anthropic send us bad tokens lock out every legitimate connector user. Example: an Owner in the
  static-headers beta setting `authorization: Bearer junk` [A1].
- **Guessing is not a threat in `oauth` mode:** a JWT can't be guessed. The failure block exists
  for bearer-token brute force.

**Proposal:**
1. In `oauth` mode, keep *counting* auth failures (logs, metrics), but make **blocking** configurable
   and **off by default**.
2. Keep the pre-auth per-IP limit, with a higher default under `oauth` (e.g. 600/min), because it
   can't tell users apart.
3. Add a **post-auth per-principal limit** keyed on `principal.name` (default 120/min per user),
   answered with 429.
4. Operators exposing the server only to connectors should allowlist `160.79.104.0/21` at the
   proxy [A1 V, A6 V]. That is deployment documentation, not code: the range is Anthropic's, and
   hard-coding it would tie the server to one vendor.

`DOCKHAND_MCP_TRUST_PROXY` semantics are unchanged: the right-most `X-Forwarded-For` entry is then
Anthropic's egress address.

## 6. Test plan

### 6.1 Unit tests (every PR; no network)

**Keys and fixtures:**
- Keys are generated at test time with `cryptography` (RSA-2048, P-256, Ed25519).
- Tokens are signed with PyJWT inside the test (the standing rule: nothing token-shaped is
  committed).
- JWKS and AS metadata are served through `respx` at `https://idp.example.test`.
- The resource URL is `https://mcp.example.test/mcp`; DockHand stays `https://dockhand.example.test`
  with environment `7`.

**Must accept:**
- a valid RS256 token with `typ: at+jwt`, `aud` a string;
- `aud` an array containing ours plus the issuer (Pocket ID's shape);
- ES256 and EdDSA;
- `exp` within the skew;
- `nbf` absent;
- `scp` array scopes.

**Must reject (401 `invalid_token`, no principal, the audit reason code checked):**
- wrong `aud`;
- `aud` array without ours;
- `aud` with a trailing slash or an upper-case host (exact match);
- wrong `iss`, including a trailing-slash variant;
- expired beyond the skew;
- `nbf` in the future beyond the skew;
- `iat` in the future;
- missing `sub` or `exp`;
- unknown `kid` (then one JWKS refresh, then reject);
- a second unknown `kid` within 60 s (no second fetch: count the `respx` calls);
- `alg: none` (hand-built unsigned token);
- **HS256 signed with the RSA public key's PEM as the HMAC secret** (RS→HS confusion);
- the header `alg` differs from the key's `alg`;
- `typ: JWT` with `REQUIRE_TYP=true`;
- unknown `crit`;
- a `jku` header pointing elsewhere (assert no request to it);
- a token over 8 KiB;
- two `Authorization` headers;
- `Basic` scheme (401 challenge, not counted);
- an opaque token.

**Must 403:**
- subject not allowed;
- email domain without `email_verified`;
- client not allowed;
- missing required scope (with the `insufficient_scope` challenge and the full scope list).

**Profile:**
- the scope map's `min(server, scope)`;
- `tools/list` filtered;
- a tool above the ceiling → "Unknown tool";
- an `op_id` from `oauth:alice` refused for `oauth:bob`;
- an approval challenge minted for `oauth:alice` refused for `oauth:bob`.

**JWKS:**
- TTL refresh;
- stale-while-refreshing;
- staleness ceiling → 503;
- body > 64 KiB refused;
- redirect not followed;
- an RSA-1024 key ignored.

**Startup:**
- metadata `issuer` mismatch → exit;
- IdP unreachable → exit;
- no allow-list → exit;
- bearer token set with `oauth` → exit;
- a JWKS override on another origin → exit (per Q7);
- `HS256` in `ALGORITHMS` → exit.

**PRM and challenge:**
- exact document;
- path-inserted route only;
- no CORS by default;
- Host allow-list applies;
- the 401 `WWW-Authenticate` parses and carries `resource_metadata` and `scope`;
- no claim values echoed.

**No passthrough:** a `respx` assertion over every tool test in oauth mode. No request to
DockHand carries the MCP access token, and every one carries only the `dh_` token.

**Failing-test commit first**, as CLAUDE.md requires.

### 6.2 Integration against a real IdP in CI (feasibility and cost)

**Actions minutes:**
- GitHub Pro includes **3,000 Actions minutes a month** for private repositories [C1 V];
- Linux 2-core costs **$0.006/min** beyond that [C2 V];
- every job is rounded up to the whole minute [C2 V].

**Pocket ID 2.16.0 as a `docker run` step** (BSD-2-Clause, Go binary):
- Headless setup through its REST API with `STATIC_API_KEY` [P3 V]: create an "API" with our
  resource URL, create a confidential client, set its secret [P8 V].
- Obtain a token with `client_credentials` and `resource=` [P2 V], then run the SDK client with it
  against a server built from the branch.
- This proves real `resource` → `aud` binding, JWKS fetch and RFC 8414 discovery.
- It cannot prove the browser authorization-code leg. That stays manual (§6.3).

**Keycloak 26.7.4:**
- the image is about 268 MB compressed (amd64) [C6 V];
- realm import with `--import-realm` [K7 V];
- no `resource` binding (Audience mapper only) [K1 V];
- the realm JSON must be mounted after checkout, so `docker run` is needed, not a `services:`
  container. That last point is an inference from how services start [U].

**navikt/mock-oauth2-server 6.0.3** (MIT): JWKS and custom claims [C5 V], but not a real IdP's
behaviour.

**Estimate** (the research pass's arithmetic; pull and startup times are [U]):
- about 2 billed minutes per run as a separate job;
- only on PRs touching `src/dockhand_mcp/auth/` (about 20 a month): about **40 min/month**;
- on every PR (about 60): about **120 min/month**;
- either is ≤ 4 % of the allowance, and **$0** while under it (≤ $0.72/month if billed).

**Recommendation:** a separate `oauth-it` job, **not required**, run on PRs touching
`src/dockhand_mcp/auth/**` or `transport/app.py`, with Pocket ID pinned by digest (D-013 applies:
newest release, Dependabot's `docker` ecosystem won't see a workflow `docker run`, so bump it by
hand like the binfmt pin). The implementation session decides whether to add it (Q11).

### 6.3 Manual custom-connector runbook (Pocket ID as the reference)

Prerequisites:
- public DNS with an `A` record for both hosts (Claude is IPv4-only [A3]);
- valid TLS;
- the MCP proxy and the IdP's `/.well-known/*` and `/api/oidc/token` reachable from
  `160.79.104.0/21` [A1 V];
- the IdP's authorize page reachable from the user's browser.

1. **IdP**
   - Create an "API" whose identifier is exactly `https://mcp.example.test/mcp`, with permissions
     `dockhand:read`, `dockhand:operate` [P2].
   - Create a **public** OIDC client with redirect URI `https://claude.ai/api/mcp/auth_callback`,
     PKCE on, restricted to the intended user group.
   - Turn off open user sign-up.
   - Set access-token lifetime to 10–15 minutes.
2. **Server**
   - `DOCKHAND_MCP_AUTH_MODE=oauth`;
   - `DOCKHAND_MCP_RESOURCE_URL=https://mcp.example.test/mcp`;
   - `DOCKHAND_MCP_OAUTH_ISSUER=<Pocket ID URL>`;
   - `DOCKHAND_MCP_OAUTH_REQUIRED_SCOPES=dockhand:read`;
   - `DOCKHAND_MCP_OAUTH_SCOPE_PROFILES=dockhand:read=read-only,dockhand:operate=operator`;
   - `DOCKHAND_MCP_OAUTH_ALLOWED_SUBJECTS=<your sub>`;
   - `DOCKHAND_MCP_OAUTH_ALLOWED_CLIENTS=<client id>`;
   - `DOCKHAND_MCP_PROFILE=operator`;
   - `mcp.example.test` added to `DOCKHAND_MCP_ALLOWED_HOSTS`.
3. **Pre-flight**
   - `dockhand-mcp check` shows the issuer match, the keys, and the capability flags.
   - `smoke.py oauth-probe --url https://mcp.example.test/mcp` passes.
4. **Claude.ai**
   - Customize › Connectors › Add custom connector, with URL `https://mcp.example.test/mcp`.
   - Advanced settings: the client ID, secret blank [A5].
   - Connect; sign in with a passkey at the IdP.
5. **Expect**
   - Server logs: one 401 challenge, then `tool_call` lines with `principal: oauth:<sub>` and
     `effective_profile: operator`.
   - Token claims: `aud` contains the resource URL.
   - Ask Claude to list stacks: a read tool works.
   - Set destructive tools to **Needs approval** or **Blocked**. At `operator` there are none.
6. **Negative checks**
   - Remove your `sub` from the allow-list and restart: connector calls fail with a terminal
     error (403), not a sign-in loop.
   - Point `RESOURCE_URL` at another path: tokens are refused (`aud`).
7. **Refresh (#228)**
   - Wait past the access-token lifetime and call a tool again.
   - Record whether Claude refreshed or asked you to reconnect.
8. **Other surfaces:** repeat step 4 from Claude Desktop's Connectors and from mobile (beta [A7]).
   Same infrastructure, expected the same [A1].
9. **Record the CIMD client ID.** Note the `client_id` Claude presents with CIMD, from the IdP's
   logs, if you enable Pocket ID's CIMD with a temporary broad allow-list on a test instance.
   That URL is unpublished today [U]; knowing it lets `ALLOWED_CLIENTS` pin CIMD.

## 7. Recommendation

**Implement now, as our own middleware (§4). Not later, and not as a sidecar.**
- **The spec needs nothing from us that SECURITY §3 forbids** (§1).
- **The design is small:** about 400 lines plus tests. PyJWT is already locked. The SDK's metadata
  model covers the RFC 9728 details.
- **It is the only way** claude.ai, mobile and Desktop's Connectors can reach the server without the
  Owner-only static-headers beta [A1, A5].
- **A verifiably working self-hosted IdP exists** (Pocket ID, stable features; Keycloak with a
  mapper).
- **Why not a sidecar** (oauth2-proxy or a tiny AS in front, ARCHITECTURE §1.1's fallback):
  - It would terminate auth outside the process, so the principal bound into `op_id`s, approval
    challenges and the destructive rate limit would collapse back to one static principal.
  - Scope → profile mapping would be impossible.
  - We would still have to serve RFC 9728 metadata and the challenge ourselves. Whether
    oauth2-proxy can do that was not checked [U].
  - The sidecar remains the fallback only if the implementation session finds a blocker.
- **Why not later:** nothing we're waiting on belongs to us.
  - The open connector bugs (#228 refresh, #341 discovery) affect every self-hosted resource
    server, and don't change our design.
  - Waiting for connector elicitation (#153) only affects destructive tools, which a connector
    deployment should not expose anyway (next point).
- **Ship it as `experimental`** in `docs/CLIENTS.md`, recommending `DOCKHAND_MCP_PROFILE=operator`
  for connector instances.
  - Connectors don't elicit [A2, G5], so D-006's human approval degrades to `confirm` plus Claude's
    per-tool **Needs approval** setting.
  - Q5 asks whether `oauth` + `admin` should require `CONFIRM_MODE=elicitation` (which would make
    destructive tools unusable over connectors until #153 ships).

**Bearer and oauth in one instance: no.** SECURITY §3 stands, for these reasons:
- A static bearer token beside OAuth becomes the weakest credential on an internet-facing
  endpoint. It bypasses the subject allow-list, IdP revocation and token expiry.
- Principals would come from two namespaces with different ceilings, and the audit would be
  ambiguous about which gate admitted a call.
- The 401 challenge would have to be right for both kinds of client at once.
- Operators who need both run two instances: a bearer instance on a private network for Claude
  Code and scripts, and an oauth instance behind the public proxy.
- Claude Code can also use the oauth instance (loopback redirect, its own CIMD [A1]).

**Implementation session:** Opus 5.5, high effort. Auth code on an internet-facing Docker control
plane deserves it. Scope:
- `auth/oauth.py`, the app wiring, `config.py` for the §4.2 variables (once Q3 is answered);
- `check`, `smoke.py`;
- the unit tests (§6.1);
- docs: ARCHITECTURE §2/§3/§5, SECURITY §3/§6 (maintainer-approved text), CLIENTS §4, and
  `deploy/.env.example`;
- the §6.3 runbook as a doc.

The CI integration job is optional (Q11).

## 8. Open questions for the maintainer

1. **Dependency.** May `auth/oauth.py` import PyJWT (MIT, 2.15.0) directly and declare
   `pyjwt[crypto]` in `pyproject.toml`? It is already in `uv.lock` through `mcp`, so nothing new
   ships, but CLAUDE.md makes a new runtime dependency a STOP.
2. **D-005 wording.** Per-request profile ceilings mean tools are *registered* for the server
   profile and *filtered* per principal (hidden from `tools/list`, "Unknown tool" on call). Accept
   this reading of D-005, or keep "one profile per instance" and drop `SCOPE_PROFILES` from v1?
3. **Config schema.** Approve the §4.2 variable names and semantics (they fill the reserved
   `DOCKHAND_MCP_RESOURCE_URL`/`DOCKHAND_MCP_OAUTH_*` names, but it is a post-Phase-1 schema
   change). Also: should Authentik-style deployments (`aud` = client ID) be allowed through an
   explicit `DOCKHAND_MCP_OAUTH_AUDIENCE` override, or stay unsupported, since `aud` must be our
   resource URL [M1]?
4. **Scopes in the challenge.** Put every mapped scope in the 401's `scope` (users get the
   highest profile the IdP grants them), or only the required ones (everyone starts at the lowest
   profile)?
5. **Destructive tools over connectors.** Should `oauth` + `admin` refuse to start unless
   `DOCKHAND_MCP_CONFIRM_MODE=elicitation`? Connectors don't elicit today, so that would mean
   "no destructive tools over connectors" until Anthropic ships #153.
6. **IdP outage.** Is a 24-hour staleness ceiling on cached JWKS right? And should `/healthz`
   stay `ok` while verification is impossible (F-02 says it reports nothing else), or go
   unhealthy so an orchestrator restarts, which would then fail closed at startup?
7. **JWKS override origin.** Require `DOCKHAND_MCP_OAUTH_JWKS_URL` to share the issuer's origin,
   or allow any `https` origin with a WARN?
8. **Private CA for the IdP.** Add `DOCKHAND_MCP_OAUTH_CA_BUNDLE`, or reuse `DOCKHAND_CA_BUNDLE`
   (which is scoped to DockHand today)?
9. **`sub` in logs.** Log `oauth:<sub>` as-is, or a salted hash, for IdPs whose subjects are
   email-like?
10. **Rate limiting under `oauth`.**
    - Should auth-failure *blocking* be off by default (counting kept), given that all connector
      traffic shares `160.79.104.0/21`?
    - Add a per-principal post-auth limit (default 120/min)?
    - Raise the per-IP default to 600/min in this mode?
    - These change rate-limit behaviour, a STOP item.
11. **CI integration job.** Add the optional, path-filtered Pocket ID `oauth-it` job (about
    40–120 Actions minutes a month), or keep OAuth to unit tests plus the manual runbook?
12. **Reference IdP for the docs.** Document Pocket ID as the reference and Keycloak as the
    second? Or stay IdP-neutral with a capability checklist (§3's columns) and no worked example?

---

## Sources

All fetched or read on **2026-09-26**.

**MCP specification**
- **M1** Authorization, 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- **M2** Authorization server discovery: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
- **M3** Client registration: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
- **M4** Security considerations: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- **M5** Changelog, 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/changelog. It covers SEP-2468 (RFC 9207 `iss`), PR #2858 (DCR deprecated in favour of CIMD), SEP-837 (`application_type`) and SEP-2352 (credentials keyed by issuer). CIMD and DCR priority are unchanged from 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- **M6** Security best practices: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices

**RFCs and drafts**
- **R1** RFC 9728: https://www.rfc-editor.org/rfc/rfc9728.html
- **R2** RFC 8707: https://www.rfc-editor.org/rfc/rfc8707.html
- **R3** RFC 9207: https://www.rfc-editor.org/rfc/rfc9207.html
- **R4** RFC 7591: https://www.rfc-editor.org/rfc/rfc7591.html
- **R5** RFC 9068: https://www.rfc-editor.org/rfc/rfc9068.html
- **R6** RFC 8725: https://www.rfc-editor.org/rfc/rfc8725.html
- **R7** RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.html
- **R8** Client ID Metadata Document, draft-ietf-oauth-client-id-metadata-document-02 (6 July 2026; MCP 2026-07-28 still cites -00): https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/. It covers the https client ID with a path, `client_id` equal to the URL, exact redirect match, no client secrets, no fetches to special-use IPs, and a 5 KB read limit. Every obligation falls on the client or the AS.

**Anthropic documentation**
- **A1** Authentication for connectors: https://claude.com/docs/connectors/building/authentication
- **A2** Build an MCP server for Claude: https://claude.com/docs/connectors/building/index.md
- **A3** Troubleshooting: https://claude.com/docs/connectors/building/troubleshooting.md
- **A4** Lazy authentication: https://claude.com/docs/connectors/building/lazy-authentication.md
- **A5** Add a connector that isn't in the directory: https://claude.com/docs/connectors/custom/remote-mcp
- **A6** Getting started with custom connectors: https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp
- **A7** Use connectors: https://support.claude.com/en/articles/11176164-use-connectors-to-extend-claude-s-capabilities
- **A8** IP addresses: https://platform.claude.com/docs/en/api/ip-addresses
- **A9** Getting started with connectors: https://claude.com/docs/connectors/getting-started.md
- **A10** MCP for connectors (annotations): https://claude.com/docs/connectors/building/mcp.md

**`anthropics/claude-ai-mcp` issues** (state and reactions read from the GitHub API)
- **G1** #228: https://github.com/anthropics/claude-ai-mcp/issues/228
- **G2** #341: https://github.com/anthropics/claude-ai-mcp/issues/341
- **G3** #632: https://github.com/anthropics/claude-ai-mcp/issues/632
- **G4** #1047: https://github.com/anthropics/claude-ai-mcp/issues/1047
- **G5** #153 "Elicitation Support": https://github.com/anthropics/claude-ai-mcp/issues/153
- **G6** #125: https://github.com/anthropics/claude-ai-mcp/issues/125

**Pocket ID**
- **P1** CIMD guide: https://pocket-id.org/docs/guides/client-id-metadata-documents
- **P2** APIs guide: https://pocket-id.org/docs/guides/apis
- **P3** Environment variables: https://pocket-id.org/docs/configuration/environment-variables
- **P4** Source at v2.16.0, `well_known_controller.go` and `oidc_service.go` (RFC 8414, RFC 9207, PKCE, `none`), and commit 7c55bdf (RFC 9068 tokens; issuer added to `aud` with identity scopes): https://github.com/pocket-id/pocket-id
- **P5** Releases (2.16.0 on 2026-09-20; CIMD in 2.13.0, PR #1526): https://github.com/pocket-id/pocket-id/releases
- **P6** Refresh rotation advisory GHSA-w6p7-2fxx-4f44: https://github.com/pocket-id/pocket-id/security/advisories/GHSA-w6p7-2fxx-4f44
- **P7** Client authentication (`sub` = `client-<id>` for `client_credentials`): https://pocket-id.org/docs/guides/oidc-client-authentication
- **P8** Client secret API, PR #1619: https://github.com/pocket-id/pocket-id/pull/1619

**Keycloak**
- **K1** Keycloak as an MCP authorization server: https://www.keycloak.org/securing-apps/mcp-authz-server
- **K2** Client registration: https://www.keycloak.org/securing-apps/client-registration
- **K3** RFC 8707 issue #14355: https://github.com/keycloak/keycloak/issues/14355
- **K4** Source at 26.7.4, `Profile.java` (CIMD and RESOURCE_INDICATORS experimental); PR #46763; issue #51413: https://github.com/keycloak/keycloak
- **K5** Source at 26.7.4, `OIDCWellKnownProvider.java` (RFC 9207 flag): https://github.com/keycloak/keycloak
- **K6** RFC 8414 path-insert, issues #40923 and #45271: https://github.com/keycloak/keycloak/issues/40923
- **K7** Containers (`--import-realm`; 26.7.4 current): https://www.keycloak.org/server/containers and https://www.keycloak.org/downloads

**Authelia**
- **L1** OpenID Connect provider roadmap: https://www.authelia.com/roadmap/active/openid-connect-1.0-provider/
- **L2** Client configuration: https://www.authelia.com/configuration/identity-providers/openid-connect/clients/
- **L3** `resource` regression and fix: https://github.com/authelia/authelia/issues/12970 (PR #12973, issue #13113)

**Authentik**
- **N1** Dynamic client registration: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/dynamic-client-registration/
- **N2** Source at `version/2026.8.3`: `providers/oauth2/views/provider.py` and `id_token.py`, https://github.com/goauthentik/authentik
- **N3** OAuth2 provider docs: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/ ; release notes: https://docs.goauthentik.io/releases/2026.8/
- **N4** RFC 8414 path-insert, PR #12383: https://github.com/goauthentik/authentik/pull/12383

**Zitadel**
- **Z1** Dynamic client registration: https://zitadel.com/docs/guides/integrate/dynamic-client-registration
- **Z2** Claims: https://zitadel.com/docs/apis/openidoauth/claims ; scopes: https://zitadel.com/docs/apis/openidoauth/scopes
- **Z3** PR #12313 (CIMD follow-up; no RFC 8414): https://github.com/zitadel/zitadel/pull/12313 ; licence: https://github.com/zitadel/zitadel
- **Z4** Token introspection: https://zitadel.com/docs/guides/integrate/token-introspection ; DCR apps opaque by default (third party): https://github.com/re-invertion/resourcePortal/pull/161

**Auth0, Okta and Entra**
- **H1** Auth0 Auth for MCP: https://auth0.com/ai/docs/mcp/auth-for-mcp ; GA post: https://auth0.com/blog/auth0-auth-for-mcp-servers-generally-available/
- **H2** Auth0 CIMD: https://auth0.com/docs/get-started/auth0-overview/create-applications/register-applications-with-cimd
- **H3** Auth0 DCR: https://auth0.com/ai/docs/mcp/guides/registering-your-mcp-client-application/dynamic-client-registration
- **H4** Auth0 Resource Parameter Compatibility Profile: https://auth0.com/ai/docs/mcp/guides/resource-param-compatibility-profile
- **H5** Auth0 refresh token rotation: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
- **H6** Okta CIMD: https://developer.okta.com/docs/guides/app-cimd-registration/main/
- **H7** Entra: https://learn.microsoft.com/entra/agent-id/secure-mcp-server-with-entra-id

**CI**
- **C1** GitHub Actions billing: https://docs.github.com/en/billing/concepts/product-billing/github-actions
- **C2** Runner pricing: https://docs.github.com/en/billing/reference/actions-runner-pricing
- **C3** Service containers: https://docs.github.com/actions/using-containerized-services/about-service-containers
- **C4** Service-container `command`/`entrypoint` (2026-04-02): https://github.blog/changelog/2026-04-02-github-actions-early-april-2026-updates/
- **C5** navikt/mock-oauth2-server 6.0.3: https://github.com/navikt/mock-oauth2-server
- **C6** Keycloak image manifest on quay.io: https://quay.io/repository/keycloak/keycloak

**Installed source**
- **S1** `mcp` 2.2.0: `server/lowlevel/server.py` (`streamable_http_app(auth=, token_verifier=)`), `server/auth/middleware/bearer_auth.py`, `server/auth/routes.py`, `server/auth/provider.py`, `server/auth/settings.py`, `shared/auth.py`, `client/auth/extensions/client_credentials.py`, `client/auth/oauth2.py` (client-side CIMD and RFC 9207)
- **S2** PyJWT 2.15.0 (MIT): `jwks_client.py`, `api_jws.py`, `api_jwt.py`, `algorithms.py`; `uv.lock` (`pyjwt` 2.15.0 and `cryptography` 50.0.1, required by `mcp` as `pyjwt[crypto]>=2.10.1`)
