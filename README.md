# dockhand-mcp

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
[![Latest release](https://img.shields.io/github/v/release/tyler-rich/dockhand-mcp)](../../releases/latest)

A security-first [Model Context Protocol](https://modelcontextprotocol.io) server for
[DockHand](https://dockhand.pro). It lets MCP clients (Claude Code, Claude Desktop, the MCP
Inspector, any client that can send a header) inspect and operate the Docker environments
DockHand manages, through DockHand's REST API only, and never through the Docker socket.

**Why:** an AI client that can manage containers is useful, and dangerous if it can do
everything DockHand can. dockhand-mcp exposes a curated, profile-gated subset of DockHand's API:
the whole server is designed around what a prompt-injected model must *not* be able to do.

**Status: early (v0.1.x).** Built and tested against DockHand's API 1.0.49. Before 1.0, tool
names, arguments, results and configuration can change in a minor release; each release's notes
list what changed, so pin the image by digest and read them before upgrading. Tools whose
DockHand response shape is not documented are marked `experimental` in
[`docs/TOOLS.md`](docs/TOOLS.md). OAuth, which Claude.ai custom connectors need, is not
available yet ([CLIENTS §4](docs/CLIENTS.md#4-claudeai)).

## Security posture

- **Profiles.** `read-only` (the server's default), `operator` (plus reversible writes: start,
  stop, deploy, compose and `.env` edits verified by reading them back) and `admin` (plus
  destructive tools). Tools above the profile are never registered, so no client can list or call
  them. The profile is set by the server's configuration, never by the client.
- **Excluded tier.** Whole API families are out in every profile, permanently: credentials and
  tokens, users and roles, in-container exec and file access, the DockHand host filesystem, secret
  providers, image export, self-update, webhooks ([SECURITY §4](docs/SECURITY.md)).
- **Human-approved destructive actions.** Every remove, prune, stack down and delete needs a human
  approval: an elicitation form bound to the exact call where the client supports it, otherwise
  an explicit `confirm` (weaker: see [Confirm mode and approvals](docs/CLIENTS.md#confirm-mode-and-approvals)).
  Destructive calls are also rate-limited per client.
- **Output redaction.** DockHand's answers pass one redactor before they reach the model:
  credential-shaped keys, tokens and URL credentials, and each stack's own variable values in its
  operation output ([SECURITY §2](docs/SECURITY.md#output-redaction)).
- **Guardrails on compose writes.** Privileged containers, host-namespace modes, dangerous
  capabilities and bind mounts of `/`, the Docker socket, `/etc` and similar are refused before
  anything is written.
- **No socket, no shell, no host mounts.** The server is a plain HTTP client of DockHand. It runs
  as a non-root, read-only, capability-free container.
- **Authenticated before anything.** Bearer-token auth on every MCP request, including tool
  listing, with rate limits and DNS-rebinding protection.
- **Scanned and signed image.** Each release image is scanned with OSV-Scanner for both platforms
  before it is pushed, signed keylessly with cosign, and published with a CycloneDX SBOM; the
  published image is rescanned weekly.
- **Fail-closed startup.** An invalid or insecure configuration, or a missing DockHand token when
  DockHand requires one, stops the server with a one-line reason instead of starting it.

Design and threat model: [`docs/SECURITY.md`](docs/SECURITY.md). Locked decisions:
[`plan.md`](plan.md).

## Quick start (Docker Compose)

You need a DockHand API token first: [`docs/DOCKHAND-SETUP.md`](docs/DOCKHAND-SETUP.md) walks
through the dedicated user, the Enterprise role or the Free-edition warning, and the token.

1. Copy [`deploy/docker-compose.yml`](deploy/docker-compose.yml) into a new directory. Its
   `image:` line is a placeholder, `ghcr.io/tyler-rich/dockhand-mcp:X.Y.Z@sha256:<digest>`:
   replace it with the exact pinned `image:` line from the latest GitHub
   [release notes](../../releases/latest), and set `DOCKHAND_URL` and `DOCKHAND_MCP_ALLOWED_HOSTS`.
2. Create the two token files. **The DockHand token file is required**: without it the server
   won't start (unless DockHand runs with authentication off).
   ```sh
   mkdir -p secrets && chmod 700 secrets
   $EDITOR secrets/dockhand_token        # paste the dh_ token
   python -c "import secrets;print(secrets.token_urlsafe(48))" > secrets/mcp_token
   chmod 600 secrets/* && sudo chown 10001:10001 secrets/*   # the container runs as UID 10001
   ```
3. Check, then start:
   ```sh
   docker compose run --rm dockhand-mcp check
   docker compose up -d
   docker compose ps          # dockhand-mcp should become "healthy"
   ```
4. Connect a client with the token in `secrets/mcp_token`: [`docs/CLIENTS.md`](docs/CLIENTS.md).

The reference compose runs profile **`operator`**: switch to `admin` only while you need
destructive tools. If the container keeps restarting, its last log line says why:
[troubleshooting](docs/DOCKHAND-SETUP.md#startup-and-runtime-failures). Other ways to run it:
[`deploy/docker-run.md`](deploy/docker-run.md) (plain Docker),
[`deploy/dockhand-stack.yml`](deploy/dockhand-stack.yml) (DockHand or Portainer stack editors),
stdio for Claude Desktop ([CLIENTS §3](docs/CLIENTS.md#3-claude-desktop-chat)).

Verify the image signature before you deploy it; each release's notes carry the exact
`cosign verify` line.

> [!WARNING]
> **Keep secrets out of compose files.** `dockhand_get_stack_compose` returns compose files as
> they are, so that they can be edited; a literal password in a compose file reaches the model.
> Keep secrets in the stack's environment or DockHand's secret variables and reference them as
> `${NAME}`. [More](docs/DOCKHAND-SETUP.md#keeping-secrets-out-of-compose-files).

> [!WARNING]
> **Never point two DockHand environments at one Docker daemon.** Each would list the other's
> stacks, duplicates become possible, and `compose down` through one removes the other's
> containers. The server guards what it can, and `dockhand-mcp check` warns when it detects a
> shared daemon. [More](docs/DOCKHAND-SETUP.md#environments-and-docker-daemons).

## Configuration

Every setting is an environment variable; `*_FILE` reads the value from a file, for example a
Docker secret. [`deploy/.env.example`](deploy/.env.example) lists them all with their defaults.

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

## Tools

97 tools in three tiers, each registered only in the profiles that include its tier:

| Tier | Profiles | Tools | Examples |
|---|---|---|---|
| read | `read-only`, `operator`, `admin` | 51 | environments, containers (list, inspect, logs, stats), stacks (list, compose, `.env`, deploy runs), images, volumes, networks, jobs, host and system, activity, audit (Enterprise), schedules, updates, vulnerabilities, registries, git, tags |
| operator | `operator`, `admin` | 36 | container and stack lifecycle, compose and `.env` edits with read-back verification, create stack with guardrails, image pull, tag and scan, volumes, networks, schedules, git sync and deploy, batch start/stop/restart |
| destructive | `admin` | 10 | remove container, image, volume or network; stack down and delete; prune; batch remove; run image prune now; clear activity log |

The full catalogue, with each tool's DockHand endpoints and permissions:
[`docs/TOOLS.md`](docs/TOOLS.md). `dockhand-mcp tools` prints the catalogue of the running version
(names, descriptions, schema hashes) so you can diff it between upgrades.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Some third-party dependencies carry their own licenses; each release's SBOM lists them.

## Contributing

Contributions are welcome under the same license: per Section 5 of the Apache License 2.0, any
contribution you intentionally submit is licensed under its terms, with no additional terms or
conditions. How to propose a change: [`CONTRIBUTING.md`](CONTRIBUTING.md). Report security issues
privately: [`SECURITY.md`](SECURITY.md).

---

Not affiliated with or endorsed by DockHand. DockHand is a trademark of its respective owner.
