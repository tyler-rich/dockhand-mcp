# Deploying dockhand-mcp

| File | Use it for |
|---|---|
| [`docker-compose.yml`](docker-compose.yml) | The hardened reference: Docker Compose with the tokens as Compose secrets. Start here ([README quick start](../README.md#quick-start-docker-compose)). |
| [`docker-run.md`](docker-run.md) | The same hardening as plain `docker run` flags. |
| [`dockhand-stack.yml`](dockhand-stack.yml) | DockHand's or Portainer's stack editor: no `secrets:` block; the tokens come from the tool's encrypted environment store. |
| [`.env.example`](.env.example) | Every variable, with its default. |

All three run the image as UID 10001 with a read-only root filesystem, no capabilities,
`no-new-privileges`, resource limits and a health check, and publish the port on `127.0.0.1` only.
Keep those settings. For anything beyond this host, put a TLS reverse proxy in front
([`docs/CLIENTS.md`](../docs/CLIENTS.md#reverse-proxy-and-tls)).

Run profile `operator` by default and `admin` only while you need destructive tools; with clients
that speak MCP 2026-07-28, also set `DOCKHAND_MCP_CONFIRM_MODE=elicitation`
([`docs/CLIENTS.md`](../docs/CLIENTS.md#confirm-mode-and-approvals)).

Pin the image by digest: copy the `image:` line from the release notes of the version you deploy,
and verify it with the release's `cosign verify` line first.

Before the first start, prepare DockHand ([`docs/DOCKHAND-SETUP.md`](../docs/DOCKHAND-SETUP.md))
and run `check`. Startup is fail-closed; the troubleshooting table is in
[DOCKHAND-SETUP](../docs/DOCKHAND-SETUP.md#startup-and-runtime-failures).
