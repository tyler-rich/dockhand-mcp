# dockhand-mcp with plain `docker run`

The same hardening as [`docker-compose.yml`](docker-compose.yml), flag for flag. Create the two
token files first (see [the README's quick start](../README.md#quick-start-docker-compose)), in a
directory only you can read:

```sh
mkdir -p secrets && chmod 700 secrets
# secrets/dockhand_token: the dh_ token from docs/DOCKHAND-SETUP.md, written with your editor
python -c "import secrets;print(secrets.token_urlsafe(48))" > secrets/mcp_token
chmod 600 secrets/*
```

The container runs as UID 10001 and the files are bind-mounted as they are, so give them to that
UID: `sudo chown 10001:10001 secrets/*`. (Mode `0600` is what the server expects; a wider mode
logs a warning at startup.)

```sh
docker run -d --name dockhand-mcp \
  --restart unless-stopped \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 256m --cpus 0.5 \
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/secrets/dockhand_token:/run/secrets/dockhand_token:ro" \
  -v "$PWD/secrets/mcp_token:/run/secrets/mcp_token:ro" \
  -e DOCKHAND_URL=https://dockhand.example.test \
  -e DOCKHAND_TOKEN_FILE=/run/secrets/dockhand_token \
  -e DOCKHAND_MCP_TOKEN_FILE=/run/secrets/mcp_token \
  -e DOCKHAND_MCP_PROFILE=operator \
  -e DOCKHAND_MCP_BIND=0.0.0.0 \
  -e DOCKHAND_MCP_ALLOWED_HOSTS=localhost,127.0.0.1,mcp.example.test \
  ghcr.io/tyler-rich/dockhand-mcp:0.1.0@sha256:<digest from the release notes>
```

| Flag | Why |
|---|---|
| `--user 10001:10001` | Non-root; the image's own user. |
| `--read-only`, `--tmpfs /tmp:…noexec…` | No writable filesystem except a small, non-executable `/tmp`. |
| `--cap-drop ALL`, `--security-opt no-new-privileges:true` | No Linux capabilities, no privilege gain through setuid binaries. |
| `--pids-limit`, `--memory`, `--cpus` | Bounds a runaway process. |
| `-p 127.0.0.1:8080:8080` | Reachable from this host only. Put a TLS reverse proxy in front for anything else ([`docs/CLIENTS.md`](../docs/CLIENTS.md#reverse-proxy-and-tls)). |
| `-v …:ro` token files, `*_FILE` variables | Tokens never appear in `docker inspect` or the process environment. |
| `DOCKHAND_MCP_BIND=0.0.0.0` | Inside the container only; the `-p` mapping decides who can connect. |
| `--restart unless-stopped` | Startup is fail-closed; this retries until DockHand is reachable. |

With clients that speak MCP 2026-07-28 (a current Claude Code over HTTP), add
`-e DOCKHAND_MCP_CONFIRM_MODE=elicitation` so destructive tools always need the human approval
form ([`docs/CLIENTS.md`](../docs/CLIENTS.md#confirm-mode-and-approvals)).

The image has a `HEALTHCHECK` (`GET /healthz` through Python), so `docker ps` shows `healthy`.
If the container keeps restarting, `docker logs dockhand-mcp` ends with a one-line reason: see
[`docs/DOCKHAND-SETUP.md`](../docs/DOCKHAND-SETUP.md#startup-and-runtime-failures).

Check the configuration and DockHand access with the same flags, replacing the last two lines:

```sh
docker run --rm … ghcr.io/tyler-rich/dockhand-mcp:0.1.0@sha256:<digest> check
```

Never add `-v /var/run/docker.sock:…`, `--privileged`, `--network host` or `--cap-add`: the server
needs none of them. It talks to DockHand over HTTPS and nothing else.
