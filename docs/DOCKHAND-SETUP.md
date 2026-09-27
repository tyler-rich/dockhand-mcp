# Preparing DockHand for dockhand-mcp

dockhand-mcp talks to DockHand with one `dh_` API token and nothing else: no username, no password,
no session cookie (plan D-002). This page sets up the DockHand side, then shows how to check it.
Do every step in order; none is optional.

Throughout, `dockhand.example.test` stands for your DockHand URL.

## 1. Create a dedicated DockHand user

1. Sign in to DockHand as an administrator.
2. In DockHand's user administration, create a new local user used only by this server, for
   example `mcp-operator` (one user per dockhand-mcp instance; name it after the profile it will
   run).
3. Give it a long random password and store that password in your password manager. Nothing in
   dockhand-mcp ever uses it; you need it only to sign in and create the token in step 3.
4. Don't reuse your own account: the audit trail in DockHand should show which actions came
   through the MCP server, and revoking this user must not lock you out.

## 2. Give the user only what its profile needs

### Enterprise: one custom role per profile

On DockHand Enterprise the token inherits its user's role, so the role is a second, independent
limit behind the MCP profile. Create one custom role per profile you run and assign it to that
profile's user.

The tables below are built from each tool's declared endpoints (`dockhand-mcp tools` prints them)
and the **Perm** column of [`docs/api/ENDPOINT-MAP.md`](api/ENDPOINT-MAP.md), which records the
permission strings DockHand's API document (v1.0.49) states for each endpoint. Many endpoints state
none. Those rows say **verify**: the name given is the closest permission the document uses
elsewhere, so check in DockHand's role editor which permission gates that area, and confirm with
`dockhand-mcp check` (step 5) and a first call of the tools involved.

Each profile includes everything in the profiles above it.

**`read-only`** (51 read tools)

| Permission | Needed for | Source |
|---|---|---|
| `environments:view` | Every environment-scoped tool resolves `environment_id` | spec |
| `stacks:view` | Stack list, compose, `.env`, variables, deploy runs, git stacks, stack validation | spec |
| `volumes:view`, `volumes:inspect` | `dockhand_list_volumes`, `dockhand_get_volume` | spec |
| `activity:view` | `dockhand_get_activity`, `dockhand_get_activity_stats` | spec |
| `git:view` | Git repository tools | spec |
| `registries:view` | Registry browsing tools | spec |
| `settings:view` | `dockhand_get_settings` (scanner part), database health | spec |
| `stacks:remove` | `dockhand_preview_stack_delete` only (DockHand gates the preview with the delete permission). If you'd rather not grant it, leave it out and set `DOCKHAND_MCP_DISABLE_TOOLS=dockhand_preview_stack_delete`. | spec |
| `containers:view`, `stacks:view` | `dockhand_list_tags` (the tag catalogue and container tags need `containers:view`, stack tags `stacks:view`) | spec |
| `containers:view`, `containers:logs` | Container list, inspect, logs, stats, top, sizes, generated compose, pending updates | **verify** |
| images (view) | Image list, history, scan results, vulnerabilities | **verify** |
| networks (view) | Network list and inspect | **verify** |
| `schedules:view` | Schedules and their executions | **verify** |
| system/host (view) | Host info, system info, disk usage, job status | **verify** |
| audit (view) | `dockhand_get_audit_log` (the audit log is Enterprise-only) | **verify** |

**`operator`** (adds 36 operator tools)

| Permission | Needed for | Source |
|---|---|---|
| `stacks:view` | **Stack-env read, required.** Every stack-scoped write (start, stop, restart, deploy, compose and `.env` writes, create) first reads the stack's `.env` and variables (`GET …/env/raw`, `GET …/env`) so it can mask their values in the output, and refuses to run if it can't ([SECURITY §2, Output redaction](SECURITY.md#output-redaction)). | spec |
| `stacks:start`, `stacks:restart` | Stack deploy (also git stack deploy), stack restart | spec |
| `stacks:edit` | Compose and `.env` writes, git stack sync | spec |
| `stacks:create` | `dockhand_create_stack` | spec |
| `secrets:view` | Stated for `POST /api/stacks` and `PUT …/compose` (create stack, update compose), which can bind secret providers. Whether DockHand demands it when no provider is used: **verify**. | spec |
| `volumes:create` | Create and clone volumes | spec |
| `git:edit` | Git repository sync and deploy | spec |
| `settings:edit` | Toggling a *system* schedule only. Leave it out if you don't need that. | spec |
| `containers:edit` | Container start, stop, restart, pause, unpause, rename, batch operations, image updates, auto-update settings | **verify** |
| stacks (stop) | Stack start and stop (`POST …/start`, `…/stop` state no permission) | **verify** |
| images (edit) | Image pull, tag, scan, scan-all | **verify** |
| networks (edit) | Create network, connect, disconnect | **verify** |
| schedules (edit) | Run or toggle a schedule | **verify** |
| environments (test), jobs (cancel) | `dockhand_test_environment`, `dockhand_cancel_job` | **verify** |

**`admin`** (adds 10 destructive tools)

| Permission | Needed for | Source |
|---|---|---|
| `stacks:view` | **Stack-env read, required**, as for `operator`: `dockhand_down_stack` and `dockhand_delete_stack` read the stack's env after approval and refuse to run if they can't. | spec |
| `stacks:remove` | Delete preview for down and delete | spec |
| `volumes:remove` | `dockhand_remove_volume` | spec |
| `activity:delete` | `dockhand_clear_activity_log` | spec |
| `environments:edit` | `dockhand_run_image_prune_now` (`PUT …/image-prune`) | spec |
| stacks (delete/down) | Stack down and delete (`POST …/down`, `DELETE /api/stacks/{name}`) | **verify** (`stacks:delete` exists in the spec) |
| containers (remove) | Remove container, batch remove | **verify** |
| images (remove), networks (remove) | Remove image, remove network | **verify** |
| prune | `dockhand_prune` (every scope) | **verify** |

Don't grant anything else: in particular nothing for users, roles, tokens, secret providers,
registries (edit), environments (create/delete), backups, notifications or license. No tool calls
those endpoints (they are the `excluded` tier, [SECURITY §4](SECURITY.md#4-the-excluded-tier--why-each-family-is-out-forever)).

### Free edition: the token is full-admin

> [!WARNING]
> **On DockHand Free, every API token can do everything its user can, and every user is a full
> administrator. There are no roles to narrow it.** The MCP profile
> (`DOCKHAND_MCP_PROFILE`) is then the only control over what this server can do, and a leaked
> token is a full DockHand admin credential.
>
> So on Free: run `operator` (or `read-only`) by default and `admin` only while you need it; keep
> the token in a file or an encrypted store, never in YAML or a shell history; give it the
> shortest expiry you can live with; and revoke it the moment you suspect it leaked.

## 3. Create an expiring API token as that user

1. Sign out, then sign in to DockHand as the dedicated user from step 1.
2. In that user's profile, create an API token. Give it a name that says where it is used (for
   example `dockhand-mcp operator`) and **an expiry date**: 90 days is a reasonable default. Put a
   reminder in your calendar a week before it.
3. Copy the token (it starts with `dh_`). DockHand shows it once.
4. Sign out.

Token creation needs an interactive session on purpose (D-002): nothing, including this server,
can mint tokens through the API.

## 4. Store the token as a secret

Pick one:

- **Compose or `docker run`** ([`deploy/docker-compose.yml`](../deploy/docker-compose.yml),
  [`deploy/docker-run.md`](../deploy/docker-run.md)): write it to `secrets/dockhand_token` next to
  the compose file, with your editor (not `echo`, which leaves it in shell history), then:

  ```sh
  chmod 700 secrets && chmod 600 secrets/dockhand_token
  sudo chown 10001:10001 secrets/dockhand_token   # the container's user must be able to read it
  ```

  The server reads it through `DOCKHAND_TOKEN_FILE`. A mode wider than `0600` logs a warning.
- **DockHand's or Portainer's stack editor** ([`deploy/dockhand-stack.yml`](../deploy/dockhand-stack.yml)):
  set `DOCKHAND_TOKEN` in the stack's environment editor, marked secret where the tool offers
  that. The value then lives in the tool's encrypted store and reaches the container at runtime;
  it never appears in the YAML.

Never put the token itself in a compose file, an `.env` file you commit, a Dockerfile, or a
command line.

## 5. Verify with `dockhand-mcp check`

Run `check` with exactly the configuration the server will use, for example with Compose:

```sh
docker compose run --rm dockhand-mcp check
```

It validates the configuration, talks to DockHand with the token, prints a JSON report on stdout
(secrets masked: `dh_… (set)`), prints warnings on stderr, and exits `1` if there is any problem.

| Output | Meaning | What you want |
|---|---|---|
| `version`, `profile`, `tools` | This server's version, the effective profile and the exact tools it registers | The profile you intended; `tools` is what clients will see |
| `dockhand.health` | `GET /api/health`: `ok`, `unreachable`, or `error (<status>)` | `ok` |
| `dockhand.database_healthy` | DockHand's database health check | `true` |
| `dockhand.auth_enabled` | DockHand's public auth setting | `true`. `false` also prints a warning: the MCP profile is then the only control |
| `dockhand.token` | `accepted` (DockHand answered `GET /api/environments` with the token), `rejected` (401), or `not configured` | `accepted` |
| `dockhand.edition` | `free` or `enterprise`, from the status of an edition probe (the body is never read); `unknown` if it can't tell | What you run; on `free`, re-read the warning in step 2 |
| `dockhand.environments` | How many environments the token's user can see | At least 1 |
| `dockhand.permissions` | One representative list per area (`containers`, `stacks`, `images`, `volumes`, `networks`) in the default or first environment: `ok`, `denied (403)`, `error (…)` | `ok` everywhere. A `denied` on Enterprise means the role from step 2 is missing that area |
| `problems` | Anything that stops the server working, one line each. Exit code `1` | `[]` |
| `config` | The effective configuration by variable name, secrets masked | What you meant to set |
| stderr `warning: Environments X (…) and Y (…) appear to share one Docker daemon…` | Two environments list the same containers: see [Environments and Docker daemons](#environments-and-docker-daemons) | No such line |
| stderr `warning: cannot compare environment …` | That environment's containers couldn't be listed, so the shared-daemon check skipped it | No such line |
| stderr `warning: the token's user cannot list environments (HTTP 403)` | The token works but the role lacks `environments:view` | No such line |

`check` is best effort about permissions: it probes one list per area, not every endpoint a tool
uses. After `check` is clean, call one tool of each kind you rely on.

## Environments and Docker daemons

> [!WARNING]
> **Never point two DockHand environments at the same Docker daemon** (the same socket, or the
> same remote host twice).

DockHand scopes stacks by environment, but Docker has no idea environments exist: a compose
project on a daemon belongs to whoever runs `docker compose` against it. With two environments on
one daemon:

- each environment's stack list also shows the other's running stacks, as untracked compose
  projects;
- a stack created with the same name through the other environment is accepted by DockHand, and
  becomes a tracked duplicate in both;
- `compose down` or a delete through either environment acts on the shared project, and removes
  the other environment's containers.

dockhand-mcp guards against the parts it can see: every write to an existing stack refuses a stack
that is not tracked in the requested environment, and `dockhand_create_stack` refuses a name that
is already a compose project on that daemon (in the stack list or in any container's labels). It
cannot undo a duplicate created outside it. `dockhand-mcp check` prints a warning when two
environments share container ids. If you see it, fix the DockHand side: one environment per daemon.

## Keeping secrets out of compose files

`dockhand_get_stack_compose` returns a stack's compose file exactly as stored, so that a client
can edit it and write it back. Whatever is written literally in a compose file therefore reaches
the model, and the conversation it is part of.

- Keep secrets in the stack's environment (`.env`, masked by DockHand's stack variables) or in
  DockHand's secret variables, and reference them in the compose file as `${NAME}`.
- Never write a literal password, token or key as a value under `environment:`. The compose
  guardrails flag such values (key names only) as a warning, but they do not remove them.
- Stack tools mask the stack's own variable values in operation output, and DockHand masks its
  secret variables as `***`. Neither applies to a value typed straight into the compose file.

## Startup and runtime failures

Startup is **fail-closed**: on any of the problems below, `serve` exits with status 1 and one line
on stderr, and the container stops. With `restart: unless-stopped` Docker retries, so a DockHand
that was still starting is picked up on a later attempt; for everything else, read the line:

```sh
docker logs --tail 5 dockhand-mcp
```

| Last log line | Cause | Fix |
|---|---|---|
| `dockhand-mcp: DOCKHAND_TOKEN is not set and the server cannot confirm DockHand authentication is disabled: DockHand is unreachable (ConnectError)` | No DockHand token, and DockHand couldn't be reached to confirm its authentication is off | Configure the token (step 4). If you really run DockHand without authentication, make sure it is reachable at `DOCKHAND_URL` from the container |
| `dockhand-mcp: DOCKHAND_TOKEN is required: DockHand reports authentication enabled` | No DockHand token, and DockHand has authentication on | Configure the token (step 4) |
| `dockhand-mcp: configuration error: DOCKHAND_TOKEN_FILE: cannot read /run/secrets/dockhand_token` | The file is missing, or UID 10001 can't read it | Check the path and `sudo chown 10001:10001` the file (step 4) |
| `dockhand-mcp: configuration error: DOCKHAND_URL is required` | `DOCKHAND_URL` unset | Set it |
| `dockhand-mcp: configuration error: DOCKHAND_URL uses http:// but DOCKHAND_ALLOW_HTTP is not true` | Plain HTTP to DockHand | Use `https://`, or set `DOCKHAND_ALLOW_HTTP=true` on a trusted network only |
| `dockhand-mcp: configuration error: DOCKHAND_MCP_AUTH_MODE=bearer requires DOCKHAND_MCP_TOKEN or DOCKHAND_MCP_TOKEN_FILE` | No MCP bearer token | Generate one (README quick start) |
| `dockhand-mcp: configuration error: DOCKHAND_MCP_TOKEN must be at least 43 characters (32 bytes base64url)` | MCP token too short | `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
| `dockhand-mcp: configuration error: DOCKHAND_MCP_AUTH_MODE=none over HTTP requires DOCKHAND_MCP_BIND=127.0.0.1 or ::1` | Unauthenticated HTTP on a non-loopback address | Use `bearer` |
| `dockhand-mcp: DOCKHAND_MCP_TRANSPORT=stdio requires DOCKHAND_MCP_AUTH_MODE=none` | stdio has no header to carry a bearer token | Set `DOCKHAND_MCP_AUTH_MODE=none` for stdio ([CLIENTS](CLIENTS.md)) |
| `…: … has mode 0644, wider than 0600; restrict it to the server's user` (warning, not fatal) | Token file readable by others | `chmod 600` |

Every other configuration error is one line that starts `dockhand-mcp: configuration error:` and
names the variable.

A **wrong, expired or revoked** token does not stop startup: the server starts, and every tool
call returns `dockhand_http_error` with `dockhand_status: 401` and the message
`DockHand rejected the API token (HTTP 401): it is missing, wrong, expired or revoked. Create a new dh_ token for the MCP server's DockHand user.`
`dockhand-mcp check` shows `"token": "rejected"`. Fix: step 3, then restart.

**Stack writes that refuse to run.** Stack lifecycle tools (start, stop, restart, deploy, down,
delete) and the compose and `.env` writes read the stack's variables before they write, so that
their values can be masked in the output. If that read fails, nothing is started and the call
returns DockHand's error. On Enterprise that is typically `dockhand_http_error` with
`dockhand_status: 403` and the message
`DockHand denied the request (HTTP 403): the token's user lacks the permission for this operation or has no access to this environment, or the feature needs DockHand Enterprise.`
Fix: grant `stacks:view` for that environment to the role of the server's user (step 2). The same
403 on any other tool means the role lacks that tool's permission; see the tables in step 2.

A stack write that answers `not_found` for a stack you can see in the list: the stack is not
tracked in that environment (see [Environments and Docker daemons](#environments-and-docker-daemons)).

## Rotate and revoke

**Rotate the DockHand token** before it expires, and whenever someone who could read it leaves:

1. Sign in as the dedicated user and create a new expiring token (step 3).
2. Replace the secret (step 4): overwrite `secrets/dockhand_token`, or update `DOCKHAND_TOKEN` in
   the stack editor.
3. Restart the container (`docker compose up -d --force-recreate`, or redeploy the stack): the
   token is read at startup.
4. Run `dockhand-mcp check` and confirm `"token": "accepted"`.
5. Revoke the old token in DockHand.

**Revoke immediately** if a token may have leaked (it appeared in a log, a chat, a commit, a
screenshot): revoke it in DockHand first, then rotate. On Free, treat a leaked token as a leaked
admin password and also review DockHand's activity for the period.

**Rotate the MCP bearer token** the same way: generate a new one, update every client, restart
the server, then delete the old value. If you set `DOCKHAND_MCP_CHALLENGE_KEY`, rotate it on the
same schedule; with the default (unset) it is random per process and changes on every restart.

To retire an instance, revoke its token and delete its DockHand user.
