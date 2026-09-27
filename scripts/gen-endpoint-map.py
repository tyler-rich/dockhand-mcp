#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate docs/api/ENDPOINT-MAP.md from the DockHand OpenAPI document.

The OpenAPI document (GET /api/docs) is NOT committed to this repository (docs/api/*.json is
git-ignored); the maintainer attaches it to the Claude Code sessions that need it, and it is saved
locally as docs/api/dockhand-openapi-1.0.49.json for the duration of the work.

Usage:
    python3 scripts/gen-endpoint-map.py docs/api/dockhand-openapi-1.0.49.json > docs/api/ENDPOINT-MAP.md
    python3 scripts/gen-endpoint-map.py --env-required docs/api/dockhand-openapi-1.0.49.json \
        > src/dockhand_mcp/client/env_required.py

`--env-required` writes the operations whose environment query parameter the spec marks required,
as the Python module the DockHand client refuses them from when the parameter is missing (#5).
The spec is not in the image, so the list is committed.

DockHand's own endpoint summaries and descriptions are not copied into the map: they are text
from DockHand's source, which is licensed BUSL-1.1, not Apache-2.0 (ARCHIVE §14, public launch).

The tier assignment below is a SECURITY DECISION for dockhand-mcp. Any change to the
tier() rules must be recorded in docs/ARCHIVE.md §14 and reflected in docs/TOOLS.md.
"""

import json
import re
import sys
from collections import Counter, defaultdict

EXCLUDED_TAGS = {
    "auth",
    "users",
    "roles",
    "license",
    "legal",
    "profile",
    "preferences",
    "dashboard",
    "container-icons",
    "icons",
    "debug",
    "metrics",
    "self-update",
    "hawser",
    "secret-providers",
    "templates",
    "config-sets",
    "docs",
    "changelog",
    "dependencies",
    "labels",
}


def tier(tag: str, m: str, p: str) -> str:
    if tag in EXCLUDED_TAGS:
        if tag == "dashboard" and p == "/api/dashboard/stats" and m == "get":
            return "read"
        return "excluded"
    if p == "/api/git/stacks/{id}/deploy-stream" and m == "post":
        return "operator"  # SSE-consumed to a final result by dockhand_deploy_git_stack; not a raw feed
    if "stream" in p or "/events" in p or p == "/api/logs/merged":
        return "excluded"  # raw SSE feeds are not tools
    if "/icon" in p:
        return "excluded"  # icons are UI cosmetics
    if tag == "health":
        return "read"
    if tag == "git":
        if (
            "credential" in p
            or "webhook" in p
            or (p.endswith("/env-files") and m == "post")
            or "preview-env" in p
        ):
            return "excluded"  # returns parsed env values from a repo checkout
        if m == "get":
            return "read"
        if any(p.endswith(s) for s in ("/deploy", "/deploy-stream", "/sync", "/test")) or any(
            k in p for k in ("branches", "preview-env", "env-files")
        ):
            return "operator"
        if m == "delete":
            return "destructive"
        return "admin"
    if tag == "registry":
        return "excluded" if m == "delete" else "read"
    if tag == "registries":
        return "read" if m == "get" else "excluded"
    if tag == "notifications":
        if m == "get":
            return "read"
        return "operator" if "test" in p else "excluded"
    if tag == "containers":
        if "/exec" in p or "/files" in p or "/shells" in p:
            return "excluded"
        if m == "get":
            return "read"
        if m == "delete" and p == "/api/containers/{id}":
            return "destructive"
        return "operator"
    if tag == "stacks":
        if m == "get" or (m == "post" and p.endswith("/validate")):
            return "read"  # validate endpoints are stateless linters (verified per-endpoint in S2)
        if m == "delete" or p.endswith("/down") or "relocate" in p:
            return "destructive"
        return "operator"
    if tag in ("tags", "container-tags", "stack-tags"):
        # 1.0.49. Reads are read. Assigning tags to a container or stack is operator, as the
        # `stacks` rule already makes PUT /api/stacks/{name}/tags. The global catalog is DockHand's
        # own configuration: admin, like settings writes.
        if m == "get":
            return "read"
        return "admin" if tag == "tags" else "operator"
    if tag in ("images", "volumes", "networks"):
        if any(k in p for k in ("/export", "/load", "/push", "/browse")):
            return "excluded"
        if m == "get":
            return "read"
        if m == "delete":
            return "destructive"
        return "operator"
    if tag == "batch":
        return "split"  # tier depends on body.operation — see legend and docs/TOOLS.md
    if tag == "prune":
        return "destructive"
    if tag == "environments":
        if "icon" in p or "notifications" in p:
            return "excluded"
        if m == "get":
            return "read"
        if p.endswith("/test") or "detect-socket" in p:
            return "operator"
        if "image-prune" in p and m == "put":
            return "destructive"
        return "admin"
    if tag == "jobs":
        return "read" if m == "get" else "operator"
    if tag in ("activity", "audit"):
        return "read" if m == "get" else "destructive"
    if tag == "schedules":
        if "settings" in p:
            return "excluded"
        if m == "get":
            return "read"
        return "destructive" if m == "delete" else "operator"
    if tag == "auto-update":
        return "read" if m == "get" else "operator"
    if tag == "vulnerabilities":
        return "read" if m == "get" else "operator"
    if tag in ("host", "system"):
        return "excluded" if "/files" in p else "read"
    if tag == "settings":
        if any(k in p for k in ("theme", "navigation", "general")):
            return "read" if (m == "get" and "general" in p) else "excluded"
        return "read" if m == "get" else "admin"
    if tag == "backup":
        if "rotate-key" in p or "dump" in p or p == "/api/backup/destinations/{id}":
            return "excluded"  # single-destination GET can return decrypted cloud credentials
        if m == "get":
            return "read"
        if (
            "destinations" in p
            and m in ("post", "put", "delete")
            and not any(p.endswith(s) for s in ("/test", "/init", "/task", "/verify"))
        ):
            return "admin"
        if "restore" in p and "preview" not in p and "stop" not in p:
            return "destructive"
        if "snapshots" in p and (m == "delete" or "batch-delete" in p):
            return "destructive"
        if p.endswith("/task") or m == "delete":
            return "destructive"
        return "operator"
    return "review"


ENV_PARAMS = ("env", "envId")


def env_required_operations(d: dict) -> dict[tuple[str, str], str]:
    """(METHOD, path template) → the environment query parameter the spec marks required."""
    found = {}
    for p, ops in d["paths"].items():
        for m, o in ops.items():
            if m not in ("get", "post", "put", "patch", "delete"):
                continue
            for pp in o.get("parameters", []):
                if pp.get("in") == "query" and pp.get("required") and pp["name"] in ENV_PARAMS:
                    found[(m.upper(), p)] = pp["name"]
    return found


def env_required_module(d: dict) -> str:
    rows = sorted(env_required_operations(d).items(), key=lambda item: (item[0][1], item[0][0]))
    out = [
        "# SPDX-License-Identifier: Apache-2.0",
        f'"""Operations whose environment query parameter DockHand requires (API v{d["info"]["version"]}).',
        "",
        "Generated from the `/api/docs` OpenAPI document by `scripts/gen-endpoint-map.py --env-required`;",
        "do not edit. `client/dockhand.py` refuses a request to any of these, before sending it, when the",
        "parameter is missing or empty (#5).",
        '"""',
        "",
        "from collections.abc import Mapping",
        "from types import MappingProxyType",
        "from typing import Final",
        "",
        "# (METHOD, path template) -> the name of the required query parameter.",
        "ENV_REQUIRED: Final[Mapping[tuple[str, str], str]] = MappingProxyType(",
        "    {",
    ]
    out += [f'        ("{m}", "{p}"): "{name}",' for (m, p), name in rows]
    out += ["    }", ")", ""]
    return "\n".join(out)


def main(path: str, env_required: bool = False) -> None:
    d = json.load(open(path))
    if env_required:
        sys.stdout.write(env_required_module(d))
        return
    rows = []
    for p, ops in d["paths"].items():
        for m, o in ops.items():
            if m not in ("get", "post", "put", "patch", "delete"):
                continue
            tag = o.get("tags", ["-"])[0]
            pub = o.get("security") == []
            t = tier(tag, m, p)
            q = [pp["name"] for pp in o.get("parameters", []) if pp.get("in") == "query"]
            rb = o.get("requestBody")
            body = (
                list(
                    rb.get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                    .get("properties", {})
                    .keys()
                )
                if rb
                else []
            )
            s = json.dumps(o)
            a = []
            if "jobId" in s or "job-polled" in s.lower():
                a.append("job")
            if "event-stream" in s or "Server-Sent" in s:
                a.append("sse")
            if "Accept" in s:
                a.append("accept-json")
            perm = sorted(
                set(
                    re.findall(
                        r"\b([a-z-]+:(?:view|start|stop|restart|edit|create|remove|exec|logs|manage|inspect|delete))\b",
                        s,
                    )
                )
            )
            rows.append((tag, m.upper(), p, t, pub, q, body, a, perm))

    c = Counter(r[3] for r in rows)
    out = []
    out.append(f"# DockHand API endpoint map (v{d['info']['version']})\n")
    out.append(
        "Generated from the `/api/docs` OpenAPI 3.0.3 document by `scripts/gen-endpoint-map.py` "
        "(the JSON itself is not committed; see `docs/api/README.md`). "
        "Regenerate when the spec is refreshed; diff the result and record tier changes in `docs/ARCHIVE.md` §14.\n"
    )
    out.append(
        "**Totals:** %d paths, %d operations. Tier counts: %s\n"
        % (len(d["paths"]), len(rows), ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    )
    out.append(
        """
## Tier legend (this is the security decision, not documentation)

| Tier | Meaning | Exposed by profile |
|---|---|---|
| `read` | Read-only. No state change on DockHand or Docker. | `read-only`, `operator`, `admin` |
| `operator` | Changes runtime state but is reversible (start/stop/restart/deploy/compose+env edits/pull/scan/update-check). | `operator`, `admin` |
| `destructive` | Deletes data or resources, or is hard to undo (remove, prune, down, delete-with-volumes, restore, relocate). Requires `confirm=true` at the MCP layer. | `admin` only |
| `admin` | Changes DockHand's own configuration (environments, git repos/stacks, backup destinations, scanner settings). **Out of scope for v1**; listed so exclusion is a conscious decision. | *(not exposed in v1)* |
| `split` | One endpoint, tier decided by a body field. Only `POST /api/batch`: `operation` ∈ start/stop/restart/pause/unpause → **operator** (`dockhand_batch_containers`); `remove` → **destructive** (`dockhand_batch_remove_containers`); anything else → not exposed. | per operation |
| `excluded` | Never exposed by this MCP server in any profile: auth-provider config, API/hawser tokens, users/roles/MFA, license, in-container exec/file access, DockHand host filesystem, UI preferences, icons, raw SSE feeds, self-update, secret providers, git/registry credentials, image export/load/push, volume file browsing, webhooks. See `docs/SECURITY.md` §4. | never |

Columns: **Async** = `job` (returns `{jobId}`; poll `GET /api/jobs/{id}`), `sse` (streams Server-Sent Events), `accept-json` (send `Accept: application/json` to receive the final result synchronously instead of a job id / SSE). **Perm** = DockHand RBAC permission strings found in the spec text for that operation (Enterprise edition only; the Free edition grants every authenticated user everything).
"""
    )
    bytag = defaultdict(list)
    for r in rows:
        bytag[r[0]].append(r)
    for tag in sorted(bytag):
        out.append(f"\n## `{tag}` ({len(bytag[tag])} ops)\n")
        out.append("| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |")
        out.append("|---|---|---|---|---|---|---|---|")
        for tg, m, p, t, pub, q, body, a, perm in bytag[tag]:
            more = "…" if len(body) > 10 else ""
            out.append(
                f"| `{m}` | `{p}` | **{t}** | {'yes' if pub else ''} | {', '.join(q)} | "
                f"{', '.join(body[:10])}{more} | {', '.join(a)} | {', '.join(perm)} |"
            )
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    as_module = "--env-required" in args
    args = [a for a in args if a != "--env-required"]
    main(args[0] if args else "docs/api/dockhand-openapi-1.0.49.json", env_required=as_module)
