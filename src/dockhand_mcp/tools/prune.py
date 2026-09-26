# SPDX-License-Identifier: Apache-2.0
"""`dockhand_prune` (destructive): prune stopped containers, unused images, networks or volumes,
or all of them, through `POST /api/prune/{scope}`.

Runs only through run_destructive (D-006). DockHand has no prune dry-run, so the preview is our
estimate from the list endpoints: stopped containers, dangling (or, with `dangling_only=false`,
unused) images, networks with no containers other than Docker's predefined ones, volumes no
container uses. Docker decides what it actually removes: for volumes it may remove only
anonymous ones. `scope=all` has no preview at all, so it also needs `scope_all_acknowledged`,
in the approval form or, on the confirm path, as an argument.

Per the spec, the images prune streams SSE (handled, like every SSE tool, when DockHand answers
with a job id instead); the other four answer synchronously and run as detached operations.
"""

from typing import Any, Final, Literal

from pydantic import Field, model_validator

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.tools._common import (
    JOB_STATUS,
    EnvDestructiveInputs,
    SseRequest,
    add_warnings,
    destructive_tool,
    dockhand_success,
    list_body,
    names_text,
    run_async_pattern,
    scoped,
    write_budget,
)
from dockhand_mcp.tools.base import ToolContext
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

PruneScope = Literal["containers", "images", "networks", "volumes", "all"]
SCOPES: Final[tuple[PruneScope, ...]] = ("containers", "images", "networks", "volumes", "all")
STOPPED_STATES: Final = frozenset({"exited", "created", "dead"})
PREDEFINED_NETWORKS: Final = frozenset({"bridge", "host", "none"})
UNTAGGED: Final = "<none>:<none>"
MAX_ESTIMATE_ITEMS: Final = 100
ESTIMATE_NOTE: Final = (
    "An estimate from DockHand's lists; Docker decides what the prune actually removes."
)
VOLUME_NOTE: Final = " Docker may prune only anonymous volumes."


class PruneInput(EnvDestructiveInputs):
    scope: PruneScope = Field(
        description="What to prune: containers (stopped), images, networks, volumes, or all."
    )
    dangling_only: bool = Field(
        default=True,
        description="With scope images: only dangling images; false prunes every image no "
        "container uses.",
    )
    scope_all_acknowledged: bool = Field(
        default=False,
        description="With scope all, on the confirm path: acknowledges that every unused "
        "container, image, network and volume is pruned.",
    )

    @model_validator(mode="after")
    def _dangling_only_for_images(self) -> PruneInput:
        if self.scope != "images" and not self.dangling_only:
            raise ValueError("dangling_only applies only to scope images")
        return self


def _get(item: dict[str, Any], *keys: str) -> Any:
    return next((item[k] for k in keys if k in item), None)


def _dicts(body: Any) -> list[dict[str, Any]]:
    return [i for i in list_body(body) if isinstance(i, dict)]


async def _containers(ctx: ToolContext, env: int) -> list[dict[str, Any]]:
    return _dicts(await ctx.client.get_json("/api/containers", params={"env": env, "all": True}))


async def _candidates(ctx: ToolContext, args: PruneInput, env: int) -> list[str]:
    """What the prune would likely remove, by name (IDs for untagged images)."""
    if args.scope == "containers":
        return [
            str(c.get("name"))
            for c in await _containers(ctx, env)
            if c.get("state") in STOPPED_STATES
        ]
    if args.scope == "images":
        images = _dicts(await ctx.client.get_json("/api/images", params={"env": env}))
        in_use = {c.get("imageId") for c in await _containers(ctx, env)}
        out = []
        for image in images:
            tags = [t for t in _get(image, "repoTags", "RepoTags") or [] if t != UNTAGGED]
            image_id = str(_get(image, "id", "Id"))
            dangling = not tags
            if image_id in in_use or (args.dangling_only and not dangling):
                continue
            out.append(tags[0] if tags else image_id.removeprefix("sha256:")[:12])
        return out
    if args.scope == "networks":
        networks = _dicts(await ctx.client.get_json("/api/networks", params={"env": env}))
        return [
            str(_get(n, "name", "Name"))
            for n in networks
            if _get(n, "name", "Name") not in PREDEFINED_NETWORKS
            and isinstance(members := _get(n, "containers", "Containers"), dict | list)
            and not members
        ]
    volumes = _dicts(await ctx.client.get_json("/api/volumes", params={"env": env}))
    return [
        str(_get(v, "name", "Name"))
        for v in volumes
        if isinstance(v.get("usedBy"), list) and not v["usedBy"]
    ]


async def prune_preview(ctx: ToolContext, args: PruneInput, env: int | None) -> Preview:
    env = scoped(env)
    if args.scope == "all":
        return Preview(
            summary=f"Prune everything unused in environment {env}: stopped containers, unused "
            "networks, images and volumes, as DockHand's prune-all does. There is no preview "
            "of what that removes.",
            data={"scope": "all", "estimate": None, "note": "No preview is available."},
            counts={},
            target={"scope": "all"},
            requires_scope_ack=True,
        )
    names = await _candidates(ctx, args, env)
    what = {
        "containers": "stopped containers",
        "images": "dangling images" if args.dangling_only else "images no container uses",
        "networks": "unused networks",
        "volumes": "unused volumes",
    }[args.scope]
    note = ESTIMATE_NOTE + (VOLUME_NOTE if args.scope == "volumes" else "")
    return Preview(
        summary=f"Prune {what} in environment {env}. Estimated {len(names)}: "
        f"{names_text(names)}. {note}",
        data={
            "scope": args.scope,
            "dangling_only": args.dangling_only if args.scope == "images" else None,
            "estimate": {"count": len(names), "items": names[:MAX_ESTIMATE_ITEMS]},
            "note": note,
        },
        counts={args.scope: len(names)},
        target={"scope": args.scope},
    )


async def prune(
    ctx: ToolContext, args: PruneInput, env: int | None, preview: Preview, approved: Approved
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    scope = str(preview.target["scope"])
    meta = {"action": f"prune_{scope}", "environment_id": env}
    if scope == "images":
        request = SseRequest(
            "POST", "/api/prune/images", params={"env": env, "dangling": args.dangling_only}
        )
        envelope = await run_async_pattern(
            "sse", ctx, wait=args.wait, budget_s=budget, meta=meta, sse=request
        )
        return add_warnings(envelope, warnings)

    async def work() -> Envelope:
        answer = await ctx.client.post_json(
            f"/api/prune/{scope}",
            params={"env": env},
            read_timeout=float(ctx.settings.max_timeout) + 5.0,
        )
        return dockhand_success(answer, {"scope": scope}, "prune")

    envelope = await run_async_pattern(
        "detached", ctx, wait=args.wait, budget_s=budget, meta=meta, work=work
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_prune",
        title="Prune",
        description=(
            "Prune stopped containers, unused images, networks or volumes, or all of them, "
            "after a human approves. Returns DockHand's prune report."
        ),
        input_model=PruneInput,
        preview=prune_preview,
        execute=prune,
        audit_args=("environment_id", "scope", "dangling_only", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (
        ENVIRONMENTS,
        ("GET", "/api/containers"),
        ("GET", "/api/images"),
        ("GET", "/api/networks"),
        ("GET", "/api/volumes"),
        *(("POST", f"/api/prune/{scope}") for scope in SCOPES),
        JOB_STATUS,
    ),
)
