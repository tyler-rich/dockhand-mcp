# SPDX-License-Identifier: Apache-2.0
"""Volume tools: list and inspect; create and clone (operator); remove (destructive). Volumes
are addressed by name (validated, not resolved)."""

from typing import Annotated, Any, Final

from pydantic import Field, StringConstraints

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.guardrails.names import DOCKER_NAME
from dockhand_mcp.tools._common import (
    PAGE_SCHEMA,
    EnvDestructiveInputs,
    EnvScoped,
    EnvWriteInputs,
    add_warnings,
    as_dict,
    destructive_tool,
    dockhand_success,
    env_tool,
    limit_field,
    list_body,
    names_text,
    offset_field,
    page,
    run_async_pattern,
    scoped,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register


class ListVolumesInput(EnvScoped):
    limit: int = limit_field(50)
    offset: int = offset_field()


async def list_volumes(ctx: ToolContext, args: ListVolumesInput, env: int) -> Any:
    body = await ctx.client.get_json("/api/volumes", params={"env": env})
    return page(list_body(body), args.limit, args.offset)


register(
    ToolSpec(
        name="dockhand_list_volumes",
        title="List volumes",
        description=(
            "List Docker volumes in an environment. Returns each volume's name, driver, "
            "mountpoint, scope, labels and the containers using it."
        ),
        input_model=ListVolumesInput,
        handler=env_tool(list_volumes),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/volumes")),
)


class GetVolumeInput(EnvScoped):
    volume: str = Field(
        min_length=1, max_length=255, pattern=DOCKER_NAME.pattern, description="Volume name."
    )


async def get_volume(ctx: ToolContext, args: GetVolumeInput, env: int) -> Any:
    return await ctx.client.get_json(
        "/api/volumes/{name}/inspect", path_params={"name": args.volume}, params={"env": env}
    )


register(
    ToolSpec(
        name="dockhand_get_volume",
        title="Get volume",
        description=(
            "Get a volume's Docker inspect payload: driver, mountpoint, scope, labels and options."
        ),
        input_model=GetVolumeInput,
        handler=env_tool(get_volume),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "volume"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/volumes/{name}/inspect")),
)

# --- operator tier ----------------------------------------------------------------------------
# `driverOpts` is never sent: `type=none, o=bind, device=/…` would make a volume a bind mount of
# any host path, which is what the compose guardrails exist to stop.

MAX_LABELS: Final = 50
LabelKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")]
LabelValue = Annotated[str, StringConstraints(max_length=1024, pattern=r"^[^\x00-\x1f\x7f]*$")]
DRIVER: Final = r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$"


def volume_name_field(description: str) -> Any:
    return Field(min_length=1, max_length=255, pattern=DOCKER_NAME.pattern, description=description)


class CreateVolumeInput(EnvWriteInputs):
    name: str = volume_name_field("Name of the new volume.")
    driver: str | None = Field(
        default=None, max_length=128, pattern=DRIVER, description="Volume driver (default local)."
    )
    labels: dict[LabelKey, LabelValue] | None = Field(
        default=None, max_length=MAX_LABELS, description="Labels for the volume."
    )


async def create_volume(ctx: ToolContext, args: CreateVolumeInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    body: dict[str, Any] = {"name": args.name}
    if args.driver is not None:
        body["driver"] = args.driver
    if args.labels:
        body["labels"] = args.labels

    async def work() -> Any:
        return await ctx.client.post_json("/api/volumes", params={"env": env}, json=body)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "create_volume", "volume": args.name, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_create_volume",
        title="Create volume",
        description="Create a named Docker volume in an environment.",
        input_model=CreateVolumeInput,
        handler=env_tool(create_volume),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "name", "driver", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/volumes")),
)


class CloneVolumeInput(EnvWriteInputs):
    source: str = volume_name_field("Volume to copy.")
    new_name: str = volume_name_field("Name of the new volume.")


async def clone_volume(ctx: ToolContext, args: CloneVolumeInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def work() -> Any:
        return await ctx.client.post_json(
            "/api/volumes/{name}/clone",
            path_params={"name": args.source},
            params={"env": env},
            json={"name": args.new_name},
            read_timeout=float(ctx.settings.max_timeout) + 5.0,
        )

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "clone_volume", "volume": args.source, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_clone_volume",
        title="Clone volume",
        description="Copy a volume's data into a new named volume with the same driver and labels.",
        input_model=CloneVolumeInput,
        handler=env_tool(clone_volume),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "source", "new_name", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/volumes/{name}/clone")),
)


# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.


def _pick(item: dict[str, Any], *keys: str) -> Any:
    return next((item[k] for k in keys if k in item), None)


class RemoveVolumeInput(EnvDestructiveInputs):
    volume: str = Field(
        min_length=1, max_length=255, pattern=DOCKER_NAME.pattern, description="Volume name."
    )
    force: bool = Field(default=False, description="Force the removal.")


async def remove_volume_preview(
    ctx: ToolContext, args: RemoveVolumeInput, env: int | None
) -> Preview:
    env = scoped(env)
    inspect = as_dict(
        await ctx.client.get_json(
            "/api/volumes/{name}/inspect", path_params={"name": args.volume}, params={"env": env}
        )
    )
    listed = list_body(await ctx.client.get_json("/api/volumes", params={"env": env}))
    item = next(
        (i for i in listed if isinstance(i, dict) and _pick(i, "name", "Name") == args.volume), {}
    )
    used_by = [str(u) for u in (item.get("usedBy") or []) if isinstance(u, str)]
    driver = _pick(inspect, "Driver", "driver")
    summary = (
        f"Remove volume {args.volume} (driver {driver}) in environment {env}"
        f"{' (forced)' if args.force else ''}; its data is deleted. Used by {len(used_by)} "
        f"container(s): {names_text(used_by)}."
    )
    return Preview(
        summary=summary,
        data={
            "volume": {
                "name": args.volume,
                "driver": driver,
                "mountpoint": _pick(inspect, "Mountpoint", "mountpoint"),
                "scope": _pick(inspect, "Scope", "scope"),
                "created": _pick(inspect, "CreatedAt", "created"),
                "labels": _pick(inspect, "Labels", "labels"),
            },
            "used_by": used_by,
            "force": args.force,
            "would_remove": True,
        },
        counts={"volumes": 1, "used_by": len(used_by)},
        target={"volume": args.volume},
    )


async def remove_volume(
    ctx: ToolContext,
    args: RemoveVolumeInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    volume = str(preview.target["volume"])

    async def work() -> Envelope:
        answer = await ctx.client.delete_json(
            "/api/volumes/{name}",
            path_params={"name": volume},
            params={"env": env, "force": args.force},
        )
        return dockhand_success(answer, {"volume": volume, "removed": True}, "volume removal")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "remove_volume", "volume": volume, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_remove_volume",
        title="Remove volume",
        description=(
            "Remove a volume and its data after a human approves. Returns the removed volume's "
            "name."
        ),
        input_model=RemoveVolumeInput,
        preview=remove_volume_preview,
        execute=remove_volume,
        audit_args=("environment_id", "volume", "force", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (
        ENVIRONMENTS,
        ("GET", "/api/volumes"),
        ("GET", "/api/volumes/{name}/inspect"),
        ("DELETE", "/api/volumes/{name}"),
    ),
)
