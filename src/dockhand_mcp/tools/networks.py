# SPDX-License-Identifier: Apache-2.0
"""Network tools: list and inspect; create, connect and disconnect (operator); remove
(destructive). Networks are named by ID or exact name, resolved through the list."""

from typing import Annotated, Any

from pydantic import Field, StringConstraints

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.guardrails.names import DOCKER_NAME, resolve_container, resolve_network
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
    fail,
    list_body,
    names_text,
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

LIST = ("GET", "/api/networks")


class ListNetworksInput(EnvScoped):
    pass


async def list_networks(ctx: ToolContext, args: ListNetworksInput, env: int) -> Any:
    items = list_body(await ctx.client.get_json("/api/networks", params={"env": env}))
    return page(items, max(len(items), 1), 0)


register(
    ToolSpec(
        name="dockhand_list_networks",
        title="List networks",
        description=(
            "List Docker networks in an environment. Returns each network's id, name, driver, "
            "scope, IPAM configuration and connected containers."
        ),
        input_model=ListNetworksInput,
        handler=env_tool(list_networks),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST),
)


class GetNetworkInput(EnvScoped):
    network: str = Field(
        min_length=1,
        max_length=255,
        description="Network ID (12-64 hex characters) or exact network name.",
    )


async def get_network(ctx: ToolContext, args: GetNetworkInput, env: int) -> Any:
    ref = await resolve_network(ctx.client, env, args.network)
    return await ctx.client.get_json(
        "/api/networks/{id}/inspect", path_params={"id": ref.id}, params={"env": env}
    )


register(
    ToolSpec(
        name="dockhand_get_network",
        title="Get network",
        description=(
            "Get a network's Docker inspect payload: driver, IPAM configuration and connected "
            "containers."
        ),
        input_model=GetNetworkInput,
        handler=env_tool(get_network),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "network"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/networks/{id}/inspect")),
)

# --- operator tier ----------------------------------------------------------------------------
# `ingress`, `ipam`, `options` and `enableIPv6` are not exposed (docs/TOOLS.md).

LabelKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")]
LabelValue = Annotated[str, StringConstraints(max_length=1024, pattern=r"^[^\x00-\x1f\x7f]*$")]
DRIVER = r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$"


class CreateNetworkInput(EnvWriteInputs):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=DOCKER_NAME.pattern,
        description="Name of the new network.",
    )
    driver: str | None = Field(
        default=None, max_length=128, pattern=DRIVER, description="Network driver (default bridge)."
    )
    internal: bool | None = Field(default=None, description="No external connectivity.")
    attachable: bool | None = Field(
        default=None, description="Allow standalone containers to attach."
    )
    labels: dict[LabelKey, LabelValue] | None = Field(
        default=None, max_length=50, description="Labels for the network."
    )


async def create_network(ctx: ToolContext, args: CreateNetworkInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    body: dict[str, Any] = {"name": args.name}
    for key, value in (
        ("driver", args.driver),
        ("internal", args.internal),
        ("attachable", args.attachable),
        ("labels", args.labels or None),
    ):
        if value is not None:
            body[key] = value

    async def work() -> Any:
        return await ctx.client.post_json("/api/networks", params={"env": env}, json=body)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "create_network", "network": args.name, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_create_network",
        title="Create network",
        description="Create a Docker network in an environment. Returns the new network's id.",
        input_model=CreateNetworkInput,
        handler=env_tool(create_network),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "name", "driver", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/networks")),
)


class ConnectInput(EnvWriteInputs):
    network: str = Field(min_length=1, max_length=255, description="Network ID or exact name.")
    ref: str = Field(
        min_length=1, max_length=255, description="Container ID or exact container name."
    )


class DisconnectInput(ConnectInput):
    force: bool = Field(default=False, description="Force the disconnect.")


def _membership(action: str) -> Any:
    async def body(ctx: ToolContext, args: ConnectInput, env: int) -> Envelope:
        network = await resolve_network(ctx.client, env, args.network)
        container = await resolve_container(ctx.client, env, args.ref)
        budget, warnings = write_budget(ctx, args)
        payload: dict[str, Any] = {"containerId": container.id, "containerName": container.name}
        if isinstance(args, DisconnectInput):
            payload["force"] = args.force

        async def work() -> dict[str, Any]:
            answer = await ctx.client.post_json(
                f"/api/networks/{{id}}/{action}",
                path_params={"id": network.id},
                params={"env": env},
                json=payload,
            )
            return {
                "network": {"id": network.id, "name": network.name},
                "container": {"id": container.id, "name": container.name},
                "result": answer,
            }

        envelope = await run_async_pattern(
            "detached",
            ctx,
            wait=args.wait,
            budget_s=budget,
            meta={
                "action": action,
                "network": network.name,
                "container": container.name,
                "environment_id": env,
            },
            work=work,
        )
        return add_warnings(envelope, warnings)

    return body


for _action, _model, _title, _description in (
    ("connect", ConnectInput, "Connect container to network", "Connect a container to a network."),
    (
        "disconnect",
        DisconnectInput,
        "Disconnect container from network",
        "Disconnect a container from a network.",
    ),
):
    register(
        ToolSpec(
            name=f"dockhand_{_action}_container_{'to' if _action == 'connect' else 'from'}_network",
            title=_title,
            description=_description,
            input_model=_model,
            handler=env_tool(_membership(_action)),
            annotations=OPERATOR_ANNOTATIONS,
            audit_args=("environment_id", "network", "ref", "wait"),
        ),
        Tier.OPERATOR,
        (
            ENVIRONMENTS,
            LIST,
            ("GET", "/api/containers"),
            ("POST", f"/api/networks/{{id}}/{_action}"),
        ),
    )


# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.


class RemoveNetworkInput(EnvDestructiveInputs):
    network: str = Field(min_length=1, max_length=255, description="Network ID or exact name.")


def _attached(inspect: dict[str, Any]) -> list[str]:
    members = inspect.get("Containers", inspect.get("containers"))
    if isinstance(members, dict):
        return [
            str(v.get("Name") or v.get("name") or k) if isinstance(v, dict) else str(k)
            for k, v in members.items()
        ]
    if isinstance(members, list):
        return [str(m.get("name", m)) if isinstance(m, dict) else str(m) for m in members]
    return []


async def remove_network_preview(
    ctx: ToolContext, args: RemoveNetworkInput, env: int | None
) -> Preview:
    env = scoped(env)
    ref = await resolve_network(ctx.client, env, args.network)
    inspect = as_dict(
        await ctx.client.get_json(
            "/api/networks/{id}/inspect", path_params={"id": ref.id}, params={"env": env}
        )
    )
    attached = _attached(inspect)
    if attached:
        raise fail(
            "guardrail_blocked",
            f"network {ref.name} has {len(attached)} attached container(s): "
            f"{names_text(attached)}. Disconnect them first. Nothing was done.",
        )
    driver = inspect.get("Driver", inspect.get("driver"))
    return Preview(
        summary=f"Remove network {ref.name} ({ref.id[:12]}, driver {driver}) in environment "
        f"{env}. No containers are attached.",
        data={
            "network": {
                "id": ref.id,
                "name": ref.name,
                "driver": driver,
                "scope": inspect.get("Scope", inspect.get("scope")),
                "internal": inspect.get("Internal", inspect.get("internal")),
            },
            "attached_containers": [],
            "would_remove": True,
        },
        counts={"networks": 1},
        target={"id": ref.id, "name": ref.name},
    )


async def remove_network(
    ctx: ToolContext,
    args: RemoveNetworkInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    network = {"id": str(preview.target["id"]), "name": str(preview.target["name"])}

    async def work() -> Envelope:
        answer = await ctx.client.delete_json(
            "/api/networks/{id}", path_params={"id": network["id"]}, params={"env": env}
        )
        return dockhand_success(answer, {"network": network, "removed": True}, "network removal")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "remove_network", "network": network["name"], "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_remove_network",
        title="Remove network",
        description=(
            "Remove a network after a human approves; refused while containers are attached. "
            "Returns the removed network's id and name."
        ),
        input_model=RemoveNetworkInput,
        preview=remove_network_preview,
        execute=remove_network,
        audit_args=("environment_id", "network", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (ENVIRONMENTS, LIST, ("GET", "/api/networks/{id}/inspect"), ("DELETE", "/api/networks/{id}")),
)
