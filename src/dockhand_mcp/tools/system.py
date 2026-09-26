# SPDX-License-Identifier: Apache-2.0
"""Host, system and dashboard tools."""

from typing import Any, Final

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.guardrails.names import MAX_ENV_ID
from dockhand_mcp.tools._common import (
    EnvScoped,
    ToolInput,
    env_tool,
    gather_sections,
    section_warnings,
)
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

# --- host -------------------------------------------------------------------------------------


class HostInfoInput(EnvScoped):
    pass


async def get_host_info(ctx: ToolContext, args: HostInfoInput, env: int) -> Any:
    return await ctx.client.get_json("/api/host", params={"env": env})


register(
    ToolSpec(
        name="dockhand_get_host_info",
        title="Get host info",
        description=(
            "Get the Docker host behind an environment: hostname, platform, CPU, memory, uptime, "
            "Docker version and container and image counts."
        ),
        input_model=HostInfoInput,
        handler=env_tool(get_host_info),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/host")),
)

# --- system -----------------------------------------------------------------------------------

# Docker `system df`: the per-object arrays can run to thousands of entries; the usage summaries
# carry the totals.
DISK_ARRAYS: Final = ("Images", "Containers", "Volumes", "BuildCache")


def summarise_disk(body: Any) -> Any:
    usage = body.get("diskUsage") if isinstance(body, dict) else None
    if not isinstance(usage, dict):
        return usage
    out: dict[str, Any] = {}
    for key, value in usage.items():
        if key in DISK_ARRAYS and isinstance(value, list):
            out[f"{key}Count"] = len(value)
        elif isinstance(value, dict) and "Items" in value:
            out[key] = {k: v for k, v in value.items() if k != "Items"}
        else:
            out[key] = value
    return out


class SystemInfoInput(EnvScoped):
    include_disk: bool = Field(
        default=True, description="Also return Docker disk usage (can be slow on large hosts)."
    )


async def get_system_info(ctx: ToolContext, args: SystemInfoInput, env: int) -> Envelope:
    calls = {"system": ctx.client.get_json("/api/system", params={"env": env})}
    if args.include_disk:
        calls["disk"] = ctx.client.get_json("/api/system/disk", params={"env": env})
    results, errors = await gather_sections(calls)
    if "system" in errors:
        main = errors["system"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    data: dict[str, Any] = dict(results["system"]) if isinstance(results["system"], dict) else {}
    if "disk" in results:
        data["disk"] = summarise_disk(results["disk"])
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_system_info",
        title="Get system info",
        description=(
            "Get Docker daemon, host, DockHand runtime and database information and object "
            "counts for an environment, optionally with Docker disk usage totals."
        ),
        input_model=SystemInfoInput,
        handler=env_tool(get_system_info),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/system"), ("GET", "/api/system/disk")),
)

# --- dashboard --------------------------------------------------------------------------------


class DashboardStatsInput(ToolInput):
    environment_id: int | None = Field(
        default=None,
        ge=1,
        le=MAX_ENV_ID,
        description="Restrict to one environment; all environments when omitted.",
    )


async def get_dashboard_stats(ctx: ToolContext, args: DashboardStatsInput) -> Envelope:
    params = {"env": args.environment_id} if args.environment_id is not None else None
    body = await ctx.client.get_json("/api/dashboard/stats", params=params)
    # One object for a single environment, an array otherwise.
    items = body if isinstance(body, list) else [body] if isinstance(body, dict) else []
    return ok({"items": items, "count": len(items)}, environment_id=args.environment_id)


register(
    ToolSpec(
        name="dockhand_get_dashboard_stats",
        title="Get dashboard stats",
        description=(
            "Get per-environment dashboard statistics: container states, images, volumes, "
            "networks, stacks, resource metrics and event counts."
        ),
        input_model=DashboardStatsInput,
        handler=get_dashboard_stats,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (("GET", "/api/dashboard/stats"),),
)
