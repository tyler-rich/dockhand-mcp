# SPDX-License-Identifier: Apache-2.0
"""`dockhand_get_auto_update_settings`: per-container automatic image update settings."""

from typing import Any

from pydantic import Field

from dockhand_mcp.guardrails.names import DOCKER_NAME
from dockhand_mcp.tools._common import EnvScoped, env_tool
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register


class AutoUpdateInput(EnvScoped):
    container_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=DOCKER_NAME.pattern,
        description="One container's setting (defaults when none is stored); all enabled when "
        "omitted.",
    )


async def get_auto_update_settings(ctx: ToolContext, args: AutoUpdateInput, env: int) -> Any:
    if args.container_name is None:
        body = await ctx.client.get_json("/api/auto-update", params={"env": env})
        return {"settings": body if isinstance(body, dict) else {}}
    body = await ctx.client.get_json(
        "/api/auto-update/{containerName}",
        path_params={"containerName": args.container_name},
        params={"env": env},
    )
    return {"container_name": args.container_name, "setting": body}


register(
    ToolSpec(
        name="dockhand_get_auto_update_settings",
        title="Get auto-update settings",
        description=(
            "Get automatic image-update settings: every enabled container's, keyed by container "
            "name, or one container's schedule and vulnerability criteria."
        ),
        input_model=AutoUpdateInput,
        handler=env_tool(get_auto_update_settings),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "container_name"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/auto-update"), ("GET", "/api/auto-update/{containerName}")),
)
