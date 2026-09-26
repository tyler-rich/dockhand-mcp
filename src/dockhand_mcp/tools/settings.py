# SPDX-License-Identifier: Apache-2.0
"""`dockhand_get_settings`: DockHand's general, scanner and semver settings, read-only.

Scanner settings are read with `settingsOnly=true`: without it DockHand also checks scanner
availability and versions through Docker, which is slow and does more than read a setting.
"""

from typing import Any

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.guardrails.names import MAX_ENV_ID
from dockhand_mcp.tools._common import ToolInput, gather_sections, section_warnings
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import Tier, register


class SettingsInput(ToolInput):
    environment_id: int | None = Field(
        default=None,
        ge=1,
        le=MAX_ENV_ID,
        description="Environment for scanner settings; global defaults when omitted.",
    )


async def get_settings(ctx: ToolContext, args: SettingsInput) -> Envelope:
    results, errors = await gather_sections(
        {
            "general": ctx.client.get_json("/api/settings/general"),
            "scanner": ctx.client.get_json(
                "/api/settings/scanner",
                params={"env": args.environment_id, "settingsOnly": True},
            ),
            "semver": ctx.client.get_json("/api/settings/semver"),
        }
    )
    if not results:
        first = next(iter(errors.values()))
        return err(first["code"], first["message"], dockhand_status=first.get("dockhand_status"))
    data: dict[str, Any] = dict(results)
    if errors:
        data["errors"] = errors
    return ok(data, environment_id=args.environment_id, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_settings",
        title="Get settings",
        description=(
            "Get DockHand's general settings, vulnerability-scanner settings and newer-version "
            "(semver) detection settings. A section that cannot be read is reported under errors."
        ),
        input_model=SettingsInput,
        handler=get_settings,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (
        ("GET", "/api/settings/general"),
        ("GET", "/api/settings/scanner"),
        ("GET", "/api/settings/semver"),
    ),
)
