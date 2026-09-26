# SPDX-License-Identifier: Apache-2.0
"""Aggregated vulnerability findings for an environment.

Spec 1.0.46 lists no environment parameter for these two routes; its description says their
filters are "parsed centrally". Live DockHand takes `env`, like every other environment-scoped
route, and answers an empty result without it (maintainer decision, ARCHIVE 2026-09-24).
"""

from typing import Any, Literal

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.tools._common import (
    JOB_STATUS,
    PAGE_SCHEMA,
    EnvScoped,
    EnvWriteInputs,
    SseRequest,
    add_warnings,
    env_tool,
    limit_field,
    list_body,
    offset_field,
    remote_page,
    run_async_pattern,
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

Severity = Literal["critical", "high", "medium", "low", "negligible", "unknown"]
FILTER = r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}$"


class ListVulnerabilitiesInput(EnvScoped):
    severity: Severity | None = Field(default=None, description="Only findings of this severity.")
    image: str | None = Field(
        default=None, max_length=255, pattern=FILTER, description="Only findings in this image."
    )
    container: str | None = Field(
        default=None, max_length=255, pattern=FILTER, description="Only this container's images."
    )
    stack: str | None = Field(
        default=None, max_length=255, pattern=FILTER, description="Only this stack's images."
    )
    q: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f]*$",
        description="Free-text search, e.g. a CVE id or package name.",
    )
    sort: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^[A-Za-z]+$",
        description="Field to sort by, e.g. severity.",
    )
    limit: int = limit_field(50, 200)
    offset: int = offset_field()


async def list_vulnerabilities(ctx: ToolContext, args: ListVulnerabilitiesInput, env: int) -> Any:
    body = await ctx.client.get_json(
        "/api/vulnerabilities",
        params={
            "env": env,
            "severity": args.severity,
            "image": args.image,
            "container": args.container,
            "stack": args.stack,
            "q": args.q,
            "sort": args.sort,
            "limit": args.limit,
            "offset": args.offset,
        },
    )
    body = body if isinstance(body, dict) else {}
    findings = list_body(body.get("findings"))
    extra = {"summary": body["summary"]} if "summary" in body else {}
    return remote_page(findings, body.get("total"), args.offset, **extra)


register(
    ToolSpec(
        name="dockhand_list_vulnerabilities",
        title="List vulnerabilities",
        description=(
            "List vulnerability findings from stored image scans in an environment, filtered by "
            "severity, image, container, stack or search text. Returns CVE, package, versions "
            "and affected images."
        ),
        input_model=ListVulnerabilitiesInput,
        handler=env_tool(list_vulnerabilities),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "severity"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/vulnerabilities")),
)


class VulnerabilitySummaryInput(EnvScoped):
    pass


async def get_vulnerability_summary(
    ctx: ToolContext, args: VulnerabilitySummaryInput, env: int
) -> Any:
    return await ctx.client.get_json("/api/vulnerabilities/count", params={"env": env})


register(
    ToolSpec(
        name="dockhand_get_vulnerability_summary",
        title="Get vulnerability summary",
        description=(
            "Get the total vulnerability finding count and counts per severity for an "
            "environment, with the images, containers and stacks that have findings."
        ),
        input_model=VulnerabilitySummaryInput,
        handler=env_tool(get_vulnerability_summary),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/vulnerabilities/count")),
)

# --- operator tier ----------------------------------------------------------------------------


class ScanAllInput(EnvWriteInputs):
    wait: bool = Field(
        default=False,
        description="Wait for the scan to finish, up to timeout_seconds; it can take many "
        "minutes. When false, return its id at once.",
    )


async def scan_all_images(ctx: ToolContext, args: ScanAllInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "scan_all", "environment_id": env},
        sse=SseRequest("POST", "/api/vulnerabilities/scan-all", params={"env": env}),
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_scan_all_images",
        title="Scan all images",
        description=(
            "Scan every image in an environment for vulnerabilities and store the results. "
            "Returns DockHand's summary, or an operation id to check later."
        ),
        input_model=ScanAllInput,
        handler=env_tool(scan_all_images),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/vulnerabilities/scan-all"), JOB_STATUS),
)
