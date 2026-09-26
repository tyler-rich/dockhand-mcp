# SPDX-License-Identifier: Apache-2.0
"""Environment tools: list environments, one environment with its schedules and settings, a
connection test (operator), and running the configured image prune now (destructive).

DockHand promises never to return `tlsKey` or `hawserToken`; both tools fail closed if an
environment object carries either key.
"""

import logging
from typing import Any, Final

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.tools._common import (
    PAGE_SCHEMA,
    EnvDestructiveInputs,
    EnvScoped,
    EnvWriteInputs,
    ToolInput,
    add_warnings,
    as_dict,
    destructive_tool,
    dockhand_success,
    env_tool,
    gather_sections,
    list_body,
    page,
    run_async_pattern,
    scoped,
    section_warnings,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.registry import Tier, register

log = logging.getLogger(__name__)

CREDENTIAL_KEYS: Final = ("tlsKey", "hawserToken")
CANARY_MESSAGE: Final = (
    "DockHand returned environment credential material (tlsKey or hawserToken), which it "
    "documents it never returns; the result was withheld"
)
ENVIRONMENTS: Final = ("GET", "/api/environments")


def leaked_credentials(items: list[Any]) -> list[str]:
    """Credential keys present in any environment object (key names only)."""
    return sorted({k for i in items if isinstance(i, dict) for k in CREDENTIAL_KEYS if k in i})


def canary_failure(keys: list[str]) -> Envelope:
    log.error("credential_canary", extra={"source": "environments", "keys": keys})
    return err("guardrail_blocked", CANARY_MESSAGE)


class ListEnvironmentsInput(ToolInput):
    pass


async def list_environments(ctx: ToolContext, args: ListEnvironmentsInput) -> Envelope:
    items = list_body(await ctx.client.get_json("/api/environments"))
    if keys := leaked_credentials(items):
        return canary_failure(keys)
    return ok(page(items, len(items) or 1, 0))


register(
    ToolSpec(
        name="dockhand_list_environments",
        title="List environments",
        description=(
            "List the Docker environments (hosts) DockHand manages. Returns each environment's "
            "id, name and connection type."
        ),
        input_model=ListEnvironmentsInput,
        handler=list_environments,
        annotations=READ_ANNOTATIONS,
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS,),
)


class GetEnvironmentInput(EnvScoped):
    pass


SECTIONS: Final = {
    "timezone": "/api/environments/{id}/timezone",
    "update_check": "/api/environments/{id}/update-check",
    "image_prune": "/api/environments/{id}/image-prune",
    "disk_warning": "/api/environments/{id}/disk-warning",
    "remote_stacks_dir": "/api/environments/{id}/remote-stacks-dir",
}


async def get_environment(ctx: ToolContext, args: GetEnvironmentInput, env: int) -> Envelope:
    calls = {"environment": ctx.client.get_json("/api/environments/{id}", path_params={"id": env})}
    for section, template in SECTIONS.items():
        calls[section] = ctx.client.get_json(template, path_params={"id": env})
    results, errors = await gather_sections(calls)
    if "environment" in errors:
        main = errors["environment"]
        return err(
            main["code"],
            f"environment {env}: {main['message']}",
            dockhand_status=main.get("dockhand_status"),
        )
    environment = results["environment"]
    if isinstance(environment, dict) and (keys := leaked_credentials([environment])):
        return canary_failure(keys)
    data: dict[str, Any] = {**results}
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_environment",
        title="Get environment",
        description=(
            "Get one environment with its timezone, update-check, image-prune, disk-warning and "
            "remote stacks directory settings. A section that cannot be read is reported under "
            "errors."
        ),
        input_model=GetEnvironmentInput,
        handler=env_tool(get_environment),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (
        ENVIRONMENTS,
        ("GET", "/api/environments/{id}"),
        *(("GET", template) for template in SECTIONS.values()),
    ),
)

# --- operator tier ----------------------------------------------------------------------------


class EnvironmentTestInput(EnvWriteInputs):
    pass


async def run_environment_test(ctx: ToolContext, args: EnvironmentTestInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def work() -> Envelope:
        body = await ctx.client.post_json("/api/environments/{id}/test", path_params={"id": env})
        hawser = body.get("hawser") if isinstance(body, dict) else None
        leaked = leaked_credentials([body, hawser])
        if leaked:
            return canary_failure(leaked)
        return ok(body)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "test_environment", "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_test_environment",
        title="Test environment",
        description=(
            "Test DockHand's connection to a saved environment's Docker endpoint without "
            "changing it. Returns success and the engine's version and counts."
        ),
        input_model=EnvironmentTestInput,
        handler=env_tool(run_environment_test),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/environments/{id}/test")),
)


# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.

IMAGE_PRUNE: Final = "/api/environments/{id}/image-prune"


class RunImagePruneInput(EnvDestructiveInputs):
    pass


async def run_image_prune_preview(
    ctx: ToolContext, args: RunImagePruneInput, env: int | None
) -> Preview:
    env = scoped(env)
    body = as_dict(await ctx.client.get_json(IMAGE_PRUNE, path_params={"id": env}))
    settings = as_dict(body.get("settings"))
    mode = settings.get("pruneMode")
    return Preview(
        summary=f"Run environment {env}'s image prune now, outside its schedule, with its "
        f"configured prune mode: {mode}. Images it removes cannot be recovered.",
        data={"image_prune_settings": settings},
        counts={},
        target={"environment_id": env},
    )


async def run_image_prune_now(
    ctx: ToolContext,
    args: RunImagePruneInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    env_id = int(preview.target["environment_id"])

    async def work() -> Envelope:
        answer = await ctx.client.put_json(
            IMAGE_PRUNE,
            path_params={"id": env_id},
            read_timeout=float(ctx.settings.max_timeout) + 5.0,
        )
        return dockhand_success(answer, {"environment_id": env_id}, "image prune")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "run_image_prune", "environment_id": env_id},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_run_image_prune_now",
        title="Run image prune now",
        description=(
            "Run an environment's configured image prune immediately, after a human approves. "
            "Returns DockHand's answer."
        ),
        input_model=RunImagePruneInput,
        preview=run_image_prune_preview,
        execute=run_image_prune_now,
        audit_args=("environment_id", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (ENVIRONMENTS, ("GET", IMAGE_PRUNE), ("PUT", IMAGE_PRUNE)),
)
