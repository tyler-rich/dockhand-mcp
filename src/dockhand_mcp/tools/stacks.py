# SPDX-License-Identifier: Apache-2.0
"""Stack tools: reads, DockHand's two stateless validators, stack lifecycle (operator), and
down and delete (destructive).

`POST /api/stacks/{name}/validate` and `POST /api/stacks/{name}/env/validate` are tiered `read`:
per the spec they lint what they are given (or the saved file) and persist nothing. Writes that
persist compose or `.env` content live in `stack_files.py`.

Lifecycle, per the spec's 200 descriptions: start, stop and down return a job id (a request
whose `Accept` lacks `text/event-stream` would block instead); deploy and restart are described
as SSE streams, but live DockHand 1.0.46 answered both with a `{jobId}` whose lines carry the
stream's events (S3a), and both shapes are handled. Delete is synchronous. Every stack operation
first reads the stack's variables so DockHand's answer is redacted with its values too.
"""

from typing import Annotated, Any, Final, Literal

from pydantic import Field, StringConstraints

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.redaction import OutputRedactor, redacting
from dockhand_mcp.guardrails.names import STACK_NAME
from dockhand_mcp.tools import _stackguard as stackguard
from dockhand_mcp.tools._common import (
    JOB_ACCEPT,
    JOB_STATUS,
    PAGE_SCHEMA,
    EnvDestructiveInputs,
    EnvScoped,
    EnvWriteInputs,
    SseRequest,
    ToolInput,
    add_warnings,
    as_dict,
    cap_json,
    cap_text,
    destructive_tool,
    dockhand_success,
    env_tool,
    gather_sections,
    limit_field,
    list_body,
    max_bytes_field,
    names_text,
    offset_field,
    page,
    run_async_pattern,
    scoped,
    section_warnings,
    text_schema,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_ANNOTATIONS,
    OPERATOR_IDEMPOTENT_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

MAX_COMPOSE_CHARS: Final = 512 * 1024  # well inside the 1 MiB request cap
MAX_ENV_VARS: Final = 500
MAX_ENV_VALUE: Final = 8192
ENV_KEY: Final = r"^[A-Za-z_][A-Za-z0-9_.-]{0,255}$"

StackName = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=STACK_NAME.pattern)
]
EnvKey = Annotated[str, StringConstraints(pattern=ENV_KEY)]
EnvValue = Annotated[str, StringConstraints(max_length=MAX_ENV_VALUE)]

STACK_DESCRIPTION: Final = "Stack name, as listed."


class StackScoped(EnvScoped):
    stack: StackName = Field(description=STACK_DESCRIPTION)


def _stack_call(ctx: ToolContext, template: str, stack: str, env: int) -> Any:
    return ctx.client.get_json(template, path_params={"name": stack}, params={"env": env})


# --- list -------------------------------------------------------------------------------------

StackType = Literal["internal", "git", "external"]


class ListStacksInput(EnvScoped):
    type: StackType | None = Field(default=None, description="Only stacks of this source type.")
    limit: int = limit_field(50)
    offset: int = offset_field()


STACK_FIELDS: Final = (
    "name",
    "status",
    "sourceType",
    "containers",
    "updatesAvailable",
    "updateCount",
    "newerVersionCount",
)


async def list_stacks(ctx: ToolContext, args: ListStacksInput, env: int) -> Any:
    body = await ctx.client.get_json("/api/stacks", params={"env": env})
    rows = [
        {**{k: i[k] for k in STACK_FIELDS if k in i}, "tracked": stackguard.is_tracked(i)}
        for i in list_body(body)
        if isinstance(i, dict)
    ]
    if args.type is not None:
        rows = [r for r in rows if r.get("sourceType") == args.type]
    return page(rows, args.limit, args.offset)


register(
    ToolSpec(
        name="dockhand_list_stacks",
        title="List stacks",
        description=(
            "List compose stacks in an environment. Returns each stack's name, status, source "
            "type, container names, pending update counts, and whether DockHand tracks it in "
            "this environment."
        ),
        input_model=ListStacksInput,
        handler=env_tool(list_stacks),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "type"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, stackguard.LIST),
)

# --- compose and env --------------------------------------------------------------------------


class StackInput(StackScoped):
    pass


class GetComposeInput(StackScoped):
    lint: bool = Field(
        default=False,
        description="Also check the compose file against this server's compose guardrails, "
        "with the stack's variables, and attach the findings. Report only.",
    )


async def _lint(ctx: ToolContext, stack: str, env: int, content: str) -> tuple[Any, list[str]]:
    warnings: list[str] = []
    variables: dict[str, Any] | None = None
    try:
        stack_env = await stackguard.fetch_stack_env(ctx, stack, env)
        variables = stackguard.stack_variables(stack_env.raw, stack_env)
    except DockhandError as e:
        warnings.append(f"stack variables unavailable ({e.message}); they were treated as unset")
    try:
        findings = stackguard.check(ctx, content, variables)
    except DockhandError as e:
        findings = stackguard.invalid_document(e.message)
    return stackguard.section(findings, "warn"), warnings


async def get_stack_compose(ctx: ToolContext, args: GetComposeInput, env: int) -> Any:
    body = await _stack_call(ctx, "/api/stacks/{name}/compose", args.stack, env)
    if not args.lint or not isinstance(body, dict):
        return body
    content = body.get("content")
    guardrails, warnings = await _lint(
        ctx, args.stack, env, content if isinstance(content, str) else ""
    )
    return ok({**body, "guardrails": guardrails}, warnings=warnings)


register(
    ToolSpec(
        name="dockhand_get_stack_compose",
        title="Get stack compose",
        description=(
            "Get a stack's compose file content and the paths of its compose and .env files, "
            "optionally with compose guardrail findings."
        ),
        input_model=GetComposeInput,
        handler=env_tool(get_stack_compose),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack", "lint"),
    ),
    Tier.READ,
    (ENVIRONMENTS, stackguard.COMPOSE, stackguard.ENV_RAW, stackguard.ENV_VARS),
)


async def get_stack_env(ctx: ToolContext, args: StackInput, env: int) -> Any:
    return await _stack_call(ctx, "/api/stacks/{name}/env", args.stack, env)


register(
    ToolSpec(
        name="dockhand_get_stack_env",
        title="Get stack env",
        description=(
            "Get a stack's environment variables as key, value and isSecret. Secret values are "
            "masked by DockHand as ***."
        ),
        input_model=StackInput,
        handler=env_tool(get_stack_env),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/stacks/{name}/env")),
)


async def get_stack_env_raw(ctx: ToolContext, args: StackInput, env: int) -> Any:
    return await _stack_call(ctx, "/api/stacks/{name}/env/raw", args.stack, env)


register(
    ToolSpec(
        name="dockhand_get_stack_env_raw",
        title="Get stack .env file",
        description=(
            "Get a stack's .env file as raw text, comments and formatting preserved. Secrets "
            "stored by DockHand are not part of this file."
        ),
        input_model=StackInput,
        handler=env_tool(get_stack_env_raw),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/stacks/{name}/env/raw")),
)

# --- deploys ----------------------------------------------------------------------------------


class ListDeploysInput(StackScoped):
    limit: int = limit_field(20, 100)


async def list_stack_deploys(ctx: ToolContext, args: ListDeploysInput, env: int) -> Any:
    body = await _stack_call(ctx, "/api/stacks/{name}/deploys", args.stack, env)
    runs = body.get("runs") if isinstance(body, dict) else None
    return page(list_body(runs), args.limit, 0)


register(
    ToolSpec(
        name="dockhand_list_stack_deploys",
        title="List stack deploys",
        description=(
            "List a stack's recorded deploy runs: id, trigger, timing, status and error message."
        ),
        input_model=ListDeploysInput,
        handler=env_tool(list_stack_deploys),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/stacks/{name}/deploys")),
)


class DeployLogInput(ToolInput):
    # The deploy-run endpoints take no environment: the run id identifies it.
    stack: StackName = Field(description=STACK_DESCRIPTION)
    run_id: int = Field(ge=1, le=2**31 - 1, description="Deploy run id, as listed.")
    max_bytes: int = max_bytes_field("log text")


async def get_stack_deploy_log(ctx: ToolContext, args: DeployLogInput) -> Envelope:
    path: dict[str, str | int] = {"name": args.stack, "runId": args.run_id}

    async def log_text() -> str:
        response = await ctx.client.raw(
            "GET", "/api/stacks/{name}/deploys/{runId}/log", path_params=path, accept="text/plain"
        )
        return response.text

    results, errors = await gather_sections(
        {
            "run": ctx.client.get_json("/api/stacks/{name}/deploys/{runId}", path_params=path),
            "log": log_text(),
        }
    )
    if "run" in errors:
        main = errors["run"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    data: dict[str, Any] = {"run": results["run"]}
    if "log" in results:
        data.update(cap_text(results["log"], args.max_bytes, key="log"))
    else:
        data.update({"log": "", "bytes": 0, "truncated": False, "dropped_bytes": 0})
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_stack_deploy_log",
        title="Get stack deploy log",
        description=(
            "Get one deploy run of a stack with its log text, capped in size, with a flag when "
            "the start of the log was dropped."
        ),
        input_model=DeployLogInput,
        handler=get_stack_deploy_log,
        annotations=READ_ANNOTATIONS,
        audit_args=("stack", "run_id"),
        data_schema=text_schema("log"),
    ),
    Tier.READ,
    (
        ("GET", "/api/stacks/{name}/deploys/{runId}"),
        ("GET", "/api/stacks/{name}/deploys/{runId}/log"),
    ),
)


async def preview_stack_delete(ctx: ToolContext, args: StackInput, env: int) -> Any:
    return await _stack_call(ctx, "/api/stacks/{name}/delete-preview", args.stack, env)


register(
    ToolSpec(
        name="dockhand_preview_stack_delete",
        title="Preview stack delete",
        description=(
            "Show the directories and named volumes that deleting a stack with its files would "
            "remove. Nothing is deleted."
        ),
        input_model=StackInput,
        handler=env_tool(preview_stack_delete),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/stacks/{name}/delete-preview")),
)

# --- validators (POST, stateless) -------------------------------------------------------------


class ValidateComposeInput(StackScoped):
    compose: str = Field(
        min_length=1,
        max_length=MAX_COMPOSE_CHARS,
        description="Compose file content to validate.",
    )
    env_vars: dict[EnvKey, EnvValue] | None = Field(
        default=None,
        max_length=MAX_ENV_VARS,
        description="Variables to interpolate while validating, by name.",
    )
    existing: bool = Field(
        default=False,
        description="True when validating an already-deployed stack, so its own containers "
        "and ports are not reported as collisions.",
    )


async def validate_stack_compose(ctx: ToolContext, args: ValidateComposeInput, env: int) -> Any:
    body: dict[str, Any] = {"compose": args.compose, "existing": args.existing}
    if args.env_vars is not None:
        body["envVars"] = args.env_vars
    # The values in hand are the ones given; the stack's saved ones are not fetched (read tier).
    with redacting(OutputRedactor.for_values((args.env_vars or {}).values())):
        result = await ctx.client.post_json(
            "/api/stacks/{name}/validate",
            path_params={"name": args.stack},
            params={"env": env},
            json=body,
        )
    try:
        findings = stackguard.check(ctx, args.compose, args.env_vars)
    except DockhandError as e:
        findings = stackguard.invalid_document(e.message)
    guardrails = stackguard.section(findings, "warn")
    return {**(result if isinstance(result, dict) else {}), "guardrails": guardrails}


register(
    ToolSpec(
        name="dockhand_validate_stack_compose",
        title="Validate stack compose",
        description=(
            "Lint a compose file with DockHand's validator and this server's compose guardrails "
            "without saving or deploying it. Returns both sets of findings with severities."
        ),
        input_model=ValidateComposeInput,
        handler=env_tool(validate_stack_compose),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack", "existing"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("POST", "/api/stacks/{name}/validate")),
)


class ValidateEnvInput(StackScoped):
    compose: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_COMPOSE_CHARS,
        description="Compose content to check against; the saved compose file when omitted.",
    )
    variables: list[EnvKey] | None = Field(
        default=None,
        max_length=MAX_ENV_VARS,
        description="Defined variable names; the stack's saved variables when omitted.",
    )


async def validate_stack_env(ctx: ToolContext, args: ValidateEnvInput, env: int) -> Any:
    body: dict[str, Any] = {}
    if args.compose is not None:
        body["compose"] = args.compose
    if args.variables is not None:
        body["variables"] = args.variables
    return await ctx.client.post_json(
        "/api/stacks/{name}/env/validate",
        path_params={"name": args.stack},
        params={"env": env},
        json=body,
    )


register(
    ToolSpec(
        name="dockhand_validate_stack_env",
        title="Validate stack env",
        description=(
            "Check a stack's defined variables against those its compose file uses, without "
            "saving anything. Returns required, optional, missing and unused variable names."
        ),
        input_model=ValidateEnvInput,
        handler=env_tool(validate_stack_env),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("POST", "/api/stacks/{name}/env/validate")),
)

# --- paths ------------------------------------------------------------------------------------


class StackPathsInput(EnvScoped):
    stack: StackName | None = Field(
        default=None, description="Stack name; omit for the environment's stacks directory only."
    )


async def get_stack_paths(ctx: ToolContext, args: StackPathsInput, env: int) -> Envelope:
    calls: dict[str, Any] = {
        "base_path": ctx.client.get_json("/api/stacks/base-path", params={"env": env}),
        "sources": ctx.client.get_json("/api/stacks/sources", params={"env": env}),
    }
    if args.stack is not None:
        by_name: dict[str, str | int] = {"name": args.stack, "env": env}
        calls["default_path"] = ctx.client.get_json("/api/stacks/default-path", params=by_name)
        calls["path_hints"] = ctx.client.get_json("/api/stacks/path-hints", params=by_name)
    results, errors = await gather_sections(calls)
    if not results:
        first = next(iter(errors.values()))
        return err(first["code"], first["message"], dockhand_status=first.get("dockhand_status"))
    sources = results.get("sources")
    # Live DockHand keys sources by stack name; the spec gives no schema.
    if args.stack is not None and isinstance(sources, dict):
        results["sources"] = {args.stack: sources[args.stack]} if args.stack in sources else {}
    data: dict[str, Any] = dict(results)
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_stack_paths",
        title="Get stack paths",
        description=(
            "Show where stack files live: the stacks base directory, stored compose and .env "
            "paths per stack, and for one stack its default path and container label hints."
        ),
        input_model=StackPathsInput,
        handler=env_tool(get_stack_paths),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "stack"),
    ),
    Tier.READ,
    (
        ENVIRONMENTS,
        ("GET", "/api/stacks/base-path"),
        ("GET", "/api/stacks/sources"),
        ("GET", "/api/stacks/default-path"),
        ("GET", "/api/stacks/path-hints"),
    ),
)

# --- lifecycle (operator) ---------------------------------------------------------------------
# Each lifecycle tool reads the stack's variables first, to redact their values from its output.

OUTPUT_ENV: Final = (stackguard.ENV_RAW, stackguard.ENV_VARS)


class StackWriteInput(EnvWriteInputs):
    stack: StackName = Field(description=STACK_DESCRIPTION)


def _meta(action: str, stack: str, env: int) -> dict[str, Any]:
    return {"action": action, "stack": stack, "environment_id": env}


def _stack_job(action: str) -> Any:
    async def body(ctx: ToolContext, args: StackWriteInput, env: int) -> Envelope:
        budget, warnings = write_budget(ctx, args)
        await stackguard.require_tracked(ctx, args.stack, env)
        redactor = await stackguard.output_redactor(ctx, args.stack, env)

        async def start() -> Any:
            return await ctx.client.post_json(
                f"/api/stacks/{{name}}/{action}",
                path_params={"name": args.stack},
                params={"env": env},
                accept=JOB_ACCEPT,
            )

        envelope = await run_async_pattern(
            "job",
            ctx,
            wait=args.wait,
            budget_s=budget,
            meta=_meta(action, args.stack, env),
            start=start,
            redactor=redactor,
        )
        return add_warnings(envelope, warnings)

    return body


for _action, _title, _description in (
    (
        "start",
        "Start stack",
        "Start a stack's containers (docker compose start/up) as a DockHand job. Returns the "
        "job's status, result and last output lines.",
    ),
    (
        "stop",
        "Stop stack",
        "Stop a stack's containers (docker compose stop) as a DockHand job. Returns the job's "
        "status, result and last output lines.",
    ),
):
    register(
        ToolSpec(
            name=f"dockhand_{_action}_stack",
            title=_title,
            description=_description,
            input_model=StackWriteInput,
            handler=env_tool(_stack_job(_action)),
            annotations=OPERATOR_IDEMPOTENT_ANNOTATIONS,
            audit_args=("environment_id", "stack", "wait"),
        ),
        Tier.OPERATOR,
        (
            ENVIRONMENTS,
            stackguard.LIST,
            *OUTPUT_ENV,
            ("POST", f"/api/stacks/{{name}}/{_action}"),
            JOB_STATUS,
        ),
    )


RestartMode = Literal["restart", "ordered", "recreate"]


class RestartStackInput(StackWriteInput):
    mode: RestartMode = Field(
        default="restart",
        description="restart: in place; ordered: stop then start honouring depends_on; "
        "recreate: new containers, picking up compose and .env changes.",
    )


async def restart_stack(ctx: ToolContext, args: RestartStackInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    await stackguard.require_tracked(ctx, args.stack, env)
    redactor = await stackguard.output_redactor(ctx, args.stack, env)
    request = SseRequest(
        "POST",
        "/api/stacks/{name}/restart",
        path_params={"name": args.stack},
        params={"env": env, "mode": args.mode},
    )
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={**_meta("restart", args.stack, env), "mode": args.mode},
        sse=request,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_restart_stack",
        title="Restart stack",
        description=(
            "Restart a stack in place, in dependency order, or by recreating its containers. "
            "Returns DockHand's result and the last progress lines."
        ),
        input_model=RestartStackInput,
        handler=env_tool(restart_stack),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "stack", "mode", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        *OUTPUT_ENV,
        ("POST", "/api/stacks/{name}/restart"),
        JOB_STATUS,
    ),
)


class DeployStackInput(StackWriteInput):
    pull: bool = Field(default=False, description="Pull images before starting.")
    build: bool = Field(default=False, description="Build images that have a build section.")
    force_recreate: bool = Field(
        default=False, description="Recreate containers even if their configuration is unchanged."
    )


async def deploy_stack(ctx: ToolContext, args: DeployStackInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    await stackguard.require_tracked(ctx, args.stack, env)
    redactor = await stackguard.output_redactor(ctx, args.stack, env)
    request = SseRequest(
        "POST",
        "/api/stacks/{name}/deploy",
        path_params={"name": args.stack},
        params={"env": env},
        json={"pull": args.pull, "build": args.build, "forceRecreate": args.force_recreate},
    )
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta=_meta("deploy", args.stack, env),
        sse=request,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_deploy_stack",
        title="Deploy stack",
        description=(
            "Deploy a stack (docker compose up), optionally pulling, building and force-"
            "recreating. Returns DockHand's result and the last progress lines."
        ),
        input_model=DeployStackInput,
        handler=env_tool(deploy_stack),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "stack", "pull", "build", "force_recreate", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, stackguard.LIST, *OUTPUT_ENV, ("POST", "/api/stacks/{name}/deploy"), JOB_STATUS),
)

# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.

DELETE_PREVIEW: Final = ("GET", "/api/stacks/{name}/delete-preview")


async def _delete_preview(ctx: ToolContext, stack: str, env: int) -> dict[str, Any]:
    return as_dict(await _stack_call(ctx, DELETE_PREVIEW[1], stack, env))


def _strings(value: Any) -> list[str]:
    return [str(v) for v in value if isinstance(v, str)] if isinstance(value, list) else []


async def _container_names(ctx: ToolContext, env: int, refs: list[str]) -> list[str]:
    """Names for a stack's containers: live DockHand 1.0.46 lists them by id, not by name."""
    listed = list_body(
        await ctx.client.get_json("/api/containers", params={"env": env, "all": True})
    )
    names = {
        str(i.get("id")): str(i.get("name"))
        for i in listed
        if isinstance(i, dict) and i.get("id") and i.get("name")
    }
    return [names.get(ref, ref) for ref in refs]


class DownStackInput(EnvDestructiveInputs):
    stack: StackName = Field(description=STACK_DESCRIPTION)
    remove_volumes: bool = Field(
        default=False, description="Also remove the stack's named volumes and their data."
    )


async def down_stack_preview(ctx: ToolContext, args: DownStackInput, env: int | None) -> Preview:
    env = scoped(env)
    item = await stackguard.require_tracked(ctx, args.stack, env)
    containers = await _container_names(ctx, env, _strings(item.get("containers")))
    data: dict[str, Any] = {
        "stack": args.stack,
        "status": item.get("status"),
        "containers": containers,
        "remove_volumes": args.remove_volumes,
    }
    counts = {"containers": len(containers)}
    summary = (
        f"Take stack {args.stack} down (docker compose down) in environment {env}: removes its "
        f"{len(containers)} container(s): {names_text(containers)}. Its files are kept."
    )
    if args.remove_volumes:
        volumes = _strings((await _delete_preview(ctx, args.stack, env)).get("namedVolumes"))
        data["named_volumes"] = volumes
        counts["volumes"] = len(volumes)
        summary += f" Also removes {len(volumes)} named volume(s) and their data: "
        summary += f"{names_text(volumes)}."
    else:
        summary += " Volumes are kept."
    return Preview(summary=summary, data=data, counts=counts, target={"stack": args.stack})


async def down_stack(
    ctx: ToolContext, args: DownStackInput, env: int | None, preview: Preview, approved: Approved
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    stack = str(preview.target["stack"])
    redactor = await stackguard.output_redactor(ctx, stack, scoped(env))

    async def start() -> Any:
        return await ctx.client.post_json(
            "/api/stacks/{name}/down",
            path_params={"name": stack},
            params={"env": env},
            json={"removeVolumes": args.remove_volumes},
            accept=JOB_ACCEPT,
        )

    envelope = await run_async_pattern(
        "job",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta=_meta("down", stack, scoped(env)),
        start=start,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_down_stack",
        title="Take stack down",
        description=(
            "Take a stack down (docker compose down: removes its containers, keeps its files) "
            "after a human approves, optionally removing its named volumes. Returns the job's "
            "status and result."
        ),
        input_model=DownStackInput,
        preview=down_stack_preview,
        execute=down_stack,
        audit_args=("environment_id", "stack", "remove_volumes", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        ("GET", "/api/containers"),
        DELETE_PREVIEW,
        *OUTPUT_ENV,
        ("POST", "/api/stacks/{name}/down"),
        JOB_STATUS,
    ),
)


class DeleteStackInput(EnvDestructiveInputs):
    stack: StackName = Field(description=STACK_DESCRIPTION)
    force: bool = Field(
        default=False, description="Remove the stack even if its compose down step fails."
    )
    remove_volumes: bool = Field(
        default=False, description="Also remove the stack's named volumes and their data."
    )
    delete_files: bool = Field(
        default=False,
        description="Also delete the stack's directory and files on the DockHand host.",
    )


async def delete_stack_preview(
    ctx: ToolContext, args: DeleteStackInput, env: int | None
) -> Preview:
    env = scoped(env)
    await stackguard.require_tracked(ctx, args.stack, env)
    found = await _delete_preview(ctx, args.stack, env)
    volumes = _strings(found.get("namedVolumes"))
    directories = [d for d in (found.get("stackDir"), found.get("gitDir")) if isinstance(d, str)]
    summary = (
        f"Delete stack {args.stack} in environment {env}: docker compose down"
        f"{' (forced if it fails)' if args.force else ''}, then remove the stack from DockHand."
    )
    if args.delete_files:
        summary += f" Deletes its files: {names_text(directories)}."
        if found.get("canDeleteFiles") is False:
            summary += " DockHand reports it cannot delete these files."
    else:
        summary += " Its files stay on disk."
    if args.remove_volumes:
        summary += f" Removes {len(volumes)} named volume(s) and their data: {names_text(volumes)}."
    else:
        summary += " Named volumes are kept."
    return Preview(
        summary=summary,
        data={
            "delete_preview": cap_json(found),
            "force": args.force,
            "remove_volumes": args.remove_volumes,
            "delete_files": args.delete_files,
        },
        counts={
            "volumes": len(volumes) if args.remove_volumes else 0,
            "directories": len(directories) if args.delete_files else 0,
        },
        target={"stack": args.stack},
    )


async def delete_stack(
    ctx: ToolContext,
    args: DeleteStackInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    stack = str(preview.target["stack"])
    redactor = await stackguard.output_redactor(ctx, stack, scoped(env))
    # DockHand deletes the files unless told not to (`files` defaults to true); always say which.
    params = {
        "env": env,
        "force": args.force,
        "volumes": args.remove_volumes,
        "files": args.delete_files,
    }

    async def work() -> Envelope:
        answer = await ctx.client.delete_json(
            "/api/stacks/{name}",
            path_params={"name": stack},
            params=params,
            read_timeout=float(ctx.settings.max_timeout) + 5.0,
        )
        data = {
            "stack": stack,
            "deleted": True,
            "files_deleted": args.delete_files,
            "volumes_removed": args.remove_volumes,
        }
        return dockhand_success(answer, data, "stack deletion")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta=_meta("delete", stack, scoped(env)),
        work=work,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_delete_stack",
        title="Delete stack",
        description=(
            "Delete a stack from DockHand (compose down, then remove it) after a human "
            "approves; its files and named volumes are kept unless asked for. Returns what was "
            "deleted."
        ),
        input_model=DeleteStackInput,
        preview=delete_stack_preview,
        execute=delete_stack,
        audit_args=(
            "environment_id",
            "stack",
            "force",
            "remove_volumes",
            "delete_files",
            "wait",
        ),
    ),
    Tier.DESTRUCTIVE,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        DELETE_PREVIEW,
        *OUTPUT_ENV,
        ("DELETE", "/api/stacks/{name}"),
    ),
)
