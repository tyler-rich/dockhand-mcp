# SPDX-License-Identifier: Apache-2.0
"""Container tools: reads, lifecycle, rename, image updates and auto-update settings. Containers
are named by ID or exact name, resolved on every call through `GET /api/containers`
(guardrails/names.py).

Inspect uses `GET /api/containers/{id}` (DockHand's `view` permission) rather than
`/{id}/inspect` (the separate `inspect` permission); both return the same Docker payload.
"""

from typing import Annotated, Any, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.batch import interpret_update
from dockhand_mcp.client.envelope import Envelope, ErrorInfo, err, ok
from dockhand_mcp.guardrails.names import DOCKER_NAME, resolve_container, resolve_containers
from dockhand_mcp.tools._common import (
    JOB_STATUS,
    PAGE_SCHEMA,
    EnvDestructiveInputs,
    EnvScoped,
    EnvWriteInputs,
    SseRequest,
    add_warnings,
    as_dict,
    cap_json,
    cap_text,
    destructive_tool,
    dockhand_success,
    env_tool,
    fail,
    gather_sections,
    limit_field,
    list_body,
    max_bytes_field,
    offset_field,
    page,
    redact_compose_env,
    redact_env,
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

LIST: Final = ("GET", "/api/containers")
MAX_LOG_TAIL: Final = 5000
MAX_PROCESSES: Final = 1000
MAX_NOTE_BYTES: Final = 16 * 1024
STACK_LABEL: Final = "com.docker.compose.project"

REF_DESCRIPTION: Final = "Container ID (12-64 hex characters) or exact container name."

ContainerState = Literal["created", "running", "paused", "restarting", "removing", "exited", "dead"]


class ContainerScoped(EnvScoped):
    ref: str = Field(min_length=1, max_length=255, description=REF_DESCRIPTION)


def _container(ref: Any) -> dict[str, str]:
    return {"id": ref.id, "name": ref.name}


# --- list -------------------------------------------------------------------------------------


class ListContainersInput(EnvScoped):
    all: bool = Field(default=True, description="Include stopped containers.")
    state: ContainerState | None = Field(default=None, description="Only containers in this state.")
    name_contains: str | None = Field(
        default=None, min_length=1, max_length=128, description="Case-insensitive name filter."
    )
    stack: str | None = Field(
        default=None, min_length=1, max_length=64, description="Only containers of this stack."
    )
    limit: int = limit_field(50)
    offset: int = offset_field()


def _summary(item: dict[str, Any]) -> dict[str, Any]:
    labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
    out = {k: item.get(k) for k in ("id", "name", "image", "state", "status", "health")}
    stack = labels.get(STACK_LABEL) if isinstance(labels, dict) else None
    if stack:
        out["stack"] = stack
    return out


async def list_containers(ctx: ToolContext, args: ListContainersInput, env: int) -> Any:
    body = await ctx.client.get_json("/api/containers", params={"env": env, "all": args.all})
    rows = [_summary(i) for i in list_body(body) if isinstance(i, dict)]
    if args.state is not None:
        rows = [r for r in rows if r["state"] == args.state]
    if args.name_contains is not None:
        needle = args.name_contains.lower()
        rows = [r for r in rows if needle in str(r["name"] or "").lower()]
    if args.stack is not None:
        rows = [r for r in rows if r.get("stack") == args.stack]
    return page(rows, args.limit, args.offset)


register(
    ToolSpec(
        name="dockhand_list_containers",
        title="List containers",
        description=(
            "List containers in an environment, optionally filtered by state, name or stack. "
            "Returns id, name, image, state, status, health and stack for each."
        ),
        input_model=ListContainersInput,
        handler=env_tool(list_containers),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "state", "stack"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST),
)

# --- inspect ----------------------------------------------------------------------------------


class GetContainerInput(ContainerScoped):
    redact_env: bool = Field(
        default=True,
        description=(
            'Replace environment variable values with "<redacted>" (names kept). When false, '
            "values are returned as-is, including secrets."
        ),
    )
    sections: list[str] | None = Field(
        default=None,
        min_length=1,
        max_length=20,
        description='Top-level inspect keys to return, e.g. ["State", "NetworkSettings"].',
    )


async def get_container(ctx: ToolContext, args: GetContainerInput, env: int) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}", path_params={"id": ref.id}, params={"env": env}
    )
    if args.redact_env:
        body = redact_env(body)
    warnings: list[str] = []
    if args.sections is not None and isinstance(body, dict):
        missing = [s for s in args.sections if s not in body]
        body = {k: v for k, v in body.items() if k in {"Id", "Name", *args.sections}}
        if missing:
            warnings.append(f"not in the inspect payload: {', '.join(missing[:20])}")
    return ok(body, warnings=warnings)


register(
    ToolSpec(
        name="dockhand_get_container",
        title="Get container",
        description=(
            "Get a container's full Docker inspect payload, or selected sections of it. "
            "Environment variable values are redacted unless redact_env is false, which returns "
            "secret values."
        ),
        input_model=GetContainerInput,
        handler=env_tool(get_container),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref", "redact_env"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}")),
)

# --- logs -------------------------------------------------------------------------------------

LOG_TIME: Final = r"^\d{1,12}[smhd]?$"


class LogsInput(ContainerScoped):
    tail: int = Field(
        default=200, ge=1, le=MAX_LOG_TAIL, description="Number of most recent lines."
    )
    since: str | None = Field(
        default=None,
        max_length=13,
        pattern=LOG_TIME,
        description="Only lines after this: a Unix timestamp or a duration such as 10m, 2h, 1d.",
    )
    until: str | None = Field(
        default=None,
        max_length=13,
        pattern=LOG_TIME,
        description="Only lines before this: a Unix timestamp or a duration such as 10m.",
    )
    max_bytes: int = max_bytes_field("log text")


async def get_container_logs(ctx: ToolContext, args: LogsInput, env: int) -> Any:
    ref = await resolve_container(ctx.client, env, args.ref)
    params: dict[str, Any] = {"env": env, "tail": args.tail, "since": args.since}
    params["until"] = args.until
    body = await ctx.client.get_json(
        "/api/containers/{id}/logs", path_params={"id": ref.id}, params=params, read_timeout=60.0
    )
    text = body.get("logs") if isinstance(body, dict) else None
    return {
        "container": _container(ref),
        "tail": args.tail,
        **cap_text(text if isinstance(text, str) else "", args.max_bytes, key="logs"),
    }


register(
    ToolSpec(
        name="dockhand_get_container_logs",
        title="Get container logs",
        description=(
            "Get the most recent lines of a container's combined stdout and stderr. Returns the "
            "text, capped in size, with a flag when older lines were dropped."
        ),
        input_model=LogsInput,
        handler=env_tool(get_container_logs),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref", "tail", "since", "until"),
        data_schema=text_schema("logs"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}/logs")),
)

# --- stats, processes -------------------------------------------------------------------------


class ContainerRefInput(ContainerScoped):
    pass


async def get_container_stats(ctx: ToolContext, args: ContainerRefInput, env: int) -> Any:
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}/stats", path_params={"id": ref.id}, params={"env": env}
    )
    return {"container": _container(ref), "stats": body}


register(
    ToolSpec(
        name="dockhand_get_container_stats",
        title="Get container stats",
        description=(
            "Get a one-shot resource snapshot for a container: CPU and memory use, network and "
            "block I/O."
        ),
        input_model=ContainerRefInput,
        handler=env_tool(get_container_stats),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}/stats")),
)


class AllStatsInput(EnvScoped):
    limit: int = limit_field(100)
    offset: int = offset_field()


async def get_all_container_stats(ctx: ToolContext, args: AllStatsInput, env: int) -> Any:
    body = await ctx.client.get_json("/api/containers/stats", params={"env": env})
    return page(list_body(body), args.limit, args.offset)


register(
    ToolSpec(
        name="dockhand_get_all_container_stats",
        title="Get all container stats",
        description=(
            "Get a resource snapshot for every running container in an environment: CPU and "
            "memory use, network and block I/O."
        ),
        input_model=AllStatsInput,
        handler=env_tool(get_all_container_stats),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/containers/stats")),
)


async def get_container_processes(ctx: ToolContext, args: ContainerRefInput, env: int) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}/top", path_params={"id": ref.id}, params={"env": env}
    )
    warnings: list[str] = []
    if isinstance(body, dict) and isinstance(body.get("Processes"), list):
        processes = body["Processes"]
        if len(processes) > MAX_PROCESSES:
            warnings.append(f"showing {MAX_PROCESSES} of {len(processes)} processes")
            body = {**body, "Processes": processes[:MAX_PROCESSES]}
    return ok(
        {"container": _container(ref), **(body if isinstance(body, dict) else {})},
        warnings=warnings,
    )


register(
    ToolSpec(
        name="dockhand_get_container_processes",
        title="Get container processes",
        description="List the processes running inside a container, with ps column titles.",
        input_model=ContainerRefInput,
        handler=env_tool(get_container_processes),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}/top")),
)

# --- sizes ------------------------------------------------------------------------------------


class SizesInput(EnvScoped):
    pass


def _size_rows(body: Any, names: dict[str, str]) -> list[dict[str, Any]]:
    # Live DockHand answers {containerId: {sizeRw, sizeRootFs}}; the spec describes an array.
    if isinstance(body, dict):
        rows = [
            {"id": cid, "name": names.get(cid), **(v if isinstance(v, dict) else {})}
            for cid, v in body.items()
        ]
    else:
        rows = [dict(i) for i in list_body(body) if isinstance(i, dict)]
    return sorted(rows, key=lambda r: -(r.get("sizeRw") or r.get("SizeRw") or 0))


async def get_container_sizes(ctx: ToolContext, args: SizesInput, env: int) -> Envelope:
    results, errors = await gather_sections(
        {
            "sizes": ctx.client.get_json("/api/containers/sizes", params={"env": env}),
            "containers": ctx.client.get_json("/api/containers", params={"env": env, "all": True}),
        }
    )
    if "sizes" in errors:
        main = errors["sizes"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    names = {
        str(i.get("id")): str(i.get("name"))
        for i in list_body(results.get("containers"))
        if isinstance(i, dict)
    }
    rows = _size_rows(results["sizes"], names)
    return ok(page(rows, max(len(rows), 1), 0), warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_container_sizes",
        title="Get container sizes",
        description=(
            "List containers in an environment with their writable-layer and root filesystem "
            "sizes in bytes, largest writable layer first."
        ),
        input_model=SizesInput,
        handler=env_tool(get_container_sizes),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/sizes")),
)

# --- generated compose ------------------------------------------------------------------------


class ComposeInput(ContainerScoped):
    redact_env: bool = Field(
        default=True,
        description=(
            'Replace environment values in the generated compose with "<redacted>" (names '
            "kept). When false, values are returned as-is, including secrets."
        ),
    )


async def generate_container_compose(ctx: ToolContext, args: ComposeInput, env: int) -> Any:
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}/compose", path_params={"id": ref.id}, params={"env": env}
    )
    body = body if isinstance(body, dict) else {}
    compose = body.get("compose")
    compose = compose if isinstance(compose, str) else ""
    # composeFullEnv (every env var, image-inherited ones included) is never passed through.
    return {
        "container": _container(ref),
        "compose": redact_compose_env(compose) if args.redact_env else compose,
        "serviceName": body.get("serviceName"),
        "stackProject": body.get("stackProject"),
        "env_redacted": args.redact_env,
    }


register(
    ToolSpec(
        name="dockhand_generate_container_compose",
        title="Generate container compose",
        description=(
            "Generate a docker-compose service definition from a container's current "
            "configuration; nothing is saved. Environment values are redacted unless redact_env "
            "is false, which returns secret values."
        ),
        input_model=ComposeInput,
        handler=env_tool(generate_container_compose),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref", "redact_env"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}/compose")),
)

# --- updates ----------------------------------------------------------------------------------


class PendingUpdatesInput(EnvScoped):
    pass


def _last_checked(*lists: Any) -> str | None:
    stamps = [
        str(i["checkedAt"])
        for items in lists
        for i in list_body(items)
        if isinstance(i, dict) and i.get("checkedAt")
    ]
    return max(stamps) if stamps else None


async def get_pending_updates(ctx: ToolContext, args: PendingUpdatesInput, env: int) -> Envelope:
    results, errors = await gather_sections(
        {
            "pending_updates": ctx.client.get_json(
                "/api/containers/pending-updates", params={"env": env}
            ),
            "cached_check": ctx.client.get_json(
                "/api/containers/check-updates", params={"env": env}
            ),
        }
    )
    if not results:
        main = errors["pending_updates"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    data: dict[str, Any] = {}
    for section, body in results.items():
        data[section] = body.get("pendingUpdates", []) if isinstance(body, dict) else []
    data["last_checked_at"] = _last_checked(*data.values())
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_get_pending_updates",
        title="Get pending updates",
        description=(
            "List containers with a newer image recorded by DockHand's last update check, with "
            "when that check ran. Does not run a new check."
        ),
        input_model=PendingUpdatesInput,
        handler=env_tool(get_pending_updates),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
    ),
    Tier.READ,
    (
        ENVIRONMENTS,
        ("GET", "/api/containers/pending-updates"),
        ("GET", "/api/containers/check-updates"),
    ),
)


# Docker's tag grammar.
VersionTag = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")]


class VersionNotesInput(ContainerScoped):
    versions: list[VersionTag] = Field(
        min_length=1,
        max_length=10,
        description='Version tags to fetch release notes for, e.g. ["16.4-alpine"].',
    )


async def get_version_notes(ctx: ToolContext, args: VersionNotesInput, env: int) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}/version-notes",
        path_params={"id": ref.id},
        params={"env": env, "versions": ",".join(args.versions)},
        read_timeout=60.0,
    )
    warnings: list[str] = []
    if isinstance(body, dict) and isinstance(body.get("notes"), list):
        notes = []
        for note in body["notes"]:
            if isinstance(note, dict) and isinstance(note.get("body"), str):
                capped = cap_text(note["body"], MAX_NOTE_BYTES, key="body")
                if capped["truncated"]:
                    # Release notes read top-down: keep the head, not the tail.
                    head = note["body"].encode("utf-8")[:MAX_NOTE_BYTES].decode("utf-8", "ignore")
                    note = {**note, "body": head, "body_truncated": True}
                    warnings.append(f"release notes for {note.get('version')} were truncated")
            notes.append(note)
        body = {**body, "notes": notes}
    return ok(
        {"container": _container(ref), **(body if isinstance(body, dict) else {})},
        warnings=warnings,
    )


register(
    ToolSpec(
        name="dockhand_get_version_notes",
        title="Get version notes",
        description=(
            "Get upstream release notes for newer image versions of a container, as found by "
            "DockHand's update check."
        ),
        input_model=VersionNotesInput,
        handler=env_tool(get_version_notes),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "ref"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}/version-notes")),
)

# --- operator tier ----------------------------------------------------------------------------
# Lifecycle endpoints answer only when Docker has finished (a stop can wait out a long grace
# period), so they run as detached operations (ARCHITECTURE §4.3); the container is re-read
# afterwards.


class ContainerWriteInput(EnvWriteInputs):
    ref: str = Field(min_length=1, max_length=255, description=REF_DESCRIPTION)


def _read_timeout(ctx: ToolContext) -> float:
    return float(ctx.settings.max_timeout) + 5.0


async def container_state(ctx: ToolContext, env: int, container_id: str) -> dict[str, Any]:
    """The container's current name, state, status and health, from the list endpoint."""
    body = await ctx.client.get_json("/api/containers", params={"env": env, "all": True})
    for item in list_body(body):
        if isinstance(item, dict) and item.get("id") == container_id:
            return {k: item.get(k) for k in ("name", "state", "status", "health")}
    return {"state": None, "status": "not found after the operation"}


def _lifecycle(action: str) -> Any:
    async def body(ctx: ToolContext, args: ContainerWriteInput, env: int) -> Envelope:
        ref = await resolve_container(ctx.client, env, args.ref)
        budget, warnings = write_budget(ctx, args)

        async def work() -> dict[str, Any]:
            await ctx.client.post_json(
                f"/api/containers/{{id}}/{action}",
                path_params={"id": ref.id},
                params={"env": env},
                read_timeout=_read_timeout(ctx),
            )
            state = await container_state(ctx, env, ref.id)
            return {"container": _container(ref), "action": action, **state}

        envelope = await run_async_pattern(
            "detached",
            ctx,
            wait=args.wait,
            budget_s=budget,
            meta={"action": action, "container": ref.name, "environment_id": env},
            work=work,
        )
        return add_warnings(envelope, warnings)

    return body


LIFECYCLE: Final = {
    "start": ("Start container", "Start a stopped container.", True),
    "stop": ("Stop container", "Stop a running container.", True),
    "restart": ("Restart container", "Restart a container.", False),
    "pause": ("Pause container", "Pause all processes in a running container.", True),
    "unpause": ("Unpause container", "Resume the processes of a paused container.", True),
}

for _action, (_title, _what, _idempotent) in LIFECYCLE.items():
    register(
        ToolSpec(
            name=f"dockhand_{_action}_container",
            title=_title,
            description=f"{_what} Returns the container's state and status afterwards.",
            input_model=ContainerWriteInput,
            handler=env_tool(_lifecycle(_action)),
            annotations=(OPERATOR_IDEMPOTENT_ANNOTATIONS if _idempotent else OPERATOR_ANNOTATIONS),
            audit_args=("environment_id", "ref", "wait"),
        ),
        Tier.OPERATOR,
        (ENVIRONMENTS, LIST, ("POST", f"/api/containers/{{id}}/{_action}")),
    )


class RenameInput(ContainerWriteInput):
    new_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=DOCKER_NAME.pattern,
        description="The new container name (without a leading '/').",
    )


async def rename_container(ctx: ToolContext, args: RenameInput, env: int) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.ref)
    budget, warnings = write_budget(ctx, args)

    async def work() -> dict[str, Any]:
        await ctx.client.post_json(
            "/api/containers/{id}/rename",
            path_params={"id": ref.id},
            params={"env": env},
            json={"name": args.new_name},
        )
        state = await container_state(ctx, env, ref.id)
        return {"container": {"id": ref.id, "previous_name": ref.name}, **state}

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "rename", "container": ref.name, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_rename_container",
        title="Rename container",
        description="Rename a container. Returns its name, state and status afterwards.",
        input_model=RenameInput,
        handler=env_tool(rename_container),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "ref", "new_name", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, LIST, ("POST", "/api/containers/{id}/rename")),
)

# --- image updates ----------------------------------------------------------------------------

OPT_OUT_LABEL: Final = "dockhand.update"
MAX_BATCH_UPDATE: Final = 25


class UpdateContainersInput(EnvWriteInputs):
    refs: list[Annotated[str, StringConstraints(min_length=1, max_length=255)]] = Field(
        min_length=1, max_length=MAX_BATCH_UPDATE, description="Container IDs or exact names."
    )


def _opted_out(inspect: Any) -> bool:
    config = inspect.get("Config") if isinstance(inspect, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    value = labels.get(OPT_OUT_LABEL) if isinstance(labels, dict) else None
    return isinstance(value, str) and value.strip().lower() == "false"


async def update_containers(ctx: ToolContext, args: UpdateContainersInput, env: int) -> Envelope:
    refs = await resolve_containers(ctx.client, env, args.refs)
    inspected, errors = await gather_sections(
        {
            r.id: ctx.client.get_json(
                "/api/containers/{id}", path_params={"id": r.id}, params={"env": env}
            )
            for r in refs
        }
    )
    if errors:
        failed = ", ".join(r.name for r in refs if r.id in errors)
        raise fail("dockhand_http_error", f"could not inspect {failed} to check its labels")
    opted_out = [r.name for r in refs if _opted_out(inspected[r.id])]
    if opted_out:
        raise fail(
            "guardrail_blocked",
            f"refused: {', '.join(opted_out)} carr{'ies' if len(opted_out) == 1 else 'y'} the "
            f"label {OPT_OUT_LABEL}=false; nothing was updated",
        )
    budget, warnings = write_budget(ctx, args)

    async def work() -> Envelope:
        answer = await ctx.client.post_json(
            "/api/containers/batch-update",
            params={"env": env},
            json={"containerIds": [r.id for r in refs]},
            read_timeout=_read_timeout(ctx),
        )
        outcome = interpret_update(answer, [{"id": r.id, "name": r.name} for r in refs])
        data = {
            "containers": [_container(r) for r in refs],
            "result": cap_json(answer),
            "items": outcome.items,
            "summary": outcome.summary,
        }
        if outcome.problem is not None and outcome.code is not None:
            return Envelope(
                ok=False, data=data, error=ErrorInfo(code=outcome.code, message=outcome.problem)
            )
        return ok(data)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "update", "containers": [r.name for r in refs], "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_update_containers",
        title="Update containers",
        description=(
            "Recreate containers with their latest images, keeping their configuration. Refuses "
            "the whole call if any carries the label dockhand.update=false."
        ),
        input_model=UpdateContainersInput,
        handler=env_tool(update_containers),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        LIST,
        ("GET", "/api/containers/{id}"),
        ("POST", "/api/containers/batch-update"),
    ),
)


class CheckUpdatesInput(EnvWriteInputs):
    pass


async def check_container_updates(ctx: ToolContext, args: CheckUpdatesInput, env: int) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    async def finish(result: Any) -> dict[str, Any]:
        pending = await ctx.client.get_json("/api/containers/pending-updates", params={"env": env})
        summary = result if isinstance(result, dict) else {}
        return {
            "check": {k: summary.get(k) for k in ("total", "updatesFound")},
            "pending_updates": (
                pending.get("pendingUpdates", []) if isinstance(pending, dict) else []
            ),
        }

    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "check_updates", "environment_id": env},
        sse=SseRequest("POST", "/api/containers/check-updates", params={"env": env}),
        finish=finish,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_check_container_updates",
        title="Check container updates",
        description=(
            "Run a fresh image-update check for every container in an environment. Returns the "
            "check's counts and the resulting pending updates."
        ),
        input_model=CheckUpdatesInput,
        handler=env_tool(check_container_updates),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        ("POST", "/api/containers/check-updates"),
        ("GET", "/api/containers/pending-updates"),
        JOB_STATUS,
    ),
)


class ClearPendingInput(EnvWriteInputs):
    ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Clear only this container's record; every record in the environment when "
        "omitted.",
    )


async def clear_pending_updates(ctx: ToolContext, args: ClearPendingInput, env: int) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.ref) if args.ref is not None else None
    budget, warnings = write_budget(ctx, args)

    async def work() -> dict[str, Any]:
        answer = await ctx.client.delete_json(
            "/api/containers/pending-updates",
            params={"env": env, "containerId": ref.id if ref is not None else None},
        )
        return {
            "cleared": _container(ref) if ref is not None else "all",
            "result": cap_json(answer),
        }

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "clear_pending_updates", "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_clear_pending_updates",
        title="Clear pending updates",
        description=(
            "Clear DockHand's pending-update records for one container or a whole environment. "
            "Images and containers are not changed."
        ),
        input_model=ClearPendingInput,
        handler=env_tool(clear_pending_updates),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "ref", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, LIST, ("DELETE", "/api/containers/pending-updates")),
)

# Five or six cron fields, made of the characters cron expressions use and nothing else.
CRON: Final = r"^[0-9A-Za-z*?/,#-]+( [0-9A-Za-z*?/,#-]+){4,5}$"


class SetAutoUpdateInput(EnvWriteInputs):
    container_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=DOCKER_NAME.pattern,
        description="Exact container name (or ID).",
    )
    enabled: bool = Field(description="Enable (or change) automatic updates, or remove them.")
    cron: str | None = Field(
        default=None,
        max_length=100,
        pattern=CRON,
        description="With enabled: when to check, as a cron expression.",
    )
    vulnerability_criteria: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^[a-z_]{1,32}$",
        description="With enabled: DockHand's vulnerability criterion for applying an update.",
    )

    @model_validator(mode="after")
    def _only_when_enabled(self) -> SetAutoUpdateInput:
        if not self.enabled and (self.cron or self.vulnerability_criteria):
            raise ValueError("cron and vulnerability_criteria apply only with enabled=true")
        return self


async def set_container_auto_update(
    ctx: ToolContext, args: SetAutoUpdateInput, env: int
) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.container_name)
    budget, warnings = write_budget(ctx, args)
    path = {"containerName": ref.name}

    async def work() -> dict[str, Any]:
        if args.enabled:
            body: dict[str, Any] = {"enabled": True}
            if args.cron is not None:
                body["cronExpression"] = args.cron
            if args.vulnerability_criteria is not None:
                body["vulnerabilityCriteria"] = args.vulnerability_criteria
            answer = await ctx.client.post_json(
                "/api/auto-update/{containerName}", path_params=path, params={"env": env}, json=body
            )
        else:
            answer = await ctx.client.delete_json(
                "/api/auto-update/{containerName}", path_params=path, params={"env": env}
            )
        return {"container": _container(ref), "enabled": args.enabled, "setting": answer}

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "set_auto_update", "container": ref.name, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_set_container_auto_update",
        title="Set container auto-update",
        description=(
            "Enable, change or remove automatic image updates for a container. Returns the "
            "stored setting."
        ),
        input_model=SetAutoUpdateInput,
        handler=env_tool(set_container_auto_update),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "container_name", "enabled", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        LIST,
        ("POST", "/api/auto-update/{containerName}"),
        ("DELETE", "/api/auto-update/{containerName}"),
    ),
)

# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.

# Docker refuses to remove these without force; so do we, before asking anyone.
RUNNING_STATES: Final = frozenset({"running", "paused", "restarting"})
MAX_MOUNTS: Final = 50


class RemoveContainerInput(EnvDestructiveInputs):
    ref: str = Field(min_length=1, max_length=255, description=REF_DESCRIPTION)
    force: bool = Field(default=False, description="Remove the container even while it runs.")


def _mounts(inspect: dict[str, Any]) -> list[dict[str, Any]]:
    mounts = inspect.get("Mounts")
    return [
        {
            "type": m.get("Type"),
            "name": m.get("Name"),
            "source": m.get("Source"),
            "destination": m.get("Destination"),
            "read_write": m.get("RW"),
        }
        for m in (mounts if isinstance(mounts, list) else [])[:MAX_MOUNTS]
        if isinstance(m, dict)
    ]


async def remove_container_preview(
    ctx: ToolContext, args: RemoveContainerInput, env: int | None
) -> Preview:
    env = scoped(env)
    ref = await resolve_container(ctx.client, env, args.ref)
    body = await ctx.client.get_json(
        "/api/containers/{id}", path_params={"id": ref.id}, params={"env": env}
    )
    inspect = as_dict(body)
    state, config = as_dict(inspect.get("State")), as_dict(inspect.get("Config"))
    status = state.get("Status") if isinstance(state.get("Status"), str) else None
    running = state.get("Running") is True or status in RUNNING_STATES
    if running and not args.force:
        raise fail(
            "guardrail_blocked",
            f"{ref.name} is {status or 'running'}: stop it first, or pass force=true to remove "
            "it while it runs. Nothing was done.",
        )
    mounts = _mounts(inspect)
    image = config.get("Image")
    summary = (
        f"Remove container {ref.name} ({ref.id[:12]}) in environment {env}: image {image}, "
        f"state {status}{', removed by force while it runs' if running else ''}. "
        f"{len(mounts)} mount(s); named volumes are kept."
    )
    return Preview(
        summary=summary,
        data={
            "container": _container(ref),
            "image": image,
            "state": status,
            "mounts": mounts,
            "force": args.force,
            "would_remove": True,
        },
        counts={"containers": 1, "mounts": len(mounts)},
        target={"id": ref.id, "name": ref.name},
    )


async def remove_container(
    ctx: ToolContext,
    args: RemoveContainerInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    container = {"id": str(preview.target["id"]), "name": str(preview.target["name"])}
    budget, warnings = write_budget(ctx, args)

    async def work() -> Envelope:
        answer = await ctx.client.delete_json(
            "/api/containers/{id}",
            path_params={"id": container["id"]},
            params={"env": env, "force": args.force},
            read_timeout=_read_timeout(ctx),
        )
        return dockhand_success(answer, {"container": container, "removed": True}, "removal")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "remove", "container": container["name"], "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_remove_container",
        title="Remove container",
        description=(
            "Remove a container after a human approves; a running container needs force. "
            "Returns the removed container's id and name."
        ),
        input_model=RemoveContainerInput,
        preview=remove_container_preview,
        execute=remove_container,
        audit_args=("environment_id", "ref", "force", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers/{id}"), ("DELETE", "/api/containers/{id}")),
)
