# SPDX-License-Identifier: Apache-2.0
"""Scheduled container start and stop (#19): read a container's times, and set or clear them.

DockHand keeps one schedule per container name and environment: a start time and a stop time,
each `HH:MM` (every day) or a five-field cron expression. A PUT replaces both (an empty one is
none) and both empty removes the schedule. The schedule list shows each time as a
`container_start` or `container_stop` schedule with the schedule's id.

The set tool's rails run before any write: the container is resolved in the requested
environment; the times are validated in the spec's two forms (cron field values are DockHand's
check); and a stop is refused for a container DockHand reports as a system container (DockHand
itself or a Hawser agent) and for the container this server runs in
(`guardrails/self_container.py`), since stopping either cuts off management access. The schedule
is then read back and compared.
"""

from typing import Annotated, Any, Final

from pydantic import Field, StringConstraints

from dockhand_mcp.client.envelope import Envelope, ErrorInfo, ok
from dockhand_mcp.guardrails import self_container
from dockhand_mcp.guardrails.names import ContainerRef, resolve_container
from dockhand_mcp.tools._common import (
    EnvScoped,
    EnvWriteInputs,
    add_warnings,
    as_dict,
    env_tool,
    fail,
    run_async_pattern,
    write_budget,
)
from dockhand_mcp.tools.base import (
    OPERATOR_IDEMPOTENT_ANNOTATIONS,
    READ_ANNOTATIONS,
    ToolContext,
    ToolSpec,
)
from dockhand_mcp.tools.containers import LIST, REF_DESCRIPTION
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

SCHEDULE: Final = "/api/scheduled-actions/{containerName}"
TIMES: Final = ("startAt", "stopAt")

# The spec's two forms (PUT summary): HH:MM every day, or five cron fields separated by spaces,
# made of the characters cron expressions use. DockHand also checks the cron fields' values.
_TIME_OF_DAY: Final = r"(?:[01]?[0-9]|2[0-3]):[0-5][0-9]"
_CRON_FIELD: Final = r"[0-9A-Za-z*?/,#-]+"
ACTION_TIME: Final = rf"^(?:{_TIME_OF_DAY}|{_CRON_FIELD}(?: {_CRON_FIELD}){{4}})$"
ActionTime = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=ACTION_TIME)]

SCHEDULE_DATA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "container": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
        },
        "schedule": {
            "type": "object",
            "description": "DockHand's schedule: startAt, stopAt, enabled, source, labelErrors, "
            "systemContainer, lastStarted, lastStopped.",
        },
        "read_back": {"type": "object"},
    },
}


def _container(ref: ContainerRef) -> dict[str, str]:
    return {"id": ref.id, "name": ref.name}


async def _schedule(ctx: ToolContext, ref: ContainerRef, env: int) -> Any:
    return await ctx.client.get_json(
        SCHEDULE, path_params={"containerName": ref.name}, params={"env": env}
    )


class GetScheduledActionsInput(EnvScoped):
    container: str = Field(min_length=1, max_length=255, description=REF_DESCRIPTION)


async def get_scheduled_actions(ctx: ToolContext, args: GetScheduledActionsInput, env: int) -> Any:
    ref = await resolve_container(ctx.client, env, args.container)
    return {"container": _container(ref), "schedule": await _schedule(ctx, ref, env)}


register(
    ToolSpec(
        name="dockhand_get_scheduled_actions",
        title="Get scheduled container start and stop",
        description=(
            "Get a container's scheduled start and stop times, whether the schedule is enabled, "
            "whether its labels set it, and when it last started or stopped on schedule."
        ),
        input_model=GetScheduledActionsInput,
        handler=env_tool(get_scheduled_actions),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "container"),
        data_schema=SCHEDULE_DATA,
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", SCHEDULE)),
)


class SetScheduledActionsInput(EnvWriteInputs):
    container: str = Field(min_length=1, max_length=255, description=REF_DESCRIPTION)
    start: ActionTime | None = Field(
        default=None,
        description="When to start the container: HH:MM (every day) or a five-field cron "
        "expression. Omitted: no scheduled start.",
    )
    stop: ActionTime | None = Field(
        default=None,
        description="When to stop the container: HH:MM (every day) or a five-field cron "
        "expression. Omitted: no scheduled stop.",
    )


def _refuse_stop(ref: ContainerRef, current: Any) -> None:
    """A scheduled stop of DockHand's container or of this server's would cut off management."""
    if as_dict(current).get("systemContainer") is True:
        raise fail(
            "guardrail_blocked",
            f"{ref.name} is a system container (DockHand's own container or a Hawser agent); "
            "stopping it on a schedule would cut off DockHand's management access. Nothing was "
            "done.",
        )
    if self_container.matches(ref.id, self_container.own_container_ids()):
        raise fail(
            "guardrail_blocked",
            f"{ref.name} is the container this MCP server runs in; stopping it on a schedule "
            "would cut off this server. Nothing was done.",
        )


def _time(schedule: Any, key: str) -> str | None:
    value = as_dict(schedule).get(key)
    return value.strip() or None if isinstance(value, str) else None


async def set_scheduled_actions(
    ctx: ToolContext, args: SetScheduledActionsInput, env: int
) -> Envelope:
    ref = await resolve_container(ctx.client, env, args.container)
    current = await _schedule(ctx, ref, env)
    if args.stop is not None:
        _refuse_stop(ref, current)
    budget, warnings = write_budget(ctx, args)
    expected = {"startAt": args.start, "stopAt": args.stop}

    async def work() -> Envelope:
        await ctx.client.put_json(
            SCHEDULE,
            path_params={"containerName": ref.name},
            params={"env": env},
            json={key: value or "" for key, value in expected.items()},
        )
        back = await _schedule(ctx, ref, env)
        actual = {key: _time(back, key) for key in TIMES}
        data = {"container": _container(ref), "schedule": back}
        if actual != expected:
            return Envelope(
                ok=False,
                data={**data, "read_back": {"expected": expected, "actual": actual}},
                verified=False,
                error=ErrorInfo(
                    code="verification_failed",
                    message=(
                        "DockHand accepted the schedule, but reading it back returned other "
                        "times; it may not have been saved"
                    ),
                ),
            )
        return ok(data, verified=True, environment_id=env)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "set_scheduled_actions", "container": ref.name, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_set_scheduled_actions",
        title="Set scheduled container start and stop",
        description=(
            "Set a container's scheduled start and stop times, HH:MM daily or five-field cron; "
            "giving neither removes the schedule. Returns the schedule as read back."
        ),
        input_model=SetScheduledActionsInput,
        handler=env_tool(set_scheduled_actions),
        annotations=OPERATOR_IDEMPOTENT_ANNOTATIONS,
        audit_args=("environment_id", "container", "wait"),
        data_schema=SCHEDULE_DATA,
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, LIST, ("GET", SCHEDULE), ("PUT", SCHEDULE)),
)
