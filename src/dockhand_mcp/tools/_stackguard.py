# SPDX-License-Identifier: Apache-2.0
"""Compose guardrails as the stack tools run them (docs/SECURITY.md §5).

A stack's variables, for interpolation, come from DockHand: the `.env` file (`GET …/env/raw`)
and the stack's variables (`GET …/env`, where secrets are masked as `***` and injected provider
keys have no value). Secrets and provider keys are known only to be set. Variables DockHand's own
process environment supplies at deploy time cannot be seen from here.

The same values let a stack tool redact them from what DockHand answers it (`redactor_for`,
`output_redactor`).

`require_tracked` is the check every write to an existing stack makes first. `GET /api/stacks`
answers the stacks DockHand has a source record for in the environment (with `sourceType`)
together with the compose projects it discovers from container labels on that environment's
Docker daemon (no `sourceType`). When two environments share one daemon, each lists the other's
running stacks that way (seen live, DockHand 1.0.46, S3g), and no item names its environment.
A write goes ahead only for a stack tracked in the requested environment.

`require_unused` is the check `dockhand_create_stack` makes first, against the same list: a new
stack's name must not already be a compose project on the daemon, tracked or not. DockHand runs
compose with the stack name as the project name and accepts a duplicate created through another
environment on the same daemon, which then shares that environment's containers (seen live,
DockHand 1.0.46, #19). It also reads every container on the daemon, stopped ones included
(`GET /api/containers?all=true`, whose items carry `labels`), and refuses a name matching any
`com.docker.compose.project` label: the label is on stopped containers too, so a project is
caught even if DockHand stopped listing it as a stack (#21; live 1.0.46 still listed a project
whose containers were all stopped).
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.redaction import OutputRedactor
from dockhand_mcp.guardrails import compose
from dockhand_mcp.guardrails.compose import MASKED, Finding, Mode, Variables
from dockhand_mcp.guardrails.dotenv import entries, parse_dotenv
from dockhand_mcp.guardrails.secrets import MASKED as MASKED_VALUE
from dockhand_mcp.tools._common import fail, gather_sections, list_body
from dockhand_mcp.tools.base import ToolContext

LIST: Final = ("GET", "/api/stacks")
COMPOSE: Final = ("GET", "/api/stacks/{name}/compose")
ENV_RAW: Final = ("GET", "/api/stacks/{name}/env/raw")
ENV_VARS: Final = ("GET", "/api/stacks/{name}/env")
VALIDATE: Final = ("POST", "/api/stacks/{name}/validate")
CONTAINERS: Final = ("GET", "/api/containers")
PROJECT_LABEL: Final = "com.docker.compose.project"


def mode(ctx: ToolContext) -> Mode:
    return ctx.settings.guardrails


def is_tracked(item: Mapping[str, Any]) -> bool:
    """Whether a `GET /api/stacks` item has a source record in the environment it was listed for."""
    source = item.get("sourceType")
    return isinstance(source, str) and bool(source)


async def require_tracked(ctx: ToolContext, stack: str, env: int) -> dict[str, Any]:
    """The stack's list item in `env`; `not_found` unless DockHand tracks it there."""
    for item in list_body(await ctx.client.get_json(LIST[1], params={"env": env})):
        if isinstance(item, dict) and item.get("name") == stack:
            if is_tracked(item):
                return item
            raise fail(
                "not_found",
                f"stack {stack} is not tracked in environment {env}: DockHand lists it only as a "
                "compose project running on that environment's Docker host, which can be "
                "another environment's stack on a shared host; nothing was done",
            )
    raise fail("not_found", f"stack {stack} not found in environment {env}")


_NOT_PROJECT_CHARS: Final = re.compile(r"[^a-z0-9_-]")


def project_name(name: str) -> str:
    """Docker Compose's project-name normalisation (compose-go `loader.NormalizeProjectName`):
    lowercase, keep only `[a-z0-9_-]`, then trim leading `_` and `-`."""
    return _NOT_PROJECT_CHARS.sub("", name.lower()).lstrip("_-")


def _listed_match(items: Sequence[Any], wanted: str) -> dict[str, Any] | None:
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and project_name(name) == wanted:
            return item
    return None


def _label_match(containers: Sequence[Any], wanted: str) -> str | None:
    for item in containers:
        labels = item.get("labels") if isinstance(item, dict) else None
        project = labels.get(PROJECT_LABEL) if isinstance(labels, dict) else None
        if isinstance(project, str) and project_name(project) == wanted:
            return project
    return None


async def require_unused(ctx: ToolContext, stack: str, env: int) -> None:
    """`validation_error` if `stack` names a compose project `env` lists, tracked or not, or
    one that any of its containers, running or stopped, is labelled with."""
    wanted = project_name(stack)
    listed = _listed_match(
        list_body(await ctx.client.get_json(LIST[1], params={"env": env})), wanted
    )
    labelled = _label_match(
        list_body(await ctx.client.get_json(CONTAINERS[1], params={"env": env, "all": True})),
        wanted,
    )
    sources: list[str] = []
    if listed is not None:
        sources.append(
            f"found in the stack list, tracked in environment {env}"
            if is_tracked(listed)
            else f"found in the stack list, not tracked in environment {env}: a compose project "
            "on its Docker host, which can be another environment's stack on a shared host"
        )
    if labelled is not None:
        sources.append(
            f"found in container labels: containers on environment {env}'s Docker host, "
            "running or stopped, belong to it"
        )
    if not sources:
        return
    name = listed["name"] if listed is not None else labelled
    raise fail(
        "validation_error",
        f"stack name {stack} is already in use on this Docker daemon as compose project "
        f"{name} ({'; '.join(sources)}); choose another name; nothing was done",
    )


@dataclass(frozen=True)
class StackEnv:
    """What DockHand holds for a stack's environment."""

    raw: str
    no_env_file: bool
    variables: list[dict[str, Any]]
    injected: list[str]


def _stack(ctx: ToolContext, template: str, stack: str, env: int) -> Any:
    return ctx.client.get_json(template, path_params={"name": stack}, params={"env": env})


async def fetch_stack_env(ctx: ToolContext, stack: str, env: int) -> StackEnv:
    results, errors = await gather_sections(
        {
            "raw": _stack(ctx, ENV_RAW[1], stack, env),
            "vars": _stack(ctx, ENV_VARS[1], stack, env),
        }
    )
    if errors:
        raise_first(errors)
    raw = results["raw"] if isinstance(results["raw"], dict) else {}
    body = results["vars"] if isinstance(results["vars"], dict) else {}
    content = raw.get("content")
    return StackEnv(
        raw=content if isinstance(content, str) else "",
        no_env_file=raw.get("noEnvFile") is True,
        variables=[v for v in list_body(body.get("variables")) if isinstance(v, dict)],
        injected=[k for k in list_body(body.get("injectedSecretKeys")) if isinstance(k, str)],
    )


def _file_values(raw: str, *, lenient: bool) -> list[Any]:
    """A `.env` file's values, as written and as interpolated. `lenient`: for a file that does
    not parse, the text after each line's first `=` instead of the parse error."""
    try:
        written = [e.value for e in entries(raw) if e.key is not None]
        return [*written, *parse_dotenv(raw).values()]
    except DockhandError:
        if not lenient:
            raise
        return [line.partition("=")[2].strip() for line in raw.splitlines() if "=" in line]


def redactor_for(stack_env: StackEnv, *new_raws: str, lenient: bool = False) -> OutputRedactor:
    """A redactor that also masks a stack's own values: its `.env` file's, any new `.env`
    content a write is about to save (`new_raws`), and DockHand's stored variables'.

    `OutputRedactor` keeps those of at least 8 characters other than DockHand's `***` mask. They
    live only in the returned redactor, for this call, and are never logged.
    """
    values: list[Any] = []
    for raw in (stack_env.raw, *new_raws):
        values += _file_values(raw, lenient=lenient)
    values += [item.get("value") for item in stack_env.variables]
    return OutputRedactor.for_values(values)


async def output_redactor(ctx: ToolContext, stack: str, env: int) -> OutputRedactor:
    """A redactor for a stack operation's output that also masks the stack's own values
    (`redactor_for`). A DockHand error propagates: an operation whose output can't be redacted
    is not started.
    """
    return redactor_for(await fetch_stack_env(ctx, stack, env))


def raise_first(errors: Mapping[str, Mapping[str, Any]]) -> None:
    first = next(iter(errors.values()))
    raise DockhandError(first.get("dockhand_status"), first["code"], first["message"])


def stack_variables(raw_env: str, stack_env: StackEnv) -> dict[str, Any]:
    """Variables for interpolation: `.env` values over DockHand's plain ones, secrets masked."""
    values: dict[str, Any] = {}
    secret: set[str] = set(stack_env.injected)
    for item in stack_env.variables:
        key, value = item.get("key"), item.get("value")
        if not isinstance(key, str):
            continue
        if item.get("isSecret") is True or value == MASKED_VALUE:
            secret.add(key)
        elif isinstance(value, str):
            values[key] = value
    values.update(parse_dotenv(raw_env, base=values))
    for key in secret:
        values[key] = MASKED
    return values


def check(ctx: ToolContext, text: str, variables: Variables | None) -> list[Finding]:
    return compose.check_compose(
        text, allow_bind=ctx.settings.guardrail_allow_bind, variables=variables
    )


def check_document(
    ctx: ToolContext, doc: dict[str, Any], variables: Variables | None
) -> list[Finding]:
    return compose.check_document(
        doc, allow_bind=ctx.settings.guardrail_allow_bind, variables=variables
    )


async def dockhand_validate(
    ctx: ToolContext, stack: str, env: int, content: str, *, existing: bool
) -> dict[str, Any]:
    body = await ctx.client.post_json(
        VALIDATE[1],
        path_params={"name": stack},
        params={"env": env},
        json={"compose": content, "existing": existing},
    )
    return body if isinstance(body, dict) else {}


def dockhand_error_count(body: Mapping[str, Any]) -> int:
    counts = body.get("counts")
    if isinstance(counts, dict) and isinstance(counts.get("error"), int):
        return int(counts["error"])
    return sum(
        1
        for f in list_body(body.get("findings"))
        if isinstance(f, dict) and f.get("severity") == "error"
    )


def section(
    findings: Sequence[Finding], mode_: Mode, dockhand: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The `guardrails` part of a result: ours, plus DockHand's validator when it ran."""
    out = compose.report(findings, mode_)
    if dockhand is not None:
        dh_errors = dockhand_error_count(dockhand)
        out["dockhand"] = {
            "counts": dockhand.get("counts"),
            "findings": list_body(dockhand.get("findings")),
        }
        out["blocked"] = out["blocked"] or (mode_ == "strict" and dh_errors > 0)
    return out


def invalid_document(message: str) -> list[Finding]:
    """A report-only stand-in for a document the guardrails could not parse."""
    return [Finding("invalid_document", "error", None, "", message)]
