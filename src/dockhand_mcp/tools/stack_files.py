# SPDX-License-Identifier: Apache-2.0
"""Stack writes that persist content: compose file, `.env` file, new stacks (operator tier).

Every one of them, in order, before anything is written:
1. refuses content carrying `<redacted>` or `***` (the placeholder write-back guard);
2. runs the compose guardrails with the stack's real variables (docs/SECURITY.md §5) and, for
   compose writes, DockHand's own validator; in `strict` mode an error finding refuses the write.
   An `.env` write is refused only for errors it introduces (a variable that makes an existing
   bind source resolve into a denied path, say), not for ones the stack already had.

DockHand's answers to these writes (and its validator's findings) are redacted in the client
with the stack's own values too: the `.env` file's, any new `.env` content, DockHand's stored
variables, or for a new stack its `env_vars` (`client/redaction.py`).

Then the write, then read-back verification: the content is fetched again and compared byte for
byte, and a mismatch is a failure (`ok: false`, `verified: false`, `error.code`
`verification_failed`) with a diff summary that holds counts and line numbers only. DockHand has
been seen to accept a compose PUT and keep the old content. Only `content` (plus the redeploy
flags) is ever sent to `PUT …/compose`: never paths, relocation fields or a secret provider.

A compose write with `redeploy` and a create with `start` are compound: one DockHand request
saves, then deploys. When DockHand answers `success: false` and the content reads back
verified, the save happened and the deploy did not: `ok: false`, `operation_failed`, with
`data.steps` and `saved` / `created` true. Nothing is rolled back.

A write that fails after it was sent (a 5xx, or a connection lost once the request went out) is
read back once, because DockHand may have saved the content before failing (#17): saved ->
`operation_failed` with `data.saved: true`; not saved (for a create: no stack) ->
`dockhand_http_error` with `saved: false`; the read-back failing -> `saved: "unknown"`. Compound
writes add a `read_back` step. A 4xx, or a connection never made, is returned as it was.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Final

from pydantic import ConfigDict, Field, StringConstraints, model_validator

from dockhand_mcp.client.envelope import Envelope, ErrorInfo, ok
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.redaction import OutputRedactor, redacting
from dockhand_mcp.guardrails import compose
from dockhand_mcp.guardrails.dotenv import edit_dotenv, entries
from dockhand_mcp.tools import _stackguard as stackguard
from dockhand_mcp.tools._common import (
    ENV_RECREATE_WARNING,
    EnvWriteInputs,
    SaveCheck,
    Saved,
    ToolInput,
    add_warnings,
    answer_failed,
    answer_message,
    cap_json,
    check_saved,
    env_tool,
    fail,
    gather_sections,
    may_have_written,
    partial_failure,
    read_back_step,
    read_back_verify,
    refuse_placeholders,
    run_async_pattern,
    step,
    verification_failed,
    write_budget,
    write_error,
)
from dockhand_mcp.tools.base import OPERATOR_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register
from dockhand_mcp.tools.stacks import (
    ENV_KEY,
    MAX_COMPOSE_CHARS,
    MAX_ENV_VALUE,
    MAX_ENV_VARS,
    STACK_DESCRIPTION,
    StackName,
)

MAX_ENV_FILE_CHARS: Final = 512 * 1024
MAX_EDITS: Final = 100
# Headroom over DOCKHAND_MCP_MAX_TIMEOUT for a synchronous write that also redeploys.
WRITE_TIMEOUT_MARGIN_S: Final = 5.0
PUT_COMPOSE: Final = ("PUT", "/api/stacks/{name}/compose")
PUT_ENV_RAW: Final = ("PUT", "/api/stacks/{name}/env/raw")
CREATE: Final = ("POST", "/api/stacks")

EnvKey = Annotated[str, StringConstraints(pattern=ENV_KEY)]
# One line of text: no control characters other than tab.
EnvValue = Annotated[
    str, StringConstraints(max_length=MAX_ENV_VALUE, pattern=r"^[^\x00-\x08\x0a-\x1f\x7f]*$")
]


# Content is sent and verified exactly as given: no whitespace stripping.
VERBATIM: Final = ConfigDict(extra="forbid", str_strip_whitespace=False)


def _guard_refusal(data: dict[str, Any], what: str) -> Envelope:
    counts = data["guardrails"]["counts"]
    dockhand = data["guardrails"].get("dockhand")
    dh_errors = stackguard.dockhand_error_count(dockhand) if dockhand is not None else 0
    return Envelope(
        ok=False,
        data=data,
        error=ErrorInfo(
            code="guardrail_blocked",
            message=(
                f"The {what} was refused: {counts['error']} guardrail error(s) and {dh_errors} "
                "DockHand validator error(s); nothing was written. See data.guardrails."
            ),
        ),
    )


def _read_timeout(ctx: ToolContext) -> float:
    return float(ctx.settings.max_timeout) + WRITE_TIMEOUT_MARGIN_S


async def _content(ctx: ToolContext, template: str, stack: str, env: int) -> str:
    body = await ctx.client.get_json(template, path_params={"name": stack}, params={"env": env})
    content = body.get("content") if isinstance(body, dict) else None
    return content if isinstance(content, str) else ""


# --- compose ----------------------------------------------------------------------------------


class UpdateComposeInput(EnvWriteInputs):
    model_config = VERBATIM

    stack: StackName = Field(description=STACK_DESCRIPTION)
    content: str = Field(
        min_length=1, max_length=MAX_COMPOSE_CHARS, description="The complete new compose file."
    )
    redeploy: bool = Field(default=False, description="Redeploy the stack after saving.")
    pull: bool = Field(default=False, description="With redeploy: pull images first.")
    force_recreate: bool = Field(
        default=False, description="With redeploy: recreate containers even if unchanged."
    )

    @model_validator(mode="after")
    def _redeploy_flags(self) -> UpdateComposeInput:
        if (self.pull or self.force_recreate) and not self.redeploy:
            raise ValueError("pull and force_recreate apply only with redeploy=true")
        return self


async def update_stack_compose(ctx: ToolContext, args: UpdateComposeInput, env: int) -> Envelope:
    refuse_placeholders({"content": args.content})
    doc = compose.load_compose(args.content)
    budget, warnings = write_budget(ctx, args)
    await stackguard.require_tracked(ctx, args.stack, env)
    stack_env = await stackguard.fetch_stack_env(ctx, args.stack, env)
    variables = stackguard.stack_variables(stack_env.raw, stack_env)
    findings = stackguard.check_document(ctx, doc, variables)
    redactor = stackguard.redactor_for(stack_env)
    with redacting(redactor):
        dockhand = await stackguard.dockhand_validate(
            ctx, args.stack, env, args.content, existing=True
        )
    data: dict[str, Any] = {
        "stack": args.stack,
        "guardrails": stackguard.section(findings, stackguard.mode(ctx), dockhand),
    }
    if data["guardrails"]["blocked"]:
        return _guard_refusal(data, "compose file")
    body: dict[str, Any] = {"content": args.content}
    if args.redeploy:
        body.update({"restart": True, "pull": args.pull, "forceRecreate": args.force_recreate})

    def read_back() -> Awaitable[str]:
        return _content(ctx, stackguard.COMPOSE[1], args.stack, env)

    async def work() -> Envelope:
        try:
            answer = await ctx.client.put_json(
                PUT_COMPOSE[1],
                path_params={"name": args.stack},
                params={"env": env},
                json=body,
                read_timeout=_read_timeout(ctx),
            )
        except DockhandError as e:
            if not may_have_written(e):
                raise
            check = await check_saved(args.content, read_back)
            return _compose_error(e, check, data, redeploy=args.redeploy)
        verified, diff = await read_back_verify(args.content, read_back)
        redeploy_failed = args.redeploy and answer_failed(answer)
        result = {
            **data,
            "redeployed": args.redeploy and not redeploy_failed,
            "dockhand": cap_json(answer),
        }
        if diff is not None:
            return verification_failed("compose file", diff, result)
        if not args.redeploy:
            return ok(result, verified=verified, environment_id=env)
        result |= {
            "saved": True,
            "steps": [
                step("save", True, verified=verified),
                step(
                    "redeploy",
                    not redeploy_failed,
                    answer_message(answer) if redeploy_failed else None,
                ),
            ],
        }
        if redeploy_failed:
            return partial_failure(
                "DockHand saved the compose file (read back and verified) but could not "
                "redeploy the stack; see data.steps. The file is saved: redeploy after fixing "
                "the cause rather than saving it again.",
                result,
                verified=verified,
            )
        return ok(result, verified=verified, environment_id=env)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "update_compose", "stack": args.stack, "environment_id": env},
        work=work,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


def _unless_unknown(saved: Saved) -> bool | None:
    return None if saved == "unknown" else bool(saved)


def _compose_error(
    e: DockhandError, check: SaveCheck, data: dict[str, Any], *, redeploy: bool
) -> Envelope:
    """A compose PUT that failed after it was sent, from its read-back."""
    if not redeploy:
        return write_error(e, check, data, "compose file", "do not save it again")
    saved = _unless_unknown(check.saved)
    result = {
        **data,
        "redeployed": False,
        "steps": [
            step("save", saved, verified=True if saved else None),
            # DockHand saves before it deploys: with the file unsaved the redeploy never ran.
            step("redeploy", None if saved is None else False, e.message if saved else None),
            read_back_step(check),
        ],
    }
    return write_error(
        e,
        check,
        result,
        "compose file",
        "redeploy the stack after fixing the cause rather than saving it again",
    )


register(
    ToolSpec(
        name="dockhand_update_stack_compose",
        title="Update stack compose",
        description=(
            "Replace a stack's compose file after compose guardrail and DockHand validation, "
            "optionally redeploying, and verify the saved file by reading it back."
        ),
        input_model=UpdateComposeInput,
        handler=env_tool(update_stack_compose),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "stack", "redeploy", "pull", "force_recreate", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        stackguard.ENV_RAW,
        stackguard.ENV_VARS,
        stackguard.VALIDATE,
        PUT_COMPOSE,
        stackguard.COMPOSE,
    ),
)

# --- .env -------------------------------------------------------------------------------------


async def _current(ctx: ToolContext, stack: str, env: int) -> tuple[stackguard.StackEnv, str]:
    """The stack's current environment and compose file, fetched together."""
    results, errors = await gather_sections(
        {
            "env": stackguard.fetch_stack_env(ctx, stack, env),
            "compose": _content(ctx, stackguard.COMPOSE[1], stack, env),
        }
    )
    if errors:
        stackguard.raise_first(errors)
    return results["env"], results["compose"]


def _env_guard(
    ctx: ToolContext, stack_env: stackguard.StackEnv, compose_text: str, new_raw: str
) -> dict[str, Any]:
    """The guardrail section for replacing the stack's `.env` with `new_raw`: new findings only."""
    try:
        doc = compose.load_compose(compose_text)
    except DockhandError as e:
        raise fail(
            "guardrail_blocked",
            f"the stack's compose file could not be checked ({e.message}), so no .env change "
            "is made",
        ) from None
    after = stackguard.check_document(ctx, doc, stackguard.stack_variables(new_raw, stack_env))
    try:
        before_vars = stackguard.stack_variables(stack_env.raw, stack_env)
    except DockhandError:
        before = []  # the current file does not parse: every finding counts as new
    else:
        before = stackguard.check_document(ctx, doc, before_vars)
    introduced = compose.new_findings(before, after)
    section = stackguard.section(introduced, stackguard.mode(ctx))
    section["scope"] = "findings this change introduces"
    return section


async def _write_env(
    ctx: ToolContext,
    args: EnvWriteInputs,
    stack: str,
    env: int,
    new_raw: str,
    data: dict[str, Any],
    action: str,
    redactor: OutputRedactor,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)

    def read_back() -> Awaitable[str]:
        return _content(ctx, stackguard.ENV_RAW[1], stack, env)

    async def work() -> Envelope:
        try:
            answer = await ctx.client.put_json(
                PUT_ENV_RAW[1],
                path_params={"name": stack},
                params={"env": env},
                json={"content": new_raw},
            )
        except DockhandError as e:
            if not may_have_written(e):
                raise
            check = await check_saved(new_raw, read_back)
            failed = write_error(e, check, data, ".env file", "do not save it again")
            if check.saved is True:
                return failed.model_copy(update={"warnings": [ENV_RECREATE_WARNING]})
            return failed
        verified, diff = await read_back_verify(new_raw, read_back)
        result = {**data, "dockhand": cap_json(answer)}
        if diff is not None:
            failed = verification_failed(".env file", diff, result)
            return failed.model_copy(update={"warnings": [ENV_RECREATE_WARNING]})
        return ok(result, verified=verified, environment_id=env, warnings=[ENV_RECREATE_WARNING])

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": action, "stack": stack, "environment_id": env},
        work=work,
        redactor=redactor,
    )
    if envelope.ok and envelope.verified is None:
        # Not finished yet (wait=false or a timeout): the reminder still applies once it is.
        envelope = add_warnings(envelope, [ENV_RECREATE_WARNING])
    return add_warnings(envelope, warnings)


class UpdateEnvRawInput(EnvWriteInputs):
    model_config = VERBATIM

    stack: StackName = Field(description=STACK_DESCRIPTION)
    content: str = Field(
        max_length=MAX_ENV_FILE_CHARS, description="The complete new .env file content."
    )
    allow_empty: bool = Field(
        default=False, description="Allow empty content, which deletes the .env file."
    )


async def update_stack_env_raw(ctx: ToolContext, args: UpdateEnvRawInput, env: int) -> Envelope:
    refuse_placeholders({"content": args.content})
    if args.content == "" and not args.allow_empty:
        raise fail(
            "validation_error", "empty content deletes the .env file; set allow_empty to do that"
        )
    entries(args.content)  # refuse a file compose could not read, before any request
    await stackguard.require_tracked(ctx, args.stack, env)
    stack_env, compose_text = await _current(ctx, args.stack, env)
    section = _env_guard(ctx, stack_env, compose_text, args.content)
    data: dict[str, Any] = {
        "stack": args.stack,
        "bytes": len(args.content.encode("utf-8")),
        "lines": len(args.content.splitlines()),
        "guardrails": section,
    }
    if section["blocked"]:
        return _guard_refusal(data, ".env change")
    # Lenient: replacing a current .env file that does not parse is allowed.
    redactor = stackguard.redactor_for(stack_env, args.content, lenient=True)
    return await _write_env(
        ctx, args, args.stack, env, args.content, data, "update_env_raw", redactor
    )


register(
    ToolSpec(
        name="dockhand_update_stack_env_raw",
        title="Replace stack .env file",
        description=(
            "Replace a stack's .env file with new raw content after compose guardrail checks, "
            "and verify it by reading it back. Empty content deletes the file only with "
            "allow_empty."
        ),
        input_model=UpdateEnvRawInput,
        handler=env_tool(update_stack_env_raw),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "stack", "allow_empty", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        stackguard.ENV_RAW,
        stackguard.ENV_VARS,
        stackguard.COMPOSE,
        PUT_ENV_RAW,
    ),
)


class ModifyEnvInput(EnvWriteInputs):
    model_config = VERBATIM

    stack: StackName = Field(description=STACK_DESCRIPTION)
    set_vars: dict[EnvKey, EnvValue] | None = Field(
        default=None,
        max_length=MAX_EDITS,
        description="Variables to set, by name; existing ones keep their place in the file.",
    )
    rename: dict[EnvKey, EnvKey] | None = Field(
        default=None, max_length=MAX_EDITS, description="Variables to rename, old name to new."
    )
    delete: list[EnvKey] | None = Field(
        default=None, max_length=MAX_EDITS, description="Variables to remove."
    )

    @model_validator(mode="after")
    def _something(self) -> ModifyEnvInput:
        if not (self.set_vars or self.rename or self.delete):
            raise ValueError("give at least one of set_vars, rename or delete")
        return self


async def modify_stack_env(ctx: ToolContext, args: ModifyEnvInput, env: int) -> Envelope:
    refuse_placeholders(
        {f"set_vars.{k}": v for k, v in (args.set_vars or {}).items()}
        | {f"rename.{k}": v for k, v in (args.rename or {}).items()}
    )
    await stackguard.require_tracked(ctx, args.stack, env)
    stack_env, compose_text = await _current(ctx, args.stack, env)
    edit = edit_dotenv(
        stack_env.raw, set_vars=args.set_vars, rename=args.rename, delete=args.delete
    )
    section = _env_guard(ctx, stack_env, compose_text, edit.text)
    data: dict[str, Any] = {"stack": args.stack, "changes": edit.diff(), "guardrails": section}
    if section["blocked"]:
        return _guard_refusal(data, ".env change")
    redactor = stackguard.redactor_for(stack_env, edit.text)
    return await _write_env(ctx, args, args.stack, env, edit.text, data, "modify_env", redactor)


register(
    ToolSpec(
        name="dockhand_modify_stack_env",
        title="Modify stack .env variables",
        description=(
            "Set, rename or delete variables in a stack's .env file, keeping comments and order, "
            "and verify the result by reading it back. Returns which keys changed."
        ),
        input_model=ModifyEnvInput,
        handler=env_tool(modify_stack_env),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "stack", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        stackguard.ENV_RAW,
        stackguard.ENV_VARS,
        stackguard.COMPOSE,
        PUT_ENV_RAW,
    ),
)

# --- create -----------------------------------------------------------------------------------

SECRETS_NOTE: Final = (
    "Secret values given in env_vars passed through the model's context; DockHand now stores them "
    "as secrets."
)


class EnvVar(ToolInput):
    model_config = VERBATIM

    key: EnvKey = Field(description="Variable name.")
    value: EnvValue = Field(description="Variable value.")
    is_secret: bool = Field(
        default=False, alias="isSecret", description="Store as a DockHand secret."
    )


class CreateStackInput(EnvWriteInputs):
    model_config = VERBATIM

    name: StackName = Field(description="Name of the new stack.")
    compose: str = Field(
        min_length=1, max_length=MAX_COMPOSE_CHARS, description="The compose file content."
    )
    env_vars: list[EnvVar] | None = Field(
        default=None, max_length=MAX_ENV_VARS, description="Variables for the stack."
    )
    start: bool = Field(default=False, description="Deploy the stack once created.")
    pull: bool = Field(default=False, description="With start: pull images first.")

    @model_validator(mode="after")
    def _checks(self) -> CreateStackInput:
        keys = [v.key for v in self.env_vars or []]
        repeated = sorted({k for k in keys if keys.count(k) > 1})
        if repeated:
            raise ValueError(f"env_vars repeats {', '.join(repeated)}")
        if self.pull and not self.start:
            raise ValueError("pull applies only with start=true")
        return self


def _env_mismatch(expected: list[EnvVar], body: Any) -> dict[str, Any] | None:
    """Key names that DockHand does not report back as written; None when all match."""
    items = body.get("variables") if isinstance(body, dict) else None
    got = {
        str(i.get("key")): i
        for i in (items if isinstance(items, list) else [])
        if isinstance(i, dict)
    }
    missing = [v.key for v in expected if v.key not in got]
    differs = [
        v.key
        for v in expected
        if v.key in got and not v.is_secret and got[v.key].get("value") != v.value
    ]
    if not missing and not differs:
        return None
    return {"missing_keys": missing, "different_keys": differs}


async def _create_error(
    e: DockhandError,
    check: SaveCheck,
    data: dict[str, Any],
    start: bool,
    variables_mismatch: Callable[[], Awaitable[dict[str, Any] | None]],
) -> Envelope:
    """A create that failed after it was sent, from its read-back. A stack that was created has
    its variables checked too, as after a successful create."""
    result: dict[str, Any] = {**data, "created": check.saved, "started": False}
    if start:
        created = _unless_unknown(check.saved)
        result["steps"] = [
            step("create", created, verified=True if created else None),
            step("start", None if created is None else False, e.message if created else None),
            read_back_step(check),
        ]
    envelope = write_error(
        e,
        check,
        result,
        "new stack",
        "deploy it after fixing the cause rather than creating it again"
        if start
        else "do not create it again",
    )
    if check.saved is not True:
        return envelope
    try:
        mismatch = await variables_mismatch()
    except DockhandError as read_error:
        # The stack was created either way: say so, with the variables unverified.
        unread = f"The stack's variables could not be read back ({read_error.message})."
        return add_warnings(envelope.model_copy(update={"verified": None}), [unread])
    if mismatch is None:
        return envelope
    return envelope.model_copy(
        update={"verified": False, "data": {**envelope.data, "read_back": mismatch}}
    )


async def create_stack(ctx: ToolContext, args: CreateStackInput, env: int) -> Envelope:
    env_vars = args.env_vars or []
    refuse_placeholders(
        {"compose": args.compose} | {f"env_vars.{v.key}": v.value for v in env_vars}
    )
    doc = compose.load_compose(args.compose)
    await stackguard.require_unused(ctx, args.name, env)
    budget, warnings = write_budget(ctx, args)
    findings = stackguard.check_document(ctx, doc, {v.key: v.value for v in env_vars})
    # The new stack's values are the ones given here.
    redactor = OutputRedactor.for_values(v.value for v in env_vars)
    with redacting(redactor):
        dockhand = await stackguard.dockhand_validate(
            ctx, args.name, env, args.compose, existing=False
        )
    data: dict[str, Any] = {
        "stack": args.name,
        "guardrails": stackguard.section(findings, stackguard.mode(ctx), dockhand),
    }
    if data["guardrails"]["blocked"]:
        return _guard_refusal(data, "stack")
    if any(v.is_secret for v in env_vars):
        warnings.append(SECRETS_NOTE)
    body: dict[str, Any] = {"name": args.name, "compose": args.compose, "start": args.start}
    if env_vars:
        body["envVars"] = [
            {"key": v.key, "value": v.value, "isSecret": v.is_secret} for v in env_vars
        ]
    if args.start:
        body["pull"] = args.pull

    def read_back() -> Awaitable[str]:
        return _content(ctx, stackguard.COMPOSE[1], args.name, env)

    async def variables_mismatch() -> dict[str, Any] | None:
        if not env_vars:
            return None
        saved = await ctx.client.get_json(
            stackguard.ENV_VARS[1], path_params={"name": args.name}, params={"env": env}
        )
        return _env_mismatch(env_vars, saved)

    async def work() -> Envelope:
        try:
            answer = await ctx.client.post_json(
                CREATE[1], params={"env": env}, json=body, read_timeout=_read_timeout(ctx)
            )
        except DockhandError as e:
            if not may_have_written(e):
                raise
            # The name was unused (require_unused): no stack means nothing was created, and a
            # stack with other content is not known to be this call's.
            check = await check_saved(args.compose, read_back, absent=False, differs="unknown")
            return await _create_error(e, check, data, args.start, variables_mismatch)
        start_failed = args.start and answer_failed(answer)
        result = {
            **data,
            "started": args.start and not start_failed,
            "dockhand": cap_json(answer),
        }
        verified, diff = await read_back_verify(args.compose, read_back)
        if diff is not None:
            return verification_failed("compose file", diff, result)
        if env_vars:
            mismatch = await variables_mismatch()
            if mismatch is not None:
                return Envelope(
                    ok=False,
                    data={**result, "read_back": mismatch},
                    verified=False,
                    error=ErrorInfo(
                        code="verification_failed",
                        message="DockHand created the stack, but reading its variables back did "
                        "not match what was sent; see data.read_back",
                    ),
                )
        if not args.start:
            return ok(result, verified=verified, environment_id=env)
        result |= {
            "created": True,
            "steps": [
                step("create", True, verified=verified),
                step("start", not start_failed, answer_message(answer) if start_failed else None),
            ],
        }
        if start_failed:
            return partial_failure(
                "DockHand created the stack (read back and verified) but could not start it; "
                "see data.steps. The stack exists: deploy it after fixing the cause rather than "
                "creating it again.",
                result,
                verified=verified,
            )
        return ok(result, verified=verified, environment_id=env)

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "create_stack", "stack": args.name, "environment_id": env},
        work=work,
        redactor=redactor,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_create_stack",
        title="Create stack",
        description=(
            "Create a compose stack after compose guardrail and DockHand validation, optionally "
            "starting it, and verify what was saved. Secret values given here pass through the "
            "model's context."
        ),
        input_model=CreateStackInput,
        handler=env_tool(create_stack),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "name", "start", "pull", "wait"),
    ),
    Tier.OPERATOR,
    (
        ENVIRONMENTS,
        stackguard.LIST,
        stackguard.CONTAINERS,
        stackguard.VALIDATE,
        CREATE,
        stackguard.COMPOSE,
        stackguard.ENV_VARS,
    ),
)
