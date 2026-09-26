# SPDX-License-Identifier: Apache-2.0
"""Git repository and git stack tools: reads; sync and deploy (operator).

`GET /api/git/stacks/{id}/env-files` lists file names only; the `POST` on the same path (parsed
env values) is excluded and never called. Webhook secrets in these payloads are redacted by the
dispatcher's key-based pass (guardrails/secrets.py).
"""

from typing import Any

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, ErrorInfo, err, ok
from dockhand_mcp.guardrails.names import MAX_ENV_ID
from dockhand_mcp.tools._common import (
    JOB_STATUS,
    SseRequest,
    ToolInput,
    WriteInputs,
    add_warnings,
    cap_json,
    gather_sections,
    list_body,
    run_async_pattern,
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


def _id_field(what: str) -> Any:
    return Field(default=None, ge=1, le=2**31 - 1, description=f"One {what}; all when omitted.")


class GitRepositoriesInput(ToolInput):
    repository_id: int | None = _id_field("repository")
    check_upstream: bool = Field(
        default=False,
        description="With repository_id: also check whether the branch has new upstream commits.",
    )


async def list_git_repositories(ctx: ToolContext, args: GitRepositoriesInput) -> Envelope:
    if args.repository_id is None:
        if args.check_upstream:
            return err("validation_error", "check_upstream needs repository_id")
        items = list_body(await ctx.client.get_json("/api/git/repositories"))
        return ok({"items": items, "count": len(items), "has_more": False})
    path = {"id": args.repository_id}
    calls = {"repository": ctx.client.get_json("/api/git/repositories/{id}", path_params=path)}
    if args.check_upstream:
        calls["upstream"] = ctx.client.get_json(
            "/api/git/repositories/{id}/sync", path_params=path, read_timeout=60.0
        )
    results, errors = await gather_sections(calls)
    if "repository" in errors:
        main = errors["repository"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    data: dict[str, Any] = dict(results)
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_list_git_repositories",
        title="List git repositories",
        description=(
            "List the git repositories DockHand deploys from, or get one, optionally checking "
            "whether its branch has new upstream commits without pulling them."
        ),
        input_model=GitRepositoriesInput,
        handler=list_git_repositories,
        annotations=READ_ANNOTATIONS,
        audit_args=("repository_id", "check_upstream"),
    ),
    Tier.READ,
    (
        ("GET", "/api/git/repositories"),
        ("GET", "/api/git/repositories/{id}"),
        ("GET", "/api/git/repositories/{id}/sync"),
    ),
)


class GitStacksInput(ToolInput):
    environment_id: int | None = Field(
        default=None, ge=1, le=MAX_ENV_ID, description="Only this environment's git stacks."
    )
    git_stack_id: int | None = _id_field("git stack, with the names of its .env files")


async def list_git_stacks(ctx: ToolContext, args: GitStacksInput) -> Envelope:
    if args.git_stack_id is None:
        items = list_body(
            await ctx.client.get_json("/api/git/stacks", params={"env": args.environment_id})
        )
        return ok(
            {"items": items, "count": len(items), "has_more": False},
            environment_id=args.environment_id,
        )
    path = {"id": args.git_stack_id}
    results, errors = await gather_sections(
        {
            "git_stack": ctx.client.get_json("/api/git/stacks/{id}", path_params=path),
            "env_files": ctx.client.get_json("/api/git/stacks/{id}/env-files", path_params=path),
        }
    )
    if "git_stack" in errors:
        main = errors["git_stack"]
        return err(main["code"], main["message"], dockhand_status=main.get("dockhand_status"))
    data: dict[str, Any] = {"git_stack": results["git_stack"]}
    files = results.get("env_files")
    if isinstance(files, dict):
        data["env_files"] = files.get("files", [])
    if errors:
        data["errors"] = errors
    return ok(data, warnings=section_warnings(errors))


register(
    ToolSpec(
        name="dockhand_list_git_stacks",
        title="List git stacks",
        description=(
            "List stacks deployed from git, or get one with the names of the .env files in its "
            "repository checkout."
        ),
        input_model=GitStacksInput,
        handler=list_git_stacks,
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "git_stack_id"),
    ),
    Tier.READ,
    (
        ("GET", "/api/git/stacks"),
        ("GET", "/api/git/stacks/{id}"),
        ("GET", "/api/git/stacks/{id}/env-files"),
    ),
)

# --- operator tier ----------------------------------------------------------------------------
# Sync and repository deploy answer synchronously; a git stack deploy streams SSE (`/deploy`, per
# ARCHITECTURE §4.2; the `deploy-stream` job variant is not used).


def _git_id(what: str) -> Any:
    return Field(ge=1, le=MAX_ENV_ID, description=f"{what} id, as listed.")


class GitStackWriteInput(WriteInputs):
    git_stack_id: int = _git_id("Git stack")


class GitRepositoryWriteInput(WriteInputs):
    repository_id: int = _git_id("Git repository")


def _git_detached(template: str, key: str, action: str) -> Any:
    async def body(ctx: ToolContext, args: Any) -> Envelope:
        item_id = getattr(args, key)
        budget, warnings = write_budget(ctx, args)

        async def work() -> Envelope:
            answer = await ctx.client.post_json(
                template,
                path_params={"id": item_id},
                read_timeout=float(ctx.settings.max_timeout) + 5.0,
            )
            if isinstance(answer, dict) and answer.get("success") is False:
                return Envelope(
                    ok=False,
                    data={"result": cap_json(answer)},
                    error=ErrorInfo(
                        code="operation_failed",
                        message=f"DockHand reports the {action} failed; see data.result",
                    ),
                )
            return ok({"result": cap_json(answer)})

        envelope = await run_async_pattern(
            "detached",
            ctx,
            wait=args.wait,
            budget_s=budget,
            meta={"action": action, key: item_id},
            work=work,
        )
        return add_warnings(envelope, warnings)

    return body


for _name, _title, _description, _model, _template, _key, _action in (
    (
        "dockhand_sync_git_stack",
        "Sync git stack",
        "Pull a git stack's repository clone to the latest commit of its tracked branch.",
        GitStackWriteInput,
        "/api/git/stacks/{id}/sync",
        "git_stack_id",
        "sync",
    ),
    (
        "dockhand_sync_git_repository",
        "Sync git repository",
        "Pull a git repository's local clone to the latest commit of its tracked branch.",
        GitRepositoryWriteInput,
        "/api/git/repositories/{id}/sync",
        "repository_id",
        "sync",
    ),
    (
        "dockhand_deploy_git_repository",
        "Deploy git repository",
        "Deploy the compose stacks defined in a git repository after pulling its latest commit.",
        GitRepositoryWriteInput,
        "/api/git/repositories/{id}/deploy",
        "repository_id",
        "deploy",
    ),
):
    register(
        ToolSpec(
            name=_name,
            title=_title,
            description=_description,
            input_model=_model,
            handler=_git_detached(_template, _key, _action),
            annotations=OPERATOR_ANNOTATIONS,
            audit_args=(_key, "wait"),
        ),
        Tier.OPERATOR,
        (("POST", _template),),
    )


async def deploy_git_stack(ctx: ToolContext, args: GitStackWriteInput) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "deploy", "git_stack_id": args.git_stack_id},
        sse=SseRequest(
            "POST", "/api/git/stacks/{id}/deploy", path_params={"id": args.git_stack_id}
        ),
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_deploy_git_stack",
        title="Deploy git stack",
        description=(
            "Deploy a git stack from its repository. Returns DockHand's result and the last "
            "progress lines."
        ),
        input_model=GitStackWriteInput,
        handler=deploy_git_stack,
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("git_stack_id", "wait"),
    ),
    Tier.OPERATOR,
    (("POST", "/api/git/stacks/{id}/deploy"), JOB_STATUS),
)
