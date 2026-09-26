# SPDX-License-Identifier: Apache-2.0
"""Image tools: list, layer history, cached vulnerability scan; pull, tag and scan (operator).

Live DockHand answers `GET /api/images` with lowercase keys (`id`, `repoTags`, `size`, ...)
where the spec documents Docker's (`Id`, `RepoTags`, ...); both are read.

A pull with `scan_after_pull` reports the scan inside the pull's own events (DockHand 1.0.46,
`src/routes/api/images/pull/+server.ts`; the success shape matched live): `scanning`, then
`scan-progress`, then `scan-complete`, or `scan-error` when the scan throws. With scanner `both`,
one scanner failing while the other completes is only a `scan-progress` event with
`stage: error`. The stream still ends with `result {status: complete}` either way, so the tool
watches the events: a pull whose scan failed is `ok: false` (`operation_failed`,
`data.pulled: true`, `data.scanned: false`, the scan's redacted error in `data.steps`), never a
success. A pull with no scan at all (scanner `none`) keeps `ok: true` with a warning.
"""

from dataclasses import dataclass, field
from typing import Any, Final, Literal

from pydantic import Field

from dockhand_mcp.auth.approval import Approved, Preview
from dockhand_mcp.client.envelope import Envelope, ErrorInfo
from dockhand_mcp.client.redaction import current_redactor
from dockhand_mcp.guardrails.names import resolve_image, validate_image_ref
from dockhand_mcp.tools._common import (
    JOB_STATUS,
    PAGE_SCHEMA,
    EnvDestructiveInputs,
    EnvScoped,
    EnvWriteInputs,
    SseRequest,
    add_warnings,
    destructive_tool,
    dockhand_success,
    env_tool,
    limit_field,
    list_body,
    names_text,
    offset_field,
    page,
    run_async_pattern,
    scoped,
    step,
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

LIST: Final = ("GET", "/api/images")
UNTAGGED: Final = "<none>:<none>"
IMAGE_DESCRIPTION: Final = "Image ID (sha256:… or hex prefix), repo:tag or repo@digest."


def _get(item: dict[str, Any], *keys: str) -> Any:
    return next((item[k] for k in keys if k in item), None)


def image_summary(item: dict[str, Any]) -> dict[str, Any]:
    tags = _get(item, "repoTags", "RepoTags")
    tags = (
        [t for t in tags if isinstance(t, str) and t != UNTAGGED] if isinstance(tags, list) else []
    )
    return {
        "id": _get(item, "id", "Id"),
        "repoTags": tags,
        "size": _get(item, "size", "Size"),
        "created": _get(item, "created", "Created"),
        "containers": _get(item, "containers", "Containers"),
    }


class ListImagesInput(EnvScoped):
    dangling_only: bool = Field(default=False, description="Only untagged (dangling) images.")
    repo_contains: str | None = Field(
        default=None, min_length=1, max_length=255, description="Case-insensitive tag filter."
    )
    limit: int = limit_field(50)
    offset: int = offset_field()


async def list_images(ctx: ToolContext, args: ListImagesInput, env: int) -> Any:
    rows = [
        image_summary(i)
        for i in list_body(await ctx.client.get_json("/api/images", params={"env": env}))
        if isinstance(i, dict)
    ]
    if args.dangling_only:
        rows = [r for r in rows if not r["repoTags"]]
    if args.repo_contains is not None:
        needle = args.repo_contains.lower()
        rows = [r for r in rows if any(needle in t.lower() for t in r["repoTags"])]
    return page(rows, args.limit, args.offset)


register(
    ToolSpec(
        name="dockhand_list_images",
        title="List images",
        description=(
            "List Docker images in an environment, optionally only dangling ones or those whose "
            "tags match. Returns id, tags, size, creation time and container count."
        ),
        input_model=ListImagesInput,
        handler=env_tool(list_images),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "dangling_only"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST),
)


class ImageHistoryInput(EnvScoped):
    image: str = Field(min_length=1, max_length=512, description=IMAGE_DESCRIPTION)


async def get_image_history(ctx: ToolContext, args: ImageHistoryInput, env: int) -> Any:
    ref = await resolve_image(ctx.client, env, args.image)
    body = await ctx.client.get_json(
        "/api/images/{id}/history", path_params={"id": ref.id}, params={"env": env}
    )
    return {"image": {"id": ref.id, "repoTags": list(ref.tags)}, "layers": list_body(body)}


register(
    ToolSpec(
        name="dockhand_get_image_history",
        title="Get image history",
        description=(
            "Get an image's layer history: each layer's creating command, size and creation time."
        ),
        input_model=ImageHistoryInput,
        handler=env_tool(get_image_history),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "image"),
    ),
    Tier.READ,
    (ENVIRONMENTS, LIST, ("GET", "/api/images/{id}/history")),
)


class ImageScanInput(EnvScoped):
    image: str = Field(min_length=1, max_length=512, description=IMAGE_DESCRIPTION)
    scanner: Literal["grype", "trivy"] | None = Field(
        default=None, description="Only results from this scanner."
    )
    limit: int = limit_field(50)
    offset: int = offset_field()


async def get_image_scan(ctx: ToolContext, args: ImageScanInput, env: int) -> Any:
    validate_image_ref(args.image)
    body = await ctx.client.get_json(
        "/api/images/scan", params={"env": env, "image": args.image, "scanner": args.scanner}
    )
    if not isinstance(body, dict) or not body.get("found"):
        return {"found": False}
    result: dict[str, Any] = body["result"] if isinstance(body.get("result"), dict) else {}
    findings = list_body(result.get("vulnerabilities"))
    return {
        "found": True,
        "summary": {k: v for k, v in result.items() if k != "vulnerabilities"},
        "findings": page(findings, args.limit, args.offset),
    }


register(
    ToolSpec(
        name="dockhand_get_image_scan",
        title="Get image scan",
        description=(
            "Get the latest stored vulnerability scan of an image without running a new one. "
            "Returns severity counts and a page of findings, or found false."
        ),
        input_model=ImageScanInput,
        handler=env_tool(get_image_scan),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id", "image", "scanner"),
    ),
    Tier.READ,
    (ENVIRONMENTS, ("GET", "/api/images/scan")),
)

# --- operator tier ----------------------------------------------------------------------------
# Pull and scan only stream (SSE, ARCHITECTURE §4.2); tag answers synchronously.

Scanner = Literal["grype", "trivy"]


class PullImageInput(EnvWriteInputs):
    image: str = Field(
        min_length=1, max_length=512, description="Image to pull, as repo:tag or repo@digest."
    )
    scan_after_pull: bool = Field(
        default=False, description="Scan the image for vulnerabilities once pulled."
    )


MAX_SCAN_ERRORS: Final = 5
SCAN_FAILED: Final = (
    "DockHand pulled the image but the vulnerability scan failed; see data.steps. The image is "
    "pulled: scan it after fixing the cause rather than pulling it again."
)
NO_SCAN: Final = (
    "DockHand ran no vulnerability scan after the pull (its scanner setting may be none); the "
    "image was pulled but not scanned."
)


@dataclass
class ScanWatch:
    """What a pull's events say about the scan after it (see the module docstring)."""

    started: bool = False
    completed: bool = False
    errors: list[str] = field(default_factory=list)

    def __call__(self, event: str, data: Any) -> None:
        if event != "progress" or not isinstance(data, dict):
            return
        status = data.get("status")
        if status == "scanning":
            self.started = True
        elif status == "scan-complete":
            self.completed = True
        elif status == "scan-error":
            self._error(data.get("error"))
        elif status == "scan-progress" and data.get("stage") == "error":
            self._error(data.get("message") or data.get("error"))

    def _error(self, message: Any) -> None:
        text = current_redactor().text(str(message) if message else "scan failed")
        if text not in self.errors and len(self.errors) < MAX_SCAN_ERRORS:
            self.errors.append(text)

    def review(self, envelope: Envelope) -> Envelope:
        """The pull's envelope, judged with the scan: only a finished, successful pull."""
        if not envelope.ok or (envelope.operation is not None and envelope.operation.timed_out):
            return envelope
        data = envelope.data if isinstance(envelope.data, dict) else {"result": envelope.data}
        if self.errors:
            return Envelope(
                ok=False,
                data={
                    **data,
                    "pulled": True,
                    "scanned": False,
                    "steps": [
                        step("pull", True),
                        step("scan", False, current_redactor().text("; ".join(self.errors))),
                    ],
                },
                operation=envelope.operation,
                error=ErrorInfo(code="operation_failed", message=SCAN_FAILED),
            )
        if not self.completed:
            return add_warnings(envelope, [NO_SCAN])
        return envelope


async def pull_image(ctx: ToolContext, args: PullImageInput, env: int) -> Envelope:
    validate_image_ref(args.image)
    budget, warnings = write_budget(ctx, args)
    watch = ScanWatch() if args.scan_after_pull else None
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "pull", "image": args.image, "environment_id": env},
        sse=SseRequest(
            "POST",
            "/api/images/pull",
            params={"env": env},
            json={"image": args.image, "scanAfterPull": args.scan_after_pull},
        ),
        on_event=watch,
        review=watch.review if watch is not None else None,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_pull_image",
        title="Pull image",
        description=(
            "Pull an image into an environment, optionally scanning it afterwards. Returns "
            "DockHand's result and the last progress lines."
        ),
        input_model=PullImageInput,
        handler=env_tool(pull_image),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "image", "scan_after_pull", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/images/pull"), JOB_STATUS),
)

# Docker's repository grammar, loosely: lowercase path components, optional registry port.
REPOSITORY: Final = (
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
TAG: Final = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"


class TagImageInput(EnvWriteInputs):
    image: str = Field(min_length=1, max_length=512, description=IMAGE_DESCRIPTION)
    repo: str = Field(
        min_length=1, max_length=255, pattern=REPOSITORY, description="Repository to tag into."
    )
    tag: str = Field(default="latest", max_length=128, pattern=TAG, description="The new tag.")


async def tag_image(ctx: ToolContext, args: TagImageInput, env: int) -> Envelope:
    ref = await resolve_image(ctx.client, env, args.image)
    budget, warnings = write_budget(ctx, args)

    async def work() -> dict[str, Any]:
        answer = await ctx.client.post_json(
            "/api/images/{id}/tag",
            path_params={"id": ref.id},
            params={"env": env},
            json={"repo": args.repo, "tag": args.tag},
        )
        return {"image": ref.id, "tagged": f"{args.repo}:{args.tag}", "result": answer}

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "tag", "image": ref.id, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_tag_image",
        title="Tag image",
        description="Add a repository tag to an image in an environment.",
        input_model=TagImageInput,
        handler=env_tool(tag_image),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "image", "repo", "tag", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, LIST, ("POST", "/api/images/{id}/tag")),
)


class ScanImageInput(EnvWriteInputs):
    image: str = Field(min_length=1, max_length=512, description=IMAGE_DESCRIPTION)
    scanner: Scanner | None = Field(default=None, description="Scanner to use.")


async def scan_image(ctx: ToolContext, args: ScanImageInput, env: int) -> Envelope:
    validate_image_ref(args.image)
    budget, warnings = write_budget(ctx, args)

    async def finish(result: Any) -> dict[str, Any]:
        cached = await ctx.client.get_json(
            "/api/images/scan", params={"env": env, "image": args.image, "scanner": args.scanner}
        )
        stored = cached.get("result") if isinstance(cached, dict) else None
        summary = (
            {k: v for k, v in stored.items() if k != "vulnerabilities"}
            if isinstance(stored, dict)
            else None
        )
        return {"image": args.image, "found": summary is not None, "summary": summary}

    body: dict[str, Any] = {"imageName": args.image}
    if args.scanner is not None:
        body["scanner"] = args.scanner
    envelope = await run_async_pattern(
        "sse",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "scan", "image": args.image, "environment_id": env},
        sse=SseRequest("POST", "/api/images/scan", params={"env": env}, json=body),
        finish=finish,
    )
    return add_warnings(envelope, warnings)


register(
    ToolSpec(
        name="dockhand_scan_image",
        title="Scan image",
        description=(
            "Scan an image for vulnerabilities and store the result. Returns the stored scan's "
            "summary with severity counts."
        ),
        input_model=ScanImageInput,
        handler=env_tool(scan_image),
        annotations=OPERATOR_ANNOTATIONS,
        audit_args=("environment_id", "image", "scanner", "wait"),
    ),
    Tier.OPERATOR,
    (ENVIRONMENTS, ("POST", "/api/images/scan"), ("GET", "/api/images/scan"), JOB_STATUS),
)


# --- destructive tier -------------------------------------------------------------------------
# Runs only through run_destructive (D-006): preview with GETs only, then human approval.


class RemoveImageInput(EnvDestructiveInputs):
    image: str = Field(min_length=1, max_length=512, description=IMAGE_DESCRIPTION)
    force: bool = Field(
        default=False,
        description="Remove even if the image has several tags or a stopped container uses it.",
    )


async def remove_image_preview(
    ctx: ToolContext, args: RemoveImageInput, env: int | None
) -> Preview:
    env = scoped(env)
    ref = await resolve_image(ctx.client, env, args.image)
    images = list_body(await ctx.client.get_json("/api/images", params={"env": env}))
    item = next((i for i in images if isinstance(i, dict) and _get(i, "id", "Id") == ref.id), {})
    containers = list_body(
        await ctx.client.get_json("/api/containers", params={"env": env, "all": True})
    )
    users = [
        {"name": c.get("name"), "state": c.get("state")}
        for c in containers
        if isinstance(c, dict) and c.get("imageId") == ref.id
    ]
    label = ", ".join(ref.tags) or ref.id.removeprefix("sha256:")[:12]
    summary = (
        f"Remove image {label} in environment {env}"
        f"{' (forced)' if args.force else ''}. Used by {len(users)} container(s): "
        f"{names_text([str(u['name']) for u in users])}."
    )
    return Preview(
        summary=summary,
        data={
            "image": image_summary(item) if item else {"id": ref.id, "repoTags": list(ref.tags)},
            "used_by": users,
            "force": args.force,
            "would_remove": True,
        },
        counts={"images": 1, "used_by": len(users)},
        target={"id": ref.id, "tags": list(ref.tags)},
    )


async def remove_image(
    ctx: ToolContext,
    args: RemoveImageInput,
    env: int | None,
    preview: Preview,
    approved: Approved,
) -> Envelope:
    budget, warnings = write_budget(ctx, args)
    image_id = str(preview.target["id"])
    image = {"id": image_id, "repoTags": list(preview.target["tags"])}

    async def work() -> Envelope:
        answer = await ctx.client.delete_json(
            "/api/images/{id}",
            path_params={"id": image_id},
            params={"env": env, "force": args.force},
        )
        return dockhand_success(answer, {"image": image, "removed": True}, "image removal")

    envelope = await run_async_pattern(
        "detached",
        ctx,
        wait=args.wait,
        budget_s=budget,
        meta={"action": "remove_image", "image": image_id, "environment_id": env},
        work=work,
    )
    return add_warnings(envelope, warnings)


register(
    destructive_tool(
        name="dockhand_remove_image",
        title="Remove image",
        description=(
            "Remove an image after a human approves. Returns the removed image's id and tags."
        ),
        input_model=RemoveImageInput,
        preview=remove_image_preview,
        execute=remove_image,
        audit_args=("environment_id", "image", "force", "wait"),
    ),
    Tier.DESTRUCTIVE,
    (ENVIRONMENTS, LIST, ("GET", "/api/containers"), ("DELETE", "/api/images/{id}")),
)
