# SPDX-License-Identifier: Apache-2.0
"""Registry browsing: configured registries, image search, tag listing.

`GET /api/registries` strips passwords (only a `hasCredentials` flag); the tool fails closed if an
item carries a `password` key anyway. Registry writes are excluded (SECURITY §4).
"""

import logging
from typing import Any, Final

from pydantic import Field

from dockhand_mcp.client.envelope import Envelope, err, ok
from dockhand_mcp.tools._common import (
    PAGE_SCHEMA,
    ToolInput,
    gather_sections,
    list_body,
    page,
    section_warnings,
)
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.registry import Tier, register

log = logging.getLogger(__name__)

MAX_TAG_INFO: Final = 25
REPOSITORY: Final = r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,254}$"
CANARY_MESSAGE: Final = (
    "DockHand returned a registry password, which it documents it strips; the result was withheld"
)


def _registry_field() -> Any:
    return Field(
        default=None,
        ge=1,
        le=2**31 - 1,
        description="Id of a configured registry; Docker Hub when omitted.",
    )


class ListRegistriesInput(ToolInput):
    pass


async def list_registries(ctx: ToolContext, args: ListRegistriesInput) -> Envelope:
    items = list_body(await ctx.client.get_json("/api/registries"))
    if any(isinstance(i, dict) and "password" in i for i in items):
        log.error("credential_canary", extra={"source": "registries", "keys": ["password"]})
        return err("guardrail_blocked", CANARY_MESSAGE)
    return ok(page(items, max(len(items), 1), 0))


register(
    ToolSpec(
        name="dockhand_list_registries",
        title="List registries",
        description=(
            "List the container registries configured in DockHand: id, name, URL, whether it is "
            "the default and whether credentials are stored."
        ),
        input_model=ListRegistriesInput,
        handler=list_registries,
        annotations=READ_ANNOTATIONS,
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/registries"),),
)


class SearchRegistryInput(ToolInput):
    term: str = Field(
        min_length=1, max_length=255, pattern=REPOSITORY, description="Image name to search for."
    )
    registry: int | None = _registry_field()
    limit: int = Field(default=25, ge=1, le=100, description="Maximum results.")


async def search_registry(ctx: ToolContext, args: SearchRegistryInput) -> Envelope:
    body = await ctx.client.get_json(
        "/api/registry/search",
        params={"term": args.term, "limit": args.limit, "registry": args.registry},
        read_timeout=30.0,
    )
    items = list_body(body)
    return ok({"items": items, "count": len(items), "has_more": False})


register(
    ToolSpec(
        name="dockhand_search_registry",
        title="Search registry",
        description=(
            "Search Docker Hub, or a configured registry, for images by name. Returns name, "
            "description, stars and whether the image is official."
        ),
        input_model=SearchRegistryInput,
        handler=search_registry,
        annotations=READ_ANNOTATIONS,
        audit_args=("term", "registry"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/registry/search"),),
)


class ListImageTagsInput(ToolInput):
    image: str = Field(
        min_length=1, max_length=255, pattern=REPOSITORY, description="Repository, e.g. nginx."
    )
    registry: int | None = _registry_field()
    page: int = Field(default=1, ge=1, le=1000, description="Page number (Docker Hub).")
    page_size: int = Field(default=50, ge=1, le=100, description="Tags per page (Docker Hub).")
    with_info: bool = Field(
        default=False,
        description=f"Also resolve size and date for up to {MAX_TAG_INFO} tags on the page.",
    )


async def list_image_tags(ctx: ToolContext, args: ListImageTagsInput) -> Envelope:
    body = await ctx.client.get_json(
        "/api/registry/tags",
        params={
            "image": args.image,
            "registry": args.registry,
            "page": args.page,
            "pageSize": args.page_size,
        },
        read_timeout=30.0,
    )
    body = body if isinstance(body, dict) else {}
    tags = [t for t in list_body(body.get("tags")) if isinstance(t, dict)]
    warnings: list[str] = []
    if args.with_info and tags:
        if len(tags) > MAX_TAG_INFO:
            warnings.append(f"size and date resolved for the first {MAX_TAG_INFO} tags only")
        calls = {
            str(t.get("name")): ctx.client.get_json(
                "/api/registry/tag-info",
                params={"image": args.image, "tag": str(t.get("name")), "registry": args.registry},
            )
            for t in tags[:MAX_TAG_INFO]
        }
        info, errors = await gather_sections(calls)
        tags = [
            {**t, "info": info[str(t.get("name"))]} if str(t.get("name")) in info else t
            for t in tags
        ]
        warnings += section_warnings(errors)
    data: dict[str, Any] = {
        "items": tags,
        "count": len(tags),
        "has_more": bool(body.get("hasNext")),
    }
    for key in ("total", "page", "pageSize"):
        if key in body:
            data[key] = body[key]
    return ok(data, warnings=warnings)


register(
    ToolSpec(
        name="dockhand_list_image_tags",
        title="List image tags",
        description=(
            "List the tags of an image repository on Docker Hub or a configured registry, "
            "optionally with each tag's size and date."
        ),
        input_model=ListImageTagsInput,
        handler=list_image_tags,
        annotations=READ_ANNOTATIONS,
        audit_args=("image", "registry"),
        data_schema=PAGE_SCHEMA,
    ),
    Tier.READ,
    (("GET", "/api/registry/tags"), ("GET", "/api/registry/tag-info")),
)
