# SPDX-License-Identifier: Apache-2.0
"""`dockhand_list_tags`: DockHand's tag catalogue and the containers and stacks carrying each tag.

The two per-environment reads map a name to tag ids and have no 200 schema in spec 1.0.49; live
DockHand answered `{}` for both with nothing tagged (ARCHIVE §14, "Fix #3"). `env` is optional on
them in the spec and sent anyway: without it DockHand would pick an environment for us.
"""

from typing import Any, Final

from dockhand_mcp.client.envelope import Envelope, ok
from dockhand_mcp.tools._common import EnvScoped, env_tool
from dockhand_mcp.tools.base import READ_ANNOTATIONS, ToolContext, ToolSpec
from dockhand_mcp.tools.environments import ENVIRONMENTS
from dockhand_mcp.tools.registry import Tier, register

_TAG_NAMES: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": {"type": "array", "items": {"type": "string"}},
}

DATA_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "tags": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "color": {"type": ["string", "null"]},
                },
                "required": ["id", "name", "color"],
            },
        },
        "containers": _TAG_NAMES,
        "stacks": _TAG_NAMES,
    },
    "required": ["tags", "containers", "stacks"],
}


class ListTagsInput(EnvScoped):
    pass


def _catalogue(body: Any) -> list[dict[str, Any]]:
    items = body.get("tags") if isinstance(body, dict) else None
    tags: list[dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and isinstance(item.get("id"), int):
            color = item.get("color")
            tags.append(
                {
                    "id": item["id"],
                    "name": str(item.get("name", "")),
                    "color": color if isinstance(color, str) else None,
                }
            )
    return tags


def _assignments(
    body: Any, what: str, names: dict[int, str], missing: set[int], warnings: list[str]
) -> dict[str, list[str]]:
    """`{resource name: [tag ids]}` → `{resource name: [tag names]}`, untagged omitted."""
    if not isinstance(body, dict):
        warnings.append(f"DockHand's {what} tag assignments had an unexpected shape; not shown")
        return {}
    out: dict[str, list[str]] = {}
    for resource in sorted(body):
        ids = body[resource]
        if not isinstance(ids, list):
            continue
        resolved: list[str] = []
        for tag_id in ids:
            if not isinstance(tag_id, int):
                continue
            if tag_id not in names:
                missing.add(tag_id)
            resolved.append(names.get(tag_id, f"#{tag_id}"))
        if resolved:
            out[str(resource)] = resolved
    return out


async def list_tags(ctx: ToolContext, args: ListTagsInput, env: int) -> Envelope:
    tags = _catalogue(await ctx.client.get_json("/api/tags"))
    containers = await ctx.client.get_json("/api/container-tags", params={"env": env})
    stacks = await ctx.client.get_json("/api/stack-tags", params={"env": env})
    names = {t["id"]: t["name"] for t in tags}
    missing: set[int] = set()
    warnings: list[str] = []
    data = {
        "tags": tags,
        "containers": _assignments(containers, "container", names, missing, warnings),
        "stacks": _assignments(stacks, "stack", names, missing, warnings),
    }
    if missing:
        ids = ", ".join(str(i) for i in sorted(missing))
        warnings.append(f"tag ids not in the catalogue, shown as #<id>: {ids}")
    return ok(data, warnings=warnings or None)


register(
    ToolSpec(
        name="dockhand_list_tags",
        title="List tags",
        description=(
            "List DockHand's tag catalogue (id, name, colour) and, for one environment, the tag "
            "names on each tagged container and stack."
        ),
        input_model=ListTagsInput,
        handler=env_tool(list_tags),
        annotations=READ_ANNOTATIONS,
        audit_args=("environment_id",),
        data_schema=DATA_SCHEMA,
    ),
    Tier.READ,
    (
        ENVIRONMENTS,
        ("GET", "/api/tags"),
        ("GET", "/api/container-tags"),
        ("GET", "/api/stack-tags"),
    ),
)
