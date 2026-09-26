# SPDX-License-Identifier: Apache-2.0
"""Validators for names and references, and name-or-ID resolution (docs/TOOLS.md contract).

Resolution goes through DockHand's list endpoints on every call; nothing is cached. The calling
tool must declare the list endpoint it resolves through (the client refuses it otherwise).

    ref matches ^[0-9a-f]{12,64}$ → an ID: prefix match against the list; 0 → not_found
    otherwise                     → exact, case-sensitive name match; 0 → not_found,
                                    >1 → ambiguous_name (candidates listed)

DockHand's list endpoints answer with lowercase keys (`id`, `name`) where the spec documents
Docker's (`Id`, `Name`); both are accepted.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from dockhand_mcp.client.errors import DockhandError, ErrorCode

if TYPE_CHECKING:
    from dockhand_mcp.client.dockhand import DockhandClient

MAX_CANDIDATES: Final = 10
MAX_ENV_ID: Final = 2**31 - 1

HEX_ID: Final = re.compile(r"^[0-9a-f]{12,64}$")
# plan S-05.
STACK_NAME: Final = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
# Docker's own rule for container, volume and network names.
DOCKER_NAME: Final = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$")
# ID (hex or sha256:hex), repo[:tag] or repo@digest. Whitespace, control characters and `..` are
# refused separately so the message can say which.
IMAGE_REF: Final = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@+-]{0,511}$")
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")


class ResolutionError(DockhandError):
    """A name that could not be validated or resolved. Carries no DockHand status."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(None, code, message)


def _invalid(message: str) -> ResolutionError:
    return ResolutionError("validation_error", message)


def _common_checks(value: str, what: str) -> None:
    if not value:
        raise _invalid(f"{what} must not be empty")
    if _CONTROL.search(value):
        raise _invalid(f"{what} must not contain control characters")
    if any(c.isspace() for c in value):
        raise _invalid(f"{what} must not contain whitespace")
    if ".." in value:
        raise _invalid(f"{what} must not contain '..'")


def validate_env_id(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_ENV_ID:
        raise _invalid(f"environment_id must be an integer from 1 to {MAX_ENV_ID}")
    return value


def validate_stack_name(value: str) -> str:
    _common_checks(value, "stack name")
    if not STACK_NAME.match(value):
        raise _invalid(
            "stack name must start with a letter or digit and contain only letters, digits, "
            "'_', '.' and '-' (at most 64 characters)"
        )
    return value


def validate_volume_name(value: str) -> str:
    _common_checks(value, "volume name")
    if not DOCKER_NAME.match(value):
        raise _invalid(
            "volume name must start with a letter or digit and contain only letters, digits, "
            "'_', '.' and '-'"
        )
    return value


def _validate_ref(value: str, what: str) -> str:
    if value.startswith("/"):
        raise _invalid(
            f"{what} names are given without Docker's leading '/' (use the name as listed)"
        )
    _common_checks(value, what)
    if not DOCKER_NAME.match(value):
        raise _invalid(
            f"{what} must be an ID (12-64 lowercase hex characters) or a name starting with a "
            "letter or digit and containing only letters, digits, '_', '.' and '-'"
        )
    return value


def validate_container_ref(value: str) -> str:
    return _validate_ref(value, "container")


def validate_network_ref(value: str) -> str:
    return _validate_ref(value, "network")


def validate_image_ref(value: str) -> str:
    _common_checks(value, "image reference")
    if not IMAGE_REF.match(value):
        raise _invalid(
            "image reference must be an image ID, repo:tag or repo@digest (letters, digits and "
            "'._/:@+-' only)"
        )
    return value


# --- resolution -------------------------------------------------------------------------------


@dataclass(frozen=True)
class ContainerRef:
    id: str
    name: str


@dataclass(frozen=True)
class NetworkRef:
    id: str
    name: str


@dataclass(frozen=True)
class ImageRef:
    id: str
    tags: tuple[str, ...]


def _field(item: Any, *keys: str) -> Any:
    if not isinstance(item, dict):
        return None
    for key in keys:
        if key in item:
            return item[key]
    return None


def _str_list(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _short(item_id: str) -> str:
    return item_id.removeprefix("sha256:")[:12]


def _candidates(labels: Sequence[str]) -> str:
    shown = ", ".join(labels[:MAX_CANDIDATES])
    more = len(labels) - MAX_CANDIDATES
    return shown + (f" (+{more} more)" if more > 0 else "")


def _not_found(what: str, ref: str, near: Sequence[str]) -> ResolutionError:
    message = f"no {what} matches {ref!r}"
    if near:
        message += f"; similar: {_candidates(near)}"
    return ResolutionError("not_found", message)


def _ambiguous(what: str, ref: str, labels: Sequence[str]) -> ResolutionError:
    return ResolutionError(
        "ambiguous_name", f"{ref!r} matches {len(labels)} {what}s: {_candidates(labels)}"
    )


async def _list(client: DockhandClient, template: str, params: dict[str, Any]) -> list[Any]:
    body = await client.get_json(template, params=params)
    return body if isinstance(body, list) else []


def _by_id_or_name(
    items: list[Any], ref: str, what: str
) -> tuple[str, str]:  # (id, name) of the one match
    rows = [
        (str(_field(i, "id", "Id") or ""), str(_field(i, "name", "Name") or ""))
        for i in items
        if isinstance(i, dict)
    ]
    if HEX_ID.match(ref):
        matches = [r for r in rows if r[0].removeprefix("sha256:").startswith(ref)]
        if not matches:
            raise _not_found(what, ref, [])
    else:
        matches = [r for r in rows if r[1] == ref]
        if not matches:
            lowered = ref.lower()
            raise _not_found(what, ref, [n for _, n in rows if lowered in n.lower()])
    if len(matches) > 1:
        raise _ambiguous(what, ref, [f"{n} ({_short(i)})" for i, n in matches])
    return matches[0]


async def resolve_container(client: DockhandClient, env: int, ref: str) -> ContainerRef:
    """Resolve a container ID or exact name via `GET /api/containers?env&all=true`."""
    validate_container_ref(ref)
    items = await _list(client, "/api/containers", {"env": env, "all": True})
    item_id, name = _by_id_or_name(items, ref, "container")
    return ContainerRef(item_id, name)


async def resolve_network(client: DockhandClient, env: int, ref: str) -> NetworkRef:
    """Resolve a network ID or exact name via `GET /api/networks?env`."""
    validate_network_ref(ref)
    items = await _list(client, "/api/networks", {"env": env})
    item_id, name = _by_id_or_name(items, ref, "network")
    return NetworkRef(item_id, name)


async def resolve_image(client: DockhandClient, env: int, ref: str) -> ImageRef:
    """Resolve an image ID (hex or sha256:hex), repo:tag or repo@digest via `GET /api/images`."""
    validate_image_ref(ref)
    items = [i for i in await _list(client, "/api/images", {"env": env}) if isinstance(i, dict)]
    rows = [
        (
            str(_field(i, "id", "Id") or ""),
            _str_list(_field(i, "repoTags", "RepoTags")),
            _str_list(_field(i, "repoDigests", "RepoDigests")),
        )
        for i in items
    ]
    bare = ref.removeprefix("sha256:")
    if HEX_ID.match(bare) and (ref.startswith("sha256:") or "/" not in ref):
        matches = [r for r in rows if r[0].removeprefix("sha256:").startswith(bare)]
        if not matches:
            raise _not_found("image", ref, [])
    elif "@" in ref:
        matches = [r for r in rows if ref in r[2]]
        if not matches:
            raise _not_found("image", ref, [])
    else:
        matches = [r for r in rows if ref in r[1]]
        if not matches:
            repo = ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref
            near = [t for _, tags, _ in rows for t in tags if t.startswith(repo + ":")]
            raise _not_found("image", ref, near)
    if len(matches) > 1:
        raise _ambiguous(
            "image", ref, [f"{(tags or ['<untagged>'])[0]} ({_short(i)})" for i, tags, _ in matches]
        )
    item_id, tags, _ = matches[0]
    return ImageRef(item_id, tuple(tags))


async def resolve_containers(
    client: DockhandClient, env: int, refs: Sequence[str]
) -> list[ContainerRef]:
    """Resolve several container refs with one list call; duplicates collapse, order is kept."""
    for ref in refs:
        validate_container_ref(ref)
    items = await _list(client, "/api/containers", {"env": env, "all": True})
    resolved: dict[str, ContainerRef] = {}
    for ref in refs:
        item_id, name = _by_id_or_name(items, ref, "container")
        resolved.setdefault(item_id, ContainerRef(item_id, name))
    return list(resolved.values())
