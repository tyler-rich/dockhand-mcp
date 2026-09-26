# SPDX-License-Identifier: Apache-2.0
"""guardrails/names.py: validators and name-or-ID resolution through DockHand's list endpoints."""

from collections.abc import AsyncIterator
from typing import Any

import pytest
import respx
from conftest import DOCKHAND_URL, ENV, IDS, load_fixture

from dockhand_mcp.client.dockhand import DockhandClient
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.guardrails import names


@pytest.fixture
async def client() -> AsyncIterator[DockhandClient]:
    c = DockhandClient(DOCKHAND_URL, retry_attempts=1)
    yield c
    await c.aclose()


def code_of(e: pytest.ExceptionInfo[DockhandError]) -> str:
    return e.value.code


# --- validators -------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [7, 1, 2**31 - 1])
def test_env_id_valid(value: int) -> None:
    assert names.validate_env_id(value) == value


@pytest.mark.parametrize("value", [0, -1, 2**31, True])
def test_env_id_invalid(value: int) -> None:
    with pytest.raises(DockhandError) as e:
        names.validate_env_id(value)
    assert code_of(e) == "validation_error"


@pytest.mark.parametrize("value", ["shop", "a", "my-stack_1.2", "A" * 64])
def test_stack_name_valid(value: str) -> None:
    assert names.validate_stack_name(value) == value


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("", "empty"),
        ("my stack", "whitespace"),
        ("a\tb", "control"),
        ("..", "'..'"),
        ("a..b", "'..'"),
        ("-lead", "start"),
        ("a/b", "start"),
        ("A" * 65, "64"),
        ("a\x00b", "control"),
    ],
)
def test_stack_name_invalid(value: str, why: str) -> None:
    with pytest.raises(DockhandError, match=why) as e:
        names.validate_stack_name(value)
    assert code_of(e) == "validation_error"


@pytest.mark.parametrize("value", ["shop_data", "cache", "a.b-c"])
def test_volume_name_valid(value: str) -> None:
    assert names.validate_volume_name(value) == value


@pytest.mark.parametrize("value", ["", " cache", "a b", "../etc", "a/b", "\x07bell"])
def test_volume_name_invalid(value: str) -> None:
    with pytest.raises(DockhandError):
        names.validate_volume_name(value)


@pytest.mark.parametrize(
    "value",
    [
        "nginx:1.27",
        "ghcr.io/owner/app:1.0",
        "registry.example.test:5000/team/app@sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "0123456789ab",
        "redis",
    ],
)
def test_image_ref_valid(value: str) -> None:
    assert names.validate_image_ref(value) == value


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("nginx 1.27", "whitespace"),
        ("nginx:\n1.27", "control"),
        ("../nginx", "'..'"),
        ("repo/..:tag", "'..'"),
        ("nginx;rm", "image reference must be"),
        ("", "empty"),
    ],
)
def test_image_ref_invalid(value: str, why: str) -> None:
    with pytest.raises(DockhandError, match=why):
        names.validate_image_ref(value)


def test_container_ref_leading_slash_is_a_validation_error() -> None:
    # Maintainer decision (S2): DockHand lists names without Docker's leading '/'; never normalise.
    with pytest.raises(DockhandError, match="without Docker's leading '/'") as e:
        names.validate_container_ref("/web")
    assert code_of(e) == "validation_error"


@pytest.mark.parametrize("value", ["we b", "web\r", "..", "-x", "a/b"])
def test_container_ref_invalid(value: str) -> None:
    with pytest.raises(DockhandError):
        names.validate_container_ref(value)


# --- resolution -------------------------------------------------------------------------------


def containers(dockhand: respx.MockRouter, body: Any = None) -> respx.Route:
    return dockhand.get("/api/containers").respond(
        200, json=body if body is not None else load_fixture("containers", "list")
    )


async def test_container_exact_name(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    route = containers(dockhand)
    ref = await names.resolve_container(client, ENV, "web")
    assert ref == names.ContainerRef(IDS["CID_WEB"], "web")
    params = route.calls.last.request.url.params
    assert params["env"] == "7"
    assert params["all"] == "true"


async def test_container_name_is_case_sensitive(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    containers(dockhand)
    with pytest.raises(DockhandError) as e:
        await names.resolve_container(client, ENV, "WEB")
    assert code_of(e) == "not_found"
    assert "similar: web" in e.value.message


async def test_container_id_prefix(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    containers(dockhand)
    ref = await names.resolve_container(client, ENV, IDS["CID_DB"][:12])
    assert ref.name == "db"
    ref = await names.resolve_container(client, ENV, IDS["CID_DB"])
    assert ref.id == IDS["CID_DB"]


async def test_container_missing(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    containers(dockhand)
    with pytest.raises(DockhandError, match="no container matches 'nope'") as e:
        await names.resolve_container(client, ENV, "nope")
    assert code_of(e) == "not_found"
    with pytest.raises(DockhandError) as e:
        await names.resolve_container(client, ENV, "f" * 12)
    assert code_of(e) == "not_found"


async def test_container_ambiguous(dockhand: respx.MockRouter, client: DockhandClient) -> None:
    body = load_fixture("containers", "list")
    body.append({**body[0], "id": IDS["CID_WORKER"]})  # a second container named "web"
    containers(dockhand, body)
    with pytest.raises(DockhandError) as e:
        await names.resolve_container(client, ENV, "web")
    assert code_of(e) == "ambiguous_name"
    assert IDS["CID_WEB"][:12] in e.value.message
    assert IDS["CID_WORKER"][:12] in e.value.message


async def test_container_ambiguous_id_prefix(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    prefix = "abcdefabcdef"
    body = [
        {"id": prefix + "1" * 52, "name": "one"},
        {"id": prefix + "2" * 52, "name": "two"},
    ]
    containers(dockhand, body)
    with pytest.raises(DockhandError) as e:
        await names.resolve_container(client, ENV, prefix)
    assert code_of(e) == "ambiguous_name"


async def test_invalid_ref_never_calls_dockhand(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    route = containers(dockhand)
    with pytest.raises(DockhandError):
        await names.resolve_container(client, ENV, "/web")
    assert route.call_count == 0


async def test_network_resolution_both_key_casings(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/networks").respond(200, json=load_fixture("networks", "list"))
    assert (await names.resolve_network(client, ENV, "back")).id == IDS["NID_BACK"]
    upper = [{"Id": IDS["NID_FRONT"], "Name": "front"}]  # the spec's documented casing
    dockhand.get("/api/networks").respond(200, json=upper)
    assert (await names.resolve_network(client, ENV, IDS["NID_FRONT"][:12])).name == "front"


async def test_network_ambiguous_and_missing(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    body = load_fixture("networks", "list")
    body.append({**body[0], "id": IDS["NID_BACK"][::-1]})  # Docker allows duplicate names
    dockhand.get("/api/networks").respond(200, json=body)
    with pytest.raises(DockhandError) as e:
        await names.resolve_network(client, ENV, "front")
    assert code_of(e) == "ambiguous_name"
    with pytest.raises(DockhandError) as e:
        await names.resolve_network(client, ENV, "side")
    assert code_of(e) == "not_found"


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("nginx:1.27", "IMG_NGINX"),
        ("redis:latest", "IMG_REDIS"),
        ("sha256:" + IDS["IMG_REDIS"], "IMG_REDIS"),
        (IDS["IMG_DANGLING"][:12], "IMG_DANGLING"),
        ("nginx@sha256:" + IDS["DIGEST_NGINX"], "IMG_NGINX"),
    ],
)
async def test_image_resolution(
    dockhand: respx.MockRouter, client: DockhandClient, ref: str, expected: str
) -> None:
    dockhand.get("/api/images").respond(200, json=load_fixture("images", "list"))
    image = await names.resolve_image(client, ENV, ref)
    assert image.id == "sha256:" + IDS[expected]


async def test_image_missing_lists_other_tags(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    dockhand.get("/api/images").respond(200, json=load_fixture("images", "list"))
    with pytest.raises(DockhandError) as e:
        await names.resolve_image(client, ENV, "redis")  # no tag: not silently :latest
    assert code_of(e) == "not_found"
    assert "redis:7" in e.value.message
    assert "redis:latest" in e.value.message


async def test_image_ambiguous_id_prefix(
    dockhand: respx.MockRouter, client: DockhandClient
) -> None:
    body = [
        {"id": "sha256:" + "c" * 64, "repoTags": ["a:1"]},
        {"id": "sha256:" + "c" * 12 + "d" * 52, "repoTags": ["b:1"]},
    ]
    dockhand.get("/api/images").respond(200, json=body)
    with pytest.raises(DockhandError) as e:
        await names.resolve_image(client, ENV, "c" * 12)
    assert code_of(e) == "ambiguous_name"
    assert "a:1" in e.value.message
