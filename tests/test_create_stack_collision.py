# SPDX-License-Identifier: Apache-2.0
"""`dockhand_create_stack` refuses a name already in use as a compose project on the daemon (#19).

Live DockHand 1.0.46, two environments on one Docker daemon: a create through environment 1
with the name of environment 2's running stack was accepted (`success: true`, `start=false`).
The duplicate became a tracked record in environment 1, and deleting it there ran
`compose down` on the shared project, removing environment 2's containers. DockHand refuses
names that are not already Docker Compose project names (lowercase, `[a-z0-9_-]`), and runs
compose with the stack name as the project name, so a top-level `name:` changes nothing.

So before any other request the tool lists the environment's stacks (tracked, and compose
projects discovered on its daemon) and refuses with `validation_error` when the requested name
matches any of them after Docker Compose's project-name normalisation: not one write request,
and not DockHand's validator either.

It also reads every container in the environment, stopped ones included (`all=true`), and
refuses a name matching any container's `com.docker.compose.project` label the same way (#21):
a project whose containers are all stopped might not be listed as a stack, and the label is on
stopped containers too (seen live, DockHand 1.0.46).
"""

import hashlib
from typing import Any, Final

import pytest
import respx
from conftest import ENV, SetEnv, load_fixture
from test_operator_tools import NEW_COMPOSE, call, compose_body, fx

from dockhand_mcp.tools import _stackguard
from dockhand_mcp.tools.registry import REGISTRY

E: Final = {"environment_id": ENV}
TOOL: Final = "dockhand_create_stack"
NAME_IN_PATH: Final = r"^/api/stacks/[^/]+"
PROJECT_LABEL: Final = "com.docker.compose.project"
SERVICE_LABEL: Final = "com.docker.compose.service"
FROM_LIST: Final = "found in the stack list"
FROM_LABELS: Final = "found in container labels"


@pytest.fixture(autouse=True)
def operator(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="operator")


def shared_daemon_list() -> Any:
    """`tools` has a source record here; `shop` is only discovered (another environment's)."""
    return load_fixture("stacks", "list-shared-daemon")


def container(name: str, project: str | None, state: str = "exited") -> dict[str, Any]:
    """A `GET /api/containers` item in the live key casing (invented, not recorded)."""
    labels = {} if project is None else {PROJECT_LABEL: project, SERVICE_LABEL: "web"}
    return {
        "id": hashlib.sha256(name.encode()).hexdigest(),
        "name": name,
        "image": "nginx:alpine",
        "state": state,
        "status": "Exited (0) 1 hour ago" if state == "exited" else "Up 1 hour",
        "labels": labels,
    }


def stopped_project_containers() -> list[dict[str, Any]]:
    """`legacy` exists only as stopped containers; nothing lists it as a stack."""
    return [
        container("shop-web-1", "shop", "running"),
        container("legacy-web-1", "legacy"),
        container("legacy-db-1", "legacy"),
        container("loose", None),
    ]


def mount_create(
    dockhand: respx.MockRouter, stack_list: Any, containers: Any | None = None
) -> None:
    """Answers for a create of any name, so a create the guard let through would succeed."""
    dockhand.route(method="GET", path="/api/stacks").respond(json=stack_list)
    dockhand.route(method="GET", path="/api/containers").respond(
        json=[] if containers is None else containers
    )
    dockhand.route(method="POST", path__regex=NAME_IN_PATH + "/validate$").respond(
        json=fx("stacks", "validate")
    )
    dockhand.route(method="POST", path="/api/stacks").respond(json=fx("stacks", "create"))
    dockhand.route(method="GET", path__regex=NAME_IN_PATH + "/compose$").respond(
        json=compose_body(NEW_COMPOSE)
    )


def non_gets(dockhand: respx.MockRouter) -> list[tuple[str, str]]:
    return [
        (c.request.method, c.request.url.path) for c in dockhand.calls if c.request.method != "GET"
    ]


async def create(
    dockhand: respx.MockRouter,
    name: str,
    stack_list: Any,
    containers: Any | None = None,
    **extra: Any,
) -> Any:
    mount_create(dockhand, stack_list, containers)
    envelope, _ = await call(TOOL, {**E, "name": name, "compose": NEW_COMPOSE, **extra})
    return envelope


def test_create_stack_declares_the_stack_list() -> None:
    (spec,) = [t for t in REGISTRY.all() if t.name == TOOL]
    assert ("GET", "/api/stacks") in spec.endpoints


def test_create_stack_declares_the_container_list() -> None:
    (spec,) = [t for t in REGISTRY.all() if t.name == TOOL]
    assert ("GET", "/api/containers") in spec.endpoints


@pytest.mark.parametrize("start", [False, True])
async def test_a_name_tracked_here_is_refused_and_nothing_is_sent(
    dockhand: respx.MockRouter, start: bool
) -> None:
    envelope = await create(dockhand, "tools", shared_daemon_list(), start=start)
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    message = envelope.error.message
    assert "already in use on this Docker daemon" in message
    assert f"tracked in environment {ENV}" in message
    assert "not tracked" not in message
    assert non_gets(dockhand) == []


@pytest.mark.parametrize("start", [False, True])
async def test_a_project_only_discovered_on_the_daemon_is_refused_and_nothing_is_sent(
    dockhand: respx.MockRouter, start: bool
) -> None:
    envelope = await create(dockhand, "shop", shared_daemon_list(), start=start)
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    message = envelope.error.message
    assert "already in use on this Docker daemon" in message
    assert f"not tracked in environment {ENV}" in message
    assert non_gets(dockhand) == []


@pytest.mark.parametrize(
    ("requested", "listed"),
    [
        ("Shop", "shop"),
        ("SHOP", "shop"),
        ("sh.op", "shop"),
        ("Sh.Op.", "shop"),
        ("Tools", "tools"),
        ("Web-App", "web-app"),
        ("webapp", "Web.App"),
        ("web_app", "web_app"),
    ],
)
async def test_case_and_normalisation_variants_are_refused(
    dockhand: respx.MockRouter, requested: str, listed: str
) -> None:
    stack_list = [{**shared_daemon_list()[1], "name": listed}]
    envelope = await create(dockhand, requested, stack_list)
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    assert listed in envelope.error.message
    assert non_gets(dockhand) == []


@pytest.mark.parametrize("name", ["fresh", "shop-2", "shop_", "tools2"])
async def test_an_unused_name_is_created_as_before(dockhand: respx.MockRouter, name: str) -> None:
    envelope = await create(dockhand, name, shared_daemon_list())
    assert envelope.ok is True, envelope.error
    assert envelope.verified is True
    assert non_gets(dockhand) == [
        ("POST", f"/api/stacks/{name}/validate"),
        ("POST", "/api/stacks"),
    ]
    listings = [c.request for c in dockhand.calls if c.request.url.path == "/api/stacks"]
    assert [(r.method, r.url.params["env"]) for r in listings][:1] == [("GET", str(ENV))]


async def test_an_empty_environment_creates_as_before(dockhand: respx.MockRouter) -> None:
    envelope = await create(dockhand, "fresh", [])
    assert envelope.ok is True, envelope.error


async def test_the_list_failing_means_nothing_is_created(dockhand: respx.MockRouter) -> None:
    mount_create(dockhand, [])
    dockhand.route(method="GET", path="/api/stacks").respond(500, json={"error": "boom"})
    envelope, _ = await call(TOOL, {**E, "name": "fresh", "compose": NEW_COMPOSE})
    assert envelope.ok is False
    assert non_gets(dockhand) == []


@pytest.mark.parametrize(
    ("name", "project"),
    [
        # compose-go loader.NormalizeProjectName: lowercase, keep [a-z0-9_-], trim leading _ and -.
        ("myapp", "myapp"),
        ("My-App", "my-app"),
        ("my.app", "myapp"),
        ("my_app", "my_app"),
        ("-_x", "x"),
        ("a.-b", "a-b"),
        ("App2.", "app2"),
    ],
)
def test_project_name_follows_docker_compose(name: str, project: str) -> None:
    assert _stackguard.project_name(name) == project


# --- container labels (#21) -------------------------------------------------------------------


@pytest.mark.parametrize("start", [False, True])
@pytest.mark.parametrize("requested", ["legacy", "Legacy", "le.gacy"])
async def test_a_name_only_on_stopped_containers_labels_is_refused_and_nothing_is_sent(
    dockhand: respx.MockRouter, start: bool, requested: str
) -> None:
    envelope = await create(
        dockhand, requested, shared_daemon_list(), stopped_project_containers(), start=start
    )
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    message = envelope.error.message
    assert "already in use on this Docker daemon as compose project legacy" in message
    assert FROM_LABELS in message
    assert FROM_LIST not in message
    assert non_gets(dockhand) == []


async def test_a_running_containers_label_not_listed_as_a_stack_is_refused(
    dockhand: respx.MockRouter,
) -> None:
    containers = [container("side-web-1", "side", "running")]
    envelope = await create(dockhand, "side", [], containers)
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    assert FROM_LABELS in envelope.error.message
    assert non_gets(dockhand) == []


@pytest.mark.parametrize("name", ["tools", "shop"])
async def test_a_stack_list_match_is_still_refused_and_says_so(
    dockhand: respx.MockRouter, name: str
) -> None:
    envelope = await create(dockhand, name, shared_daemon_list(), [])
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    assert FROM_LIST in envelope.error.message
    assert FROM_LABELS not in envelope.error.message
    assert non_gets(dockhand) == []


async def test_a_match_in_both_sources_names_both(dockhand: respx.MockRouter) -> None:
    envelope = await create(dockhand, "shop", shared_daemon_list(), stopped_project_containers())
    assert envelope.error is not None
    assert envelope.error.code == "validation_error", envelope.error
    assert FROM_LIST in envelope.error.message
    assert FROM_LABELS in envelope.error.message
    assert f"not tracked in environment {ENV}" in envelope.error.message
    assert non_gets(dockhand) == []


@pytest.mark.parametrize("name", ["fresh", "legacy-2", "legacy_"])
async def test_an_unused_name_is_created_after_reading_every_container(
    dockhand: respx.MockRouter, name: str
) -> None:
    envelope = await create(dockhand, name, shared_daemon_list(), stopped_project_containers())
    assert envelope.ok is True, envelope.error
    assert envelope.verified is True
    assert non_gets(dockhand) == [
        ("POST", f"/api/stacks/{name}/validate"),
        ("POST", "/api/stacks"),
    ]
    listings = [c.request for c in dockhand.calls if c.request.url.path == "/api/containers"]
    assert [(r.url.params["env"], r.url.params["all"]) for r in listings] == [(str(ENV), "true")]


async def test_the_container_list_failing_means_nothing_is_created(
    dockhand: respx.MockRouter,
) -> None:
    mount_create(dockhand, [])
    dockhand.route(method="GET", path="/api/containers").respond(500, json={"error": "boom"})
    envelope, _ = await call(TOOL, {**E, "name": "fresh", "compose": NEW_COMPOSE})
    assert envelope.ok is False
    assert non_gets(dockhand) == []
