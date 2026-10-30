# SPDX-License-Identifier: Apache-2.0
"""Scheduled container start and stop (#19): `dockhand_get_scheduled_actions` (read) and
`dockhand_set_scheduled_actions` (operator), and the run/toggle allowlists that admit
`container_start` and `container_stop`.

The set tool's rails all run before any write: the container is resolved in the requested
environment; the times are `HH:MM` or a five-field cron expression (the spec's two forms); a stop
is refused for DockHand's own container (DockHand reports it as `systemContainer`, as it does a
Hawser agent) and for the container this server runs in; and a container that another
environment also lists (one Docker daemon serving several environments) is refused unless the
requested environment tracks its stack. After the PUT the schedule is read back.

The fixtures are invented (tests/fixtures/dockhand/scheduled-actions/).
"""

import importlib
import json
from collections.abc import Callable
from types import ModuleType
from typing import Any, get_args

import httpx
import pytest
import respx
from conftest import ENV, IDS, SetEnv, load_fixture, mcp_client
from test_operation_output import TOKEN, URL_PASS, URL_USER
from test_operator_tools import Called, Seq, mount, sent
from test_operator_tools import call as operator_call
from test_read_tools import Called as ReadCalled
from test_read_tools import call as read_call
from test_read_tools import declared

from dockhand_mcp.config import load_settings
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.tools import schedules
from dockhand_mcp.tools.base import OPERATOR_IDEMPOTENT_ANNOTATIONS, READ_ANNOTATIONS
from dockhand_mcp.tools.registry import REGISTRY, Profile, Tier
from dockhand_mcp.transport.app import create_app

GET_TOOL = "dockhand_get_scheduled_actions"
SET_TOOL = "dockhand_set_scheduled_actions"
WEB = IDS["CID_WEB"]
E = {"environment_id": ENV}
PATH = "/api/scheduled-actions/web"
LIST = ("GET", "/api/containers")
SA = ("GET", "/api/scheduled-actions/{containerName}")
SA_PUT = ("PUT", "/api/scheduled-actions/{containerName}")
ENVIRONMENTS = ("GET", "/api/environments")
STACKS = ("GET", "/api/stacks")
LEAK = f"bad label {TOKEN} from https://{URL_USER}:{URL_PASS}@registry.example.test"


def own() -> ModuleType:
    """The self-identification module (imported here so a missing one fails each test)."""
    return importlib.import_module("dockhand_mcp.guardrails.self_container")


def fx(name: str) -> Any:
    return load_fixture("scheduled-actions", name)


def containers() -> tuple[str, str, Any]:
    return ("GET", "/api/containers", load_fixture("containers", "list"))


def owned() -> list[tuple[str, str, Any]]:
    """The container list and the stack list, where `web`'s stack `shop` is tracked."""
    return [containers(), ("GET", "/api/stacks", load_fixture("stacks", "list"))]


def schedule(**fields: Any) -> dict[str, Any]:
    return {**fx("empty"), **fields}


def set_routes(before: Any, after: Any, put: Any | None = None) -> list[tuple[str, str, Any]]:
    """The container and stack lists, the schedule GET (before the write, then the read-back) and
    the PUT."""
    return [
        *owned(),
        ("GET", PATH, Seq((before, after))),
        ("PUT", PATH, after if put is None else put),
    ]


def writes(dockhand: respx.MockRouter) -> list[Any]:
    return [c.request for c in dockhand.calls if c.request.method != "GET"]


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


@pytest.fixture
def own_container(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Make this server believe it runs in the container with the given id."""

    def _set(*ids: str) -> None:
        monkeypatch.setattr(own(), "own_container_ids", lambda: frozenset(ids))

    return _set


# --- read tool --------------------------------------------------------------------------------


async def test_get_populated(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount_read = [*owned(), ("GET", PATH, fx("set"))]
    mount(dockhand, mount_read)
    env, _, _ = await read_call(GET_TOOL, {**E, "container": "web"})
    assert env.ok is True, env.error
    assert env.environment_id == ENV
    assert env.data["container"] == {"id": WEB, "name": "web"}
    assert env.data["schedule"]["startAt"] == "07:00"
    assert env.data["schedule"]["stopAt"] == "0 23 * * 1-5"
    assert env.data["schedule"]["enabled"] is True
    (request,) = [c.request for c in dockhand.calls if c.request.url.path == PATH]
    assert request.url.params["env"] == str(ENV)


async def test_get_by_id_uses_the_name(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [*owned(), ("GET", PATH, fx("set"))])
    env, _, _ = await read_call(GET_TOOL, {**E, "container": WEB[:12]})
    assert env.ok is True, env.error
    assert env.data["container"]["name"] == "web"


async def test_get_empty(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [*owned(), ("GET", PATH, fx("empty"))])
    env, _, _ = await read_call(GET_TOOL, {**E, "container": "web"})
    assert env.ok is True, env.error
    assert env.data["schedule"]["startAt"] is None
    assert env.data["schedule"]["stopAt"] is None


async def test_get_not_found(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [containers()])
    env, _, _ = await read_call(GET_TOOL, {**E, "container": "nope"})
    assert env.error is not None
    assert env.error.code == "not_found"
    assert [c.request.url.path for c in dockhand.calls] == ["/api/containers"]


async def test_get_calls_only_declared_endpoints(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    mount(dockhand, [*owned(), ("GET", PATH, fx("set"))])
    called = ReadCalled()
    await read_call(GET_TOOL, {**E, "container": "web"}, called)
    assert set(called.endpoints) == {LIST, STACKS, SA}
    assert declared(GET_TOOL) == {ENVIRONMENTS, LIST, STACKS, SA}


async def test_get_redacts_dockhand_free_text(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    mount(dockhand, [*owned(), ("GET", PATH, schedule(labelErrors=[LEAK]))])
    env, content, _ = await read_call(GET_TOOL, {**E, "container": "web"})
    assert env.ok is True, env.error
    text = json.dumps(content)
    assert TOKEN not in text
    assert URL_PASS not in text
    assert f"https://{REDACTED}@registry.example.test" in env.data["schedule"]["labelErrors"][0]


def test_get_is_read_tier_in_every_profile() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == GET_TOOL)
    assert entry.tier is Tier.READ
    for profile in Profile:
        assert GET_TOOL in {t.name for t in REGISTRY.tools_for_profile(profile)}, profile
    mcp_tool = entry.tool.to_mcp()  # type: ignore[attr-defined]
    assert mcp_tool.title
    assert mcp_tool.annotations == READ_ANNOTATIONS
    assert mcp_tool.output_schema is not None


# --- set tool ---------------------------------------------------------------------------------

ARGS = {**E, "container": "web", "start": "07:00", "stop": "0 23 * * 1-5"}


async def test_set_both(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, ARGS)
    assert env.ok is True, env.error
    assert env.verified is True
    assert env.environment_id == ENV
    assert env.data["container"] == {"id": WEB, "name": "web"}
    assert env.data["schedule"]["startAt"] == "07:00"
    (put,) = sent(dockhand, "PUT", PATH)
    assert put.url.params["env"] == str(ENV)
    assert json.loads(put.content) == {"startAt": "07:00", "stopAt": "0 23 * * 1-5"}
    # The schedule is read back after the write.
    gets = [c.request.url.path for c in dockhand.calls if c.request.url.path == PATH]
    assert gets == [PATH, PATH, PATH]
    assert [c.request.method for c in dockhand.calls if c.request.url.path == PATH] == [
        "GET",
        "PUT",
        "GET",
    ]


async def test_set_start_only_sends_an_empty_stop(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    after = schedule(startAt="6:30")
    mount(dockhand, set_routes(fx("empty"), after))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web", "start": "6:30"})
    assert env.ok is True, env.error
    assert env.verified is True
    (put,) = sent(dockhand, "PUT", PATH)
    assert json.loads(put.content) == {"startAt": "6:30", "stopAt": ""}


async def test_clear_removes_the_schedule(dockhand: respx.MockRouter, operator_env: SetEnv) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("set"), fx("empty")))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web"})
    assert env.ok is True, env.error
    assert env.verified is True
    (put,) = sent(dockhand, "PUT", PATH)
    assert json.loads(put.content) == {"startAt": "", "stopAt": ""}
    assert env.data["schedule"]["startAt"] is None


async def test_read_back_mismatch_is_verification_failed(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), fx("empty"), put=fx("set")))
    env, _ = await operator_call(SET_TOOL, ARGS)
    assert env.ok is False
    assert env.verified is False
    assert env.error is not None
    assert env.error.code == "verification_failed"
    assert env.data["read_back"]["expected"] == {"startAt": "07:00", "stopAt": "0 23 * * 1-5"}
    assert env.data["read_back"]["actual"] == {"startAt": None, "stopAt": None}


@pytest.mark.parametrize(
    "bad",
    [
        {"start": "24:00"},
        {"start": "7:60"},
        {"start": "07:0"},
        {"start": "7"},
        {"stop": "0 23 * *"},
        {"stop": "0 23 * * 1-5 2026"},
        {"stop": "@daily"},
        {"stop": "0  23 * * *"},
        {"stop": "0 23 * * 1;rm"},
        {"stop": ""},
        {"stop": "0 " * 60 + "*"},
    ],
)
async def test_invalid_format_is_refused_without_writes(
    bad: dict[str, str], dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web", **bad})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


@pytest.mark.parametrize("value", ["0:00", "23:59", "07:00", "*/15 * * * *", "0 7 * * MON-FRI"])
async def test_valid_formats_are_sent(
    value: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), schedule(startAt=value)))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web", "start": value})
    assert env.ok is True, env.error
    (put,) = sent(dockhand, "PUT", PATH)
    assert json.loads(put.content)["startAt"] == value


async def test_unknown_container_is_not_found_without_writes(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, {**ARGS, "container": "nope"})
    assert env.error is not None
    assert env.error.code == "not_found"
    assert writes(dockhand) == []


async def test_stop_on_dockhands_own_container_is_refused(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(schedule(systemContainer=True), fx("set")))
    env, _ = await operator_call(SET_TOOL, ARGS)
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "DockHand" in env.error.message
    assert writes(dockhand) == []


async def test_stop_on_this_servers_container_is_refused(
    dockhand: respx.MockRouter, operator_env: SetEnv, own_container: Any
) -> None:
    operator_env()
    own_container(WEB)
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, ARGS)
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "this MCP server" in env.error.message
    assert writes(dockhand) == []


async def test_this_servers_container_matched_by_short_id(
    dockhand: respx.MockRouter, operator_env: SetEnv, own_container: Any
) -> None:
    operator_env()
    own_container(WEB[:12])  # Docker's default hostname
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web", "stop": "23:00"})
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert writes(dockhand) == []


async def test_a_start_on_this_servers_container_is_allowed(
    dockhand: respx.MockRouter, operator_env: SetEnv, own_container: Any
) -> None:
    operator_env()
    own_container(WEB)
    mount(dockhand, set_routes(fx("empty"), schedule(startAt="07:00")))
    env, _ = await operator_call(SET_TOOL, {**E, "container": "web", "start": "07:00"})
    assert env.ok is True, env.error


async def test_another_container_is_not_protected(
    dockhand: respx.MockRouter, operator_env: SetEnv, own_container: Any
) -> None:
    operator_env()
    own_container(IDS["CID_DB"])
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    env, _ = await operator_call(SET_TOOL, ARGS)
    assert env.ok is True, env.error


async def test_set_redacts_dockhand_free_text(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    after = {**fx("set"), "labelErrors": [LEAK]}
    mount(dockhand, set_routes(fx("empty"), after))
    env, content = await operator_call(SET_TOOL, ARGS)
    assert env.ok is True, env.error
    text = json.dumps(content)
    assert TOKEN not in text
    assert URL_PASS not in text


async def test_set_calls_only_declared_endpoints(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount(dockhand, set_routes(fx("empty"), fx("set")))
    called = Called()
    await operator_call(SET_TOOL, ARGS, called)
    assert set(called.endpoints) == {LIST, STACKS, SA, SA_PUT}
    assert declared(SET_TOOL) == {ENVIRONMENTS, LIST, STACKS, SA, SA_PUT}


@pytest.mark.parametrize(("profile", "visible"), [("read-only", False), ("operator", True)])
async def test_set_is_absent_from_the_read_only_profile(
    base_env: SetEnv, profile: str, visible: bool
) -> None:
    base_env(DOCKHAND_MCP_PROFILE=profile)
    async with mcp_client(create_app(load_settings())) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert (SET_TOOL in names) is visible
    assert GET_TOOL in names


def test_set_metadata() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == SET_TOOL)
    assert entry.tier is Tier.OPERATOR
    mcp_tool = entry.tool.to_mcp()  # type: ignore[attr-defined]
    assert mcp_tool.title
    assert mcp_tool.annotations == OPERATOR_IDEMPOTENT_ANNOTATIONS
    assert mcp_tool.annotations.destructive_hint is False
    assert mcp_tool.output_schema is not None


# --- this server's own container ----------------------------------------------------------------

LONG = IDS["CID_WORKER"]


def mountinfo(*lines: str) -> str:
    return "".join(line + "\n" for line in lines)


@pytest.mark.parametrize(
    "line",
    [
        # Docker
        f"612 590 8:1 /var/lib/docker/containers/{LONG}/hostname /etc/hostname rw,relatime - "
        "ext4 /dev/sda1 rw",
        # rootless Docker
        f"612 590 0:41 /home/u/.local/share/docker/containers/{LONG}/hostname /etc/hostname "
        "rw - btrfs /dev/vda2 rw",
        # Podman
        f"612 590 0:41 /var/lib/containers/storage/overlay-containers/{LONG}/userdata/hostname "
        "/etc/hostname rw - xfs /dev/vda2 rw",
    ],
)
def test_own_id_from_the_hostname_mount(line: str) -> None:
    text = mountinfo("600 1 0:50 / / ro - overlay overlay rw", line)
    assert own().discover(text, "web-host") == frozenset({LONG})


def test_other_containers_mounts_on_a_docker_host_are_ignored() -> None:
    # In the host's mount namespace, other containers' shm mounts are listed; none is ours.
    text = mountinfo(
        f"700 30 0:60 / /var/lib/docker/containers/{LONG}/mounts/shm rw - tmpfs shm rw",
        f"701 30 8:1 /var/lib/docker/containers/{LONG}/hostname /var/x rw - ext4 /dev/sda1 rw",
    )
    assert own().discover(text, "workstation") == frozenset()


def test_own_id_falls_back_to_a_container_hostname() -> None:
    assert own().discover("", LONG[:12]) == frozenset({LONG[:12]})
    assert own().discover(None, LONG[:12]) == frozenset({LONG[:12]})


@pytest.mark.parametrize("hostname", ["workstation", "ABCDEF012345", LONG[:11], LONG[:13], ""])
def test_other_hostnames_are_not_ids(hostname: str) -> None:
    assert own().discover(None, hostname) == frozenset()


def test_matches_by_prefix_both_ways() -> None:
    assert own().matches(LONG, frozenset({LONG[:12]}))
    assert own().matches(LONG[:12], frozenset({LONG}))
    assert not own().matches(LONG, frozenset({IDS["CID_DB"]}))
    assert not own().matches(LONG, frozenset())
    assert not own().matches("", frozenset({LONG}))


# --- run / toggle allowlists --------------------------------------------------------------------

CONTAINER_TYPES = ("container_start", "container_stop")
# Every other type the spec lists for run or toggle (besides the three already allowed).
REFUSED = (
    "image_prune",
    "repo_prune",
    "backup",
    "repo_check",
    "repo_verify",
    "system_cleanup",
    "deploy_log_reconcile",
)


def test_allowlists_are_exactly_the_operator_types() -> None:
    allowed = {"container_update", "git_stack_sync", "env_update_check", *CONTAINER_TYPES}
    assert set(get_args(schedules.RunnableType)) == allowed
    assert set(get_args(schedules.ToggleType)) == allowed | {"system"}


@pytest.mark.parametrize("schedule_type", CONTAINER_TYPES)
async def test_run_accepts_container_types(
    schedule_type: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    path = f"/api/schedules/{schedule_type}/5/run"
    mount(dockhand, [("POST", path, load_fixture("schedules", "run"))])
    env, _ = await operator_call(
        "dockhand_run_schedule_now", {"schedule_type": schedule_type, "schedule_id": 5}
    )
    assert env.ok is True, env.error
    assert [c.request.url.path for c in dockhand.calls] == [path]


@pytest.mark.parametrize("schedule_type", CONTAINER_TYPES)
async def test_toggle_accepts_container_types(
    schedule_type: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    path = f"/api/schedules/{schedule_type}/5/toggle"
    mount(dockhand, [("POST", path, load_fixture("schedules", "toggle"))])
    env, _ = await operator_call(
        "dockhand_toggle_schedule", {"schedule_type": schedule_type, "schedule_id": 5}
    )
    assert env.ok is True, env.error
    assert [c.request.url.path for c in dockhand.calls] == [path]


@pytest.mark.parametrize("tool", ["dockhand_run_schedule_now", "dockhand_toggle_schedule"])
@pytest.mark.parametrize("schedule_type", REFUSED)
async def test_other_types_still_refused(
    tool: str, schedule_type: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await operator_call(tool, {"schedule_type": schedule_type, "schedule_id": 1})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


def test_module_registers_both_tools() -> None:
    names = {t.name for t in REGISTRY.all()}
    assert {GET_TOOL, SET_TOOL} <= names


# --- one Docker daemon, several environments ----------------------------------------------------
# Rule (maintainer decision): (1) the container's compose project is a stack tracked in the
# requested environment → allowed; (2) otherwise, no other environment lists the container (by id)
# → allowed; (3) otherwise → guardrail_blocked, naming the other environments and the one tracking
# its stack, if any; (4) a stack or container list that cannot be read → refused. The read tool
# answers in every case, with a warning where (3) or (4) would refuse.

OTHER = 8
SHARED = load_fixture("containers", "list")  # web and db (stack shop), worker (standalone)


def item(name: str, project: str | None) -> dict[str, Any]:
    found = next(c for c in SHARED if c["name"] == name)
    labels = {} if project is None else {"com.docker.compose.project": project}
    return {**found, "labels": labels}


def by_env(bodies: dict[int, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answer per `env` query parameter; an int body is an HTTP status."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = bodies[int(request.url.params["env"])]
        if isinstance(body, int):
            return httpx.Response(body, json={"error": "Internal error"})
        return httpx.Response(200, json=body)

    return answer


def environments(*ids: int) -> list[dict[str, Any]]:
    return [{"id": i, "name": f"env-{i}"} for i in ids]


def stacks(*tracked: str, untracked: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    return [
        *({"name": n, "sourceType": "internal", "status": "running"} for n in tracked),
        *({"name": n, "status": "running"} for n in untracked),
    ]


def daemon(
    dockhand: respx.MockRouter,
    *,
    containers_by_env: dict[int, Any],
    stacks_by_env: dict[int, Any],
    envs: Any,
    name: str = "web",
) -> None:
    """Mock a deployment: per-environment container and stack lists, the environment list (or an
    HTTP status), and `name`'s schedule (none before the write, a stop at 23:00 after)."""
    dockhand.get("/api/containers").mock(side_effect=by_env(containers_by_env))
    dockhand.get("/api/stacks").mock(side_effect=by_env(stacks_by_env))
    if isinstance(envs, int):
        dockhand.get("/api/environments").respond(envs, json={"error": "Internal error"})
    else:
        dockhand.get("/api/environments").respond(200, json=envs)
    path = f"/api/scheduled-actions/{name}"
    after = schedule(stopAt="23:00")
    answers = [httpx.Response(200, json=fx("empty")), httpx.Response(200, json=after)]
    dockhand.get(path).mock(side_effect=answers)
    dockhand.put(path).respond(200, json=after)


def stop(name: str = "web") -> dict[str, Any]:
    return {**E, "container": name, "stop": "23:00"}


def listed_envs(dockhand: respx.MockRouter) -> list[int]:
    return sorted(
        int(c.request.url.params["env"])
        for c in dockhand.calls
        if c.request.url.path == "/api/containers"
    )


async def test_rule1_tracked_here_is_allowed_without_reading_other_environments(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    daemon(
        dockhand,
        containers_by_env={ENV: SHARED, OTHER: SHARED},
        stacks_by_env={ENV: stacks("shop"), OTHER: stacks(untracked=("shop",))},
        envs=environments(ENV, OTHER),
    )
    env, _ = await operator_call(SET_TOOL, stop())
    assert env.ok is True, env.error
    assert listed_envs(dockhand) == [ENV]
    assert not [c for c in dockhand.calls if c.request.url.path == "/api/environments"]


@pytest.mark.parametrize("name", ["web", "worker"])
async def test_rule2_single_environment_untracked_and_standalone_are_allowed(
    name: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    daemon(
        dockhand,
        containers_by_env={ENV: [item("web", "adhoc"), item("worker", None)]},
        stacks_by_env={ENV: stacks("shop")},
        envs=environments(ENV),
        name=name,
    )
    env, _ = await operator_call(SET_TOOL, stop(name))
    assert env.ok is True, env.error
    assert len(writes(dockhand)) == 1


async def test_rule2_another_environment_not_listing_it_is_allowed(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    daemon(
        dockhand,
        containers_by_env={ENV: [item("worker", None)], OTHER: [item("db", None)]},
        stacks_by_env={ENV: stacks()},
        envs=environments(ENV, OTHER),
        name="worker",
    )
    env, _ = await operator_call(SET_TOOL, stop("worker"))
    assert env.ok is True, env.error
    assert listed_envs(dockhand) == [ENV, OTHER]


@pytest.mark.parametrize(
    ("name", "here", "there", "expected"),
    [
        ("web", stacks(untracked=("shop",)), stacks("shop"), "tracked in environment 8"),
        ("web", stacks(untracked=("shop",)), stacks(untracked=("shop",)), "not tracked in"),
        ("worker", stacks(), stacks(), "belongs to no stack"),
    ],
    ids=["tracked-elsewhere", "tracked-nowhere", "standalone"],
)
@pytest.mark.parametrize("times", [{"stop": "23:00"}, {"start": "07:00"}, {}], ids=str)
async def test_rule3_listed_elsewhere_and_not_tracked_here_is_refused(
    name: str,
    here: Any,
    there: Any,
    expected: str,
    times: dict[str, str],
    dockhand: respx.MockRouter,
    operator_env: SetEnv,
) -> None:
    operator_env()
    daemon(
        dockhand,
        containers_by_env={ENV: SHARED, OTHER: SHARED},
        stacks_by_env={ENV: here, OTHER: there},
        envs=environments(ENV, OTHER),
        name=name,
    )
    env, _ = await operator_call(SET_TOOL, {**E, "container": name, **times})
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "environment 8" in env.error.message
    assert expected in env.error.message
    assert writes(dockhand) == []


@pytest.mark.parametrize(
    ("containers_by_env", "stacks_by_env", "envs"),
    [
        ({ENV: SHARED, OTHER: SHARED}, {ENV: 500}, environments(ENV, OTHER)),
        ({ENV: SHARED, OTHER: SHARED}, {ENV: stacks()}, 500),
        ({ENV: SHARED, OTHER: 500}, {ENV: stacks()}, environments(ENV, OTHER)),
    ],
    ids=["stack-list", "environment-list", "other-container-list"],
)
async def test_rule4_an_unreadable_list_refuses(
    containers_by_env: dict[int, Any],
    stacks_by_env: dict[int, Any],
    envs: Any,
    dockhand: respx.MockRouter,
    operator_env: SetEnv,
) -> None:
    operator_env()
    daemon(
        dockhand,
        containers_by_env=containers_by_env,
        stacks_by_env=stacks_by_env,
        envs=envs,
        name="worker",
    )
    env, _ = await operator_call(SET_TOOL, stop("worker"))
    assert env.error is not None
    assert env.error.code == "guardrail_blocked"
    assert "nothing was done" in env.error.message.lower()
    assert writes(dockhand) == []


async def test_read_tool_warns_when_another_environment_lists_it(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    daemon(
        dockhand,
        containers_by_env={ENV: SHARED, OTHER: SHARED},
        stacks_by_env={ENV: stacks(untracked=("shop",)), OTHER: stacks("shop")},
        envs=environments(ENV, OTHER),
    )
    env, _, _ = await read_call(GET_TOOL, {**E, "container": "web"})
    assert env.ok is True, env.error
    assert env.warnings is not None
    assert any("environment 8" in w for w in env.warnings)


async def test_read_tool_warns_when_a_list_cannot_be_read(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    daemon(
        dockhand,
        containers_by_env={ENV: SHARED, OTHER: 500},
        stacks_by_env={ENV: stacks()},
        envs=environments(ENV, OTHER),
        name="worker",
    )
    env, _, _ = await read_call(GET_TOOL, {**E, "container": "worker"})
    assert env.ok is True, env.error
    assert env.warnings is not None
    assert any("could not" in w for w in env.warnings)


@pytest.mark.parametrize(
    ("containers_by_env", "stacks_by_env", "name"),
    [
        ({ENV: SHARED, OTHER: SHARED}, {ENV: stacks("shop")}, "web"),
        ({ENV: SHARED, OTHER: []}, {ENV: stacks()}, "worker"),
    ],
    ids=["rule1", "rule2"],
)
async def test_read_tool_has_no_warning_when_the_set_tool_would_allow(
    containers_by_env: dict[int, Any],
    stacks_by_env: dict[int, Any],
    name: str,
    dockhand: respx.MockRouter,
    base_env: SetEnv,
) -> None:
    base_env()
    daemon(
        dockhand,
        containers_by_env=containers_by_env,
        stacks_by_env=stacks_by_env,
        envs=environments(ENV, OTHER),
        name=name,
    )
    env, _, _ = await read_call(GET_TOOL, {**E, "container": name})
    assert env.ok is True, env.error
    assert env.warnings is None
