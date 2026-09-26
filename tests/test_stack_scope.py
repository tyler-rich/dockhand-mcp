# SPDX-License-Identifier: Apache-2.0
"""Stack environment scoping (S3g): a stack listed in an environment may belong to another one.

Live DockHand 1.0.46, two environments on one Docker daemon: `GET /api/stacks?env=N` answers
the stacks DockHand has a source record for in N (with `sourceType`) together with the compose
projects it discovers from container labels on N's daemon (no `sourceType`), which includes
every running stack of the other environment. The items carry no environment field.

So `dockhand_list_stacks` keeps every stack and says which are `tracked` (have a source record
in the requested environment), and every tool that writes to an existing stack, operator and
destructive, preview included, first confirms the stack is tracked there: otherwise
`not_found`, and not one write request.
"""

from typing import Any, Final

import pytest
import respx
from conftest import ENV, SetEnv, load_fixture
from test_destructive_tools import CASES as DESTRUCTIVE_CASES
from test_destructive_tools import call, never_asked
from test_operator_tools import CASES as OPERATOR_CASES
from test_operator_tools import Route, fx, mount

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.tools.registry import REGISTRY, Tier

E: Final = {"environment_id": ENV}
LIST: Final = ("GET", "/api/stacks")

# Every non-read tool that writes to an existing stack by name, from the registry: it declares a
# non-GET under /api/stacks/{name}. `dockhand_create_stack` declares one too (DockHand's
# validator, called for the stack it is about to create), but targets no existing stack.
NAMED_STACK_WRITES: Final = sorted(
    t.name
    for t in REGISTRY.all()
    if t.tier is not Tier.READ
    and t.name != "dockhand_create_stack"
    and any(m != "GET" and p.startswith("/api/stacks/{name}") for m, p in t.endpoints)
)


def test_the_stack_write_list_comes_from_the_registry() -> None:
    assert NAMED_STACK_WRITES == [
        "dockhand_delete_stack",
        "dockhand_deploy_stack",
        "dockhand_down_stack",
        "dockhand_modify_stack_env",
        "dockhand_restart_stack",
        "dockhand_start_stack",
        "dockhand_stop_stack",
        "dockhand_update_stack_compose",
        "dockhand_update_stack_env_raw",
    ]


@pytest.mark.parametrize("tool", NAMED_STACK_WRITES)
def test_every_stack_write_declares_the_stack_list(tool: str) -> None:
    endpoints = next(t for t in REGISTRY.all() if t.name == tool).endpoints
    assert LIST in endpoints


@pytest.fixture(autouse=True)
def admin(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="admin", DOCKHAND_MCP_CONFIRM_MODE="param")


def shared_daemon_list() -> Any:
    """`tools` has a source record here; `shop` is only discovered (another environment's)."""
    return load_fixture("stacks", "list-shared-daemon")


def routes_for(tool: str, stack_list: Any) -> tuple[dict[str, Any], list[Route]]:
    """The tool's usual arguments and routes (so any write it sent would be answered)."""
    if tool in DESTRUCTIVE_CASES:
        case = DESTRUCTIVE_CASES[tool]
        routes = [*case.reads, case.write, *case.after]
        args = {**case.args, "confirm": True}
    else:
        args, routes = OPERATOR_CASES[tool]
    routes = [r for r in routes if (r[0], r[1]) != LIST]
    return args, [(*LIST, stack_list), *routes]


def writes(dockhand: respx.MockRouter) -> list[tuple[str, str]]:
    return [
        (c.request.method, c.request.url.path) for c in dockhand.calls if c.request.method != "GET"
    ]


async def run(tool: str, dockhand: respx.MockRouter, stack_list: Any) -> Envelope:
    args, routes = routes_for(tool, stack_list)
    mount(dockhand, routes)
    return await call(tool, args, human=never_asked)


# --- list_stacks ------------------------------------------------------------------------------


async def test_list_stacks_says_which_stacks_are_tracked_here(dockhand: respx.MockRouter) -> None:
    mount(dockhand, [(*LIST, shared_daemon_list())])
    envelope = await call("dockhand_list_stacks", E)
    assert envelope.ok is True
    assert isinstance(envelope.data, dict)
    tracked = {i["name"]: i["tracked"] for i in envelope.data["items"]}
    assert tracked == {"tools": True, "shop": False}


async def test_list_stacks_tracked_follows_source_type(dockhand: respx.MockRouter) -> None:
    mount(dockhand, [(*LIST, fx("stacks", "list"))])
    envelope = await call("dockhand_list_stacks", E)
    assert isinstance(envelope.data, dict)
    assert all(i["tracked"] is True for i in envelope.data["items"])


# --- every write to an existing stack ---------------------------------------------------------


@pytest.mark.parametrize("tool", NAMED_STACK_WRITES)
async def test_a_stack_only_discovered_here_is_not_found_and_nothing_is_written(
    tool: str, dockhand: respx.MockRouter
) -> None:
    envelope = await run(tool, dockhand, shared_daemon_list())
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "not_found", envelope.error
    assert "shop" in envelope.error.message
    assert writes(dockhand) == []


@pytest.mark.parametrize("tool", NAMED_STACK_WRITES)
async def test_a_stack_not_listed_at_all_is_not_found_and_nothing_is_written(
    tool: str, dockhand: respx.MockRouter
) -> None:
    envelope = await run(tool, dockhand, [])
    assert envelope.error is not None
    assert envelope.error.code == "not_found", envelope.error
    assert writes(dockhand) == []


@pytest.mark.parametrize("tool", NAMED_STACK_WRITES)
async def test_a_tracked_stack_is_written_as_before(tool: str, dockhand: respx.MockRouter) -> None:
    envelope = await run(tool, dockhand, fx("stacks", "list"))
    assert envelope.ok is True, envelope.error
    assert len(writes(dockhand)) >= 1
