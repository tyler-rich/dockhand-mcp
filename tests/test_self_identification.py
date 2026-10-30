# SPDX-License-Identifier: Apache-2.0
"""This server's own container, when it cannot be identified (#19 follow-up).

`dockhand_set_scheduled_actions` refuses a scheduled stop of the container this server runs in,
which it finds from its own mount table or hostname. When neither names an id, the protection
cannot apply; that must not be silent. `dockhand-mcp check` reports it (a problem when the server
appears to run in a container, a warning otherwise) and `serve` logs a WARN at startup, whenever
the profile registers the set tool. Stops are not refused because of it.
"""

import importlib
import json
import logging
from types import ModuleType
from typing import Any

import pytest
import respx
from conftest import DOCKHAND_TOKEN, SetEnv, healthy_dockhand

from dockhand_mcp.__main__ import main
from dockhand_mcp.config import load_settings

LONG = "f" * 64
UNIDENTIFIED = "cannot identify own container; scheduled stops cannot be refused for it"
HOSTNAME_MOUNT_WITHOUT_ID = (
    "612 590 0:41 /var/lib/kubelet/pods/0a1b/etc-hosts /etc/hostname rw - ext4 /dev/vda2 rw\n"
)
HOST_TABLE = "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"


def own() -> ModuleType:
    return importlib.import_module("dockhand_mcp.guardrails.self_container")


def startup() -> ModuleType:
    return importlib.import_module("dockhand_mcp.startup")


@pytest.fixture
def identity(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Make this server see itself as `ids` (empty: unidentified), in a container or not."""

    def _set(ids: frozenset[str], in_container: bool) -> None:
        module = own()
        found = module.Identity(ids=ids, in_container=in_container)
        monkeypatch.setattr(module, "identify", lambda: found)

    return _set


def mock_dockhand(router: respx.MockRouter) -> None:
    healthy_dockhand(router)
    router.get("/api/auth/settings").respond(200, json={"authEnabled": True})
    router.get("/api/environments").respond(200, json=[{"id": 7, "name": "example"}])
    router.get("/api/roles").respond(403, content=b"x")
    for domain in ("containers", "stacks", "images", "volumes", "networks"):
        router.get(f"/api/{domain}").respond(200, json=[])


def run_check(capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any], str]:
    code = main(["check"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out) if captured.out else {}, captured.err


# --- detection --------------------------------------------------------------------------------


def test_a_hostname_mount_without_an_id_is_a_container() -> None:
    assert own().discover(HOSTNAME_MOUNT_WITHOUT_ID, "my-service") == frozenset()
    assert own().in_container(HOSTNAME_MOUNT_WITHOUT_ID, markers=False) is True


def test_a_runtime_marker_file_is_a_container() -> None:
    assert own().in_container(HOST_TABLE, markers=True) is True
    assert own().in_container(None, markers=True) is True


def test_a_host_table_is_not_a_container() -> None:
    assert own().in_container(HOST_TABLE, markers=False) is False
    assert own().in_container(None, markers=False) is False


# --- check ------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["operator", "admin"])
def test_check_reports_an_unidentified_container_as_a_problem(
    profile: str,
    identity: Any,
    base_env: SetEnv,
    dockhand: respx.MockRouter,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity(frozenset(), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE=profile)
    mock_dockhand(dockhand)
    code, report, _ = run_check(capsys)
    assert code == 1
    assert [p for p in report["problems"] if p.startswith(UNIDENTIFIED)], report["problems"]
    assert "hostname" in next(p for p in report["problems"] if p.startswith(UNIDENTIFIED))


def test_check_warns_when_it_may_not_be_in_a_container(
    identity: Any, base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    identity(frozenset(), False)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    mock_dockhand(dockhand)
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert report["problems"] == []
    assert f"warning: {UNIDENTIFIED}" in err


@pytest.mark.parametrize(
    "env",
    [
        {"DOCKHAND_MCP_PROFILE": "read-only"},
        {
            "DOCKHAND_MCP_PROFILE": "operator",
            "DOCKHAND_MCP_DISABLE_TOOLS": "dockhand_set_scheduled_actions",
        },
    ],
    ids=["read-only", "set-tool-disabled"],
)
def test_check_is_quiet_without_the_set_tool(
    env: dict[str, str],
    identity: Any,
    base_env: SetEnv,
    dockhand: respx.MockRouter,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity(frozenset(), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, **env)
    mock_dockhand(dockhand)
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert UNIDENTIFIED not in err
    assert not [p for p in report["problems"] if UNIDENTIFIED in p]


def test_check_is_quiet_when_identified(
    identity: Any, base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    identity(frozenset({LONG}), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    mock_dockhand(dockhand)
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert UNIDENTIFIED not in err


def test_check_reports_it_even_when_dockhand_is_unreachable(
    identity: Any, base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    identity(frozenset(), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    dockhand.get("/api/health").respond(503, json={"error": "down"})
    _, report, _ = run_check(capsys)
    assert [p for p in report["problems"] if p.startswith(UNIDENTIFIED)]


# --- serve ------------------------------------------------------------------------------------


@pytest.mark.parametrize("in_container", [True, False])
def test_startup_logs_a_warn(
    in_container: bool, identity: Any, base_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    identity(frozenset(), in_container)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    with caplog.at_level(logging.WARNING, logger="dockhand_mcp.startup"):
        startup().warn_if_unidentified(load_settings())
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert [r for r in warns if UNIDENTIFIED in r.getMessage()]


def test_startup_is_quiet_when_identified_or_without_the_set_tool(
    identity: Any, base_env: SetEnv, caplog: pytest.LogCaptureFixture
) -> None:
    identity(frozenset({LONG}), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    with caplog.at_level(logging.WARNING, logger="dockhand_mcp.startup"):
        startup().warn_if_unidentified(load_settings())
    identity(frozenset(), True)
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="read-only")
    with caplog.at_level(logging.WARNING, logger="dockhand_mcp.startup"):
        startup().warn_if_unidentified(load_settings())
    assert not [r for r in caplog.records if UNIDENTIFIED in r.getMessage()]


def test_serve_runs_the_startup_warning(
    base_env: SetEnv, monkeypatch: pytest.MonkeyPatch, dockhand: respx.MockRouter
) -> None:
    import uvicorn

    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_PROFILE="operator")
    seen: list[str] = []
    monkeypatch.setattr(startup(), "warn_if_unidentified", lambda s: seen.append(s.profile.value))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    assert main(["serve"]) == 0
    assert seen == ["operator"]


def test_the_set_tool_still_allows_stops_when_unidentified() -> None:
    # Visibility only: nothing is refused because the id is unknown.
    assert own().matches(LONG, frozenset()) is False
