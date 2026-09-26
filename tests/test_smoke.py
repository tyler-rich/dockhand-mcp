# SPDX-License-Identifier: Apache-2.0
"""scripts/smoke.py: the plan runner against the in-process app with a mocked DockHand."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import respx
from conftest import (
    DOCKHAND_TOKEN,
    DOCKHAND_URL,
    MCP_TOKEN,
    SetEnv,
    fake_dh_token,
    healthy_dockhand,
    mcp_client,
)
from test_endpoint_map import ENDPOINT_MAP, parse_endpoint_map

from dockhand_mcp.client.dockhand import DockhandClient, UndeclaredEndpointError, declared_endpoints
from dockhand_mcp.config import load_settings
from dockhand_mcp.tools.registry import REGISTRY, Tier
from dockhand_mcp.transport.app import create_app

SMOKE = Path(__file__).resolve().parents[1] / "scripts" / "smoke.py"


@pytest.fixture(scope="module")
def smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("smoke", SMOKE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["smoke"] = module
    spec.loader.exec_module(module)
    return module


GOOD_PLAN: list[dict[str, Any]] = [
    {"tool": "dockhand_health", "args": {}, "expect": {"ok": True}},
    {
        "tool": "dockhand_health",
        "expect": {
            "equals": {"data.database.healthy": True, "data.dockhand.status": "ok"},
            "not_equals": {"data.database.pendingMigrations": 1},
        },
    },
    {
        "tool": "dockhand_get_operation",
        "args": {"op_id": "7f1c1c2e-8f5a-4d7e-9a57-0d6f9b1f2a10"},
        "expect": {"ok": False, "error.code": "operation_unknown"},
    },
]


async def run(smoke: ModuleType, plan: list[dict[str, Any]], **kwargs: Any) -> tuple[int, str]:
    lines: list[str] = []
    async with mcp_client(create_app(load_settings())) as c:
        code = await smoke.run_plan(c, plan, out=lines.append, **kwargs)
    return code, "\n".join(lines)


async def test_good_plan_passes(
    smoke: ModuleType, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    code, out = await run(smoke, GOOD_PLAN)
    assert code == 0, out
    assert out.count("dockhand_health") >= 2
    assert "operation_unknown" in out
    assert MCP_TOKEN not in out


async def test_failed_expectation_exits_non_zero(
    smoke: ModuleType, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    plan = [
        {"tool": "dockhand_health", "expect": {"ok": True}},
        {"tool": "dockhand_health", "expect": {"equals": {"data.database.healthy": False}}},
    ]
    code, out = await run(smoke, plan)
    assert code != 0
    assert "FAIL" in out
    assert "data.database.healthy" in out


async def test_show_prints_redacted_payloads(
    smoke: ModuleType, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    status = fake_dh_token("SecretishValue")
    dockhand.get("/api/health").respond(200, json={"status": status, "timestamp": "t"})
    dockhand.get("/api/health/database").respond(200, json={"healthy": True})
    code, out = await run(smoke, [{"tool": "dockhand_health"}], show=True)
    assert code == 0
    assert "dh_***" in out
    assert "SecretishValue" not in out


def test_payloads_hidden_without_show(smoke: ModuleType) -> None:
    line = smoke.summary_line(
        "dockhand_x", {"ok": True, "data": {"items": [1, 2, 3], "a": 1}}, 0.01
    )
    assert "dockhand_x" in line
    assert "ok" in line
    assert "items=3" in line
    assert "[1, 2, 3]" not in line


@pytest.mark.parametrize(
    ("expect", "failures"),
    [
        ({"ok": True}, 0),
        ({"ok": False}, 1),
        ({"error.code": "not_found"}, 1),
        ({"verified": True}, 1),
        ({"equals": {"data.a.b": 2}}, 0),
        ({"equals": {"data.a.missing": 2}}, 1),
        ({"not_equals": {"data.a.b": 3}}, 0),
        ({"not_equals": {"data.a.b": 2}}, 1),
        ({"bogus": 1}, 1),
    ],
)
def test_expectations(smoke: ModuleType, expect: dict[str, Any], failures: int) -> None:
    result = {"ok": True, "data": {"a": {"b": 2}}}
    assert len(smoke.check_expectations(result, expect)) == failures


def test_plan_file_must_be_a_list_of_steps(smoke: ModuleType, tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps(GOOD_PLAN), encoding="utf-8")
    assert smoke.load_plan(good) == GOOD_PLAN
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"tool": "x"}), encoding="utf-8")
    with pytest.raises(ValueError):
        smoke.load_plan(bad)


def test_token_comes_from_the_token_file_only(smoke: ModuleType, tmp_path: Path) -> None:
    token_file = tmp_path / "mcp_token"
    token_file.write_text(MCP_TOKEN + "\n", encoding="utf-8")
    assert smoke.load_token({"DOCKHAND_MCP_TOKEN_FILE": str(token_file)}) == MCP_TOKEN
    with pytest.raises(SystemExit):
        smoke.load_token({"DOCKHAND_MCP_TOKEN": MCP_TOKEN})


def test_argv_has_no_token_option(smoke: ModuleType) -> None:
    with pytest.raises(SystemExit):
        smoke.parse_args(["--token", MCP_TOKEN, "list"])


# --- saved values, any_of, each_matches (S2) --------------------------------------------------


def test_substitute_replaces_whole_placeholders_only(smoke: ModuleType) -> None:
    saved = {"env": 7, "name": "web"}
    args = {"environment_id": "${env}", "ref": "${name}", "note": "x ${env}", "list": ["${env}"]}
    out, missing = smoke.substitute(args, saved)
    assert out == {"environment_id": 7, "ref": "web", "note": "x ${env}", "list": [7]}
    assert missing == []
    _, missing = smoke.substitute({"a": "${nope}"}, saved)
    assert missing == ["nope"]


def test_save_values_with_default(smoke: ModuleType) -> None:
    saved: dict[str, Any] = {}
    result = {"data": {"items": [{"id": 3}]}}
    spec = {"a": "data.items.0.id", "b": {"path": "data.items.5.id", "default": 1}, "c": "data.x"}
    assert smoke.save_values(result, spec, saved) == ["c"]
    assert saved == {"a": 3, "b": 1}


@pytest.mark.parametrize(
    ("expect", "failures"),
    [
        ({"each_matches": {"data.env": "[^=]+(=<redacted>)?"}}, 0),
        ({"each_matches": {"data.bad": "[^=]+(=<redacted>)?"}}, 1),
        ({"each_matches": {"data.missing": "x"}}, 1),
        ({"any_of": [{"ok": False}, {"equals": {"data.n": 1}}]}, 0),
        ({"any_of": [{"ok": False}, {"error.code": "not_found"}]}, 1),
    ],
)
def test_new_expectations(smoke: ModuleType, expect: dict[str, Any], failures: int) -> None:
    result = {
        "ok": True,
        "data": {"env": ["A=<redacted>", "FLAG"], "bad": ["A=<redacted>", "B=plain"], "n": 1},
    }
    assert len(smoke.check_expectations(result, expect)) == failures


async def test_plan_uses_saved_values_and_skips_unsaved(
    smoke: ModuleType, dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    healthy_dockhand(dockhand)
    plan = [
        {"tool": "dockhand_health", "save": {"status": "data.dockhand.status", "gone": "data.x"}},
        {
            "tool": "dockhand_health",
            "expect": {"equals": {"data.dockhand.status": "${status}"}},
        },
        {"tool": "dockhand_get_operation", "args": {"op_id": "${gone}"}},
    ]
    code, out = await run(smoke, plan)
    assert code == 0, out
    assert "nothing to save for: gone" in out
    assert "[3] dockhand_get_operation SKIP" in out
    assert "2/2 steps passed, 1 skipped" in out


def test_read_plan_calls_every_read_tool(smoke: ModuleType) -> None:
    from dockhand_mcp.tools.registry import REGISTRY, Tier

    plan = smoke.load_plan(SMOKE.parent / "smoke-plans" / "read.json")
    called = {step["tool"] for step in plan}
    read = {t.name for t in REGISTRY.all() if t.tier is Tier.READ}
    assert read <= called
    redaction = [
        step
        for step in plan
        if step["tool"] == "dockhand_get_container" and "each_matches" in step.get("expect", {})
    ]
    assert redaction[0]["expect"]["each_matches"] == {"data.Config.Env": "[^=]+(=<redacted>)?"}
    assert all(set(step.get("expect", {})) <= smoke.EXPECT_KEYS for step in plan)


# --- write plans and cleanup (S3a) ------------------------------------------------------------

OPERATOR_PLAN = SMOKE.parent / "smoke-plans" / "operator.json"
TEST_ENV = 7


def test_includes_expectation(smoke: ModuleType) -> None:
    result = {"ok": True, "warnings": ["a", "b"]}
    assert smoke.check_expectations(result, {"includes": {"warnings": "b"}}) == []
    assert len(smoke.check_expectations(result, {"includes": {"warnings": "c"}})) == 1
    assert len(smoke.check_expectations(result, {"includes": {"missing": "c"}})) == 1


def test_operator_plan_is_a_pinned_write_plan(smoke: ModuleType) -> None:
    plan = smoke.load_plan(OPERATOR_PLAN)
    assert smoke.is_write_plan(plan)
    assert smoke.check_write_plan(plan, TEST_ENV) == TEST_ENV
    assert all(set(step.get("expect", {})) <= smoke.EXPECT_KEYS for step in plan)
    tools = [step["tool"] for step in plan]
    for tool in (
        "dockhand_create_stack",
        "dockhand_update_stack_compose",
        "dockhand_modify_stack_env",
        "dockhand_deploy_stack",
        "dockhand_list_stack_deploys",
        "dockhand_get_stack_deploy_log",
        "dockhand_restart_stack",
        "dockhand_stop_stack",
    ):
        assert tool in tools
    seed = smoke.write_plan_seed(TEST_ENV)
    assert seed["test_env"] == TEST_ENV
    assert seed["smoke_stack"].startswith("mcp-smoke-")
    assert seed["smoke_stack"] != smoke.write_plan_seed(TEST_ENV)["smoke_stack"]


def test_write_plan_refused_without_a_test_environment(smoke: ModuleType) -> None:
    plan = smoke.load_plan(OPERATOR_PLAN)
    with pytest.raises(smoke.PlanRefusedError, match="DOCKHAND_MCP_TEST_ENVIRONMENT_ID"):
        smoke.check_write_plan(plan, None)
    assert smoke.read_test_environment({}) is None
    with pytest.raises(smoke.PlanRefusedError):
        smoke.read_test_environment({"DOCKHAND_MCP_TEST_ENVIRONMENT_ID": "seven"})


def test_main_refuses_a_write_plan_before_any_call(
    smoke: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    # No token file is needed: the refusal comes first.
    assert smoke.main(["run", str(OPERATOR_PLAN)]) == 2
    assert "refused" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        {"environment_id": 8, "stack": "${smoke_stack}"},
        {"environment_id": "${test_env}", "stack": "production"},
        {"environment_id": "${test_env}", "name": "mcp-smoke-other"},
        {"environment_id": "${test_env}", "stack": "${smoke_stack}", "ref": "web"},
        {"environment_id": "${test_env}", "git_stack_id": 1},
        {"environment_id": "${test_env}", "volume": "data"},
    ],
)
def test_write_plan_steps_are_pinned(smoke: ModuleType, args: dict[str, Any]) -> None:
    plan = [{"tool": "dockhand_get_stack_compose", "args": {"stack": "${smoke_stack}"}}]
    plan.append({"tool": "dockhand_anything", "args": args})
    with pytest.raises(smoke.PlanRefusedError):
        smoke.check_write_plan(plan, TEST_ENV)


def test_read_plan_is_not_a_write_plan(smoke: ModuleType) -> None:
    assert not smoke.is_write_plan(smoke.load_plan(SMOKE.parent / "smoke-plans" / "read.json"))


@pytest.mark.parametrize(
    ("name", "environment_id", "prefix"),
    [
        ("production", TEST_ENV, "mcp-smoke-"),
        ("smoke-mcp-1", TEST_ENV, "mcp-smoke-"),
        ("mcp-smoke-1", TEST_ENV + 1, "mcp-smoke-"),
        ("mcp-smoke-1", TEST_ENV, "mcp-"),
        ("shop", TEST_ENV, ""),
        ("mcp-smoke-../x", TEST_ENV, "mcp-smoke-"),
    ],
)
def test_cleanup_guard_refuses(
    smoke: ModuleType, name: str, environment_id: int, prefix: str
) -> None:
    with pytest.raises(smoke.PlanRefusedError):
        smoke.check_cleanup_target(name, environment_id, prefix=prefix, test_env=TEST_ENV)


def test_cleanup_guard_accepts_a_smoke_stack(smoke: ModuleType) -> None:
    smoke.check_cleanup_target("mcp-smoke-1a2b", TEST_ENV, prefix="mcp-smoke-", test_env=TEST_ENV)


def smoke_client() -> DockhandClient:
    return DockhandClient(DOCKHAND_URL, token=DOCKHAND_TOKEN)


async def test_cleanup_deletes_only_smoke_stacks_in_the_test_environment(
    smoke: ModuleType, dockhand: respx.MockRouter
) -> None:
    dockhand.get("/api/stacks").respond(
        200, json=[{"name": "shop"}, {"name": "mcp-smoke-1a2b"}, {"name": "mcp-smoke-ffff"}]
    )
    deleted = dockhand.route(method="DELETE", path__startswith="/api/stacks/").respond(
        200, json={"success": True}
    )
    lines: list[str] = []
    code = await smoke.cleanup(
        smoke_client(),
        prefix="mcp-smoke-",
        environment_id=TEST_ENV,
        test_env=TEST_ENV,
        out=lines.append,
    )
    assert code == 0
    paths = sorted(c.request.url.path for c in deleted.calls)
    assert paths == ["/api/stacks/mcp-smoke-1a2b", "/api/stacks/mcp-smoke-ffff"]
    for c in deleted.calls:
        assert c.request.url.params["env"] == str(TEST_ENV)
    (listed,) = [c for c in dockhand.calls if c.request.method == "GET"]
    assert listed.request.url.params["env"] == str(TEST_ENV)


async def test_cleanup_refuses_another_environment_before_any_call(
    smoke: ModuleType, dockhand: respx.MockRouter
) -> None:
    with pytest.raises(smoke.PlanRefusedError):
        await smoke.cleanup(
            smoke_client(), prefix="mcp-smoke-", environment_id=8, test_env=TEST_ENV
        )
    with pytest.raises(smoke.PlanRefusedError):
        await smoke.cleanup(
            smoke_client(), prefix="prod-", environment_id=TEST_ENV, test_env=TEST_ENV
        )
    assert dockhand.calls.call_count == 0


async def test_cleanup_declaration_is_narrow(smoke: ModuleType) -> None:
    assert smoke.MAINTAINER_TOOLING == {"smoke-cleanup": smoke.CLEANUP_ENDPOINTS}
    assert smoke.CLEANUP_ENDPOINTS == {("GET", "/api/stacks"), ("DELETE", "/api/stacks/{name}")}
    emap = parse_endpoint_map(ENDPOINT_MAP.read_text(encoding="utf-8"))
    assert {emap[e] for e in smoke.CLEANUP_ENDPOINTS} == {"read", "destructive"}
    # The client enforces the declaration: anything else is refused before it is sent.
    with declared_endpoints(smoke.CLEANUP_ENDPOINTS), pytest.raises(UndeclaredEndpointError):
        await smoke_client().delete_json("/api/volumes/{name}", path_params={"name": "data"})


async def test_cleanup_is_not_an_mcp_tool(base_env: SetEnv) -> None:
    for profile in ("read-only", "operator", "admin"):
        base_env(DOCKHAND_MCP_PROFILE=profile)
        async with mcp_client(create_app(load_settings())) as c:
            names = [t.name for t in (await c.list_tools()).tools]
        assert not [n for n in names if "cleanup" in n]
    # Only the destructive tier may declare the stack DELETE: admin profile, human approval.
    declaring = [t for t in REGISTRY.all() if ("DELETE", "/api/stacks/{name}") in t.endpoints]
    assert [(t.name, t.tier) for t in declaring] == [("dockhand_delete_stack", Tier.DESTRUCTIVE)]


# --- destructive plan (S3b) -------------------------------------------------------------------

DESTRUCTIVE_PLAN = SMOKE.parent / "smoke-plans" / "destructive.json"


def test_destructive_plan_is_a_pinned_write_plan(smoke: ModuleType) -> None:
    plan = smoke.load_plan(DESTRUCTIVE_PLAN)
    assert smoke.is_write_plan(plan)
    assert smoke.check_write_plan(plan, TEST_ENV) == TEST_ENV
    assert all(set(step.get("expect", {})) <= smoke.EXPECT_KEYS for step in plan)
    calls = [(step["tool"], step["args"]) for step in plan]
    deletes = [args for tool, args in calls if tool == "dockhand_delete_stack"]
    # Unconfirmed first (confirmation_required, stack still there), then confirmed.
    assert [a.get("confirm", False) for a in deletes] == [False, True]
    removes = [args for tool, args in calls if tool == "dockhand_remove_container"]
    assert removes and all("force" not in a and "confirm" not in a for a in removes)
    seed = smoke.write_plan_seed(TEST_ENV)
    assert seed["smoke_container"] == seed["smoke_stack"] + "-web-1"


@pytest.mark.parametrize(
    "step",
    [
        {"tool": "dockhand_prune", "args": {"environment_id": "${test_env}", "scope": "all"}},
        {"tool": "dockhand_remove_volume", "args": {"environment_id": "${test_env}"}},
        {"tool": "dockhand_clear_activity_log", "args": {}},
        {"tool": "dockhand_run_image_prune_now", "args": {"environment_id": "${test_env}"}},
        {
            "tool": "dockhand_remove_container",
            "args": {"environment_id": "${test_env}", "ref": "db"},
        },
    ],
)
def test_write_plans_may_not_reach_beyond_the_smoke_stack(
    smoke: ModuleType, step: dict[str, Any]
) -> None:
    plan = [{"tool": "dockhand_get_stack_compose", "args": {"stack": "${smoke_stack}"}}, step]
    with pytest.raises(smoke.PlanRefusedError):
        smoke.check_write_plan(plan, TEST_ENV)


def test_write_plan_destructive_tools_are_a_subset_of_the_tier(smoke: ModuleType) -> None:
    tier = {t.name for t in REGISTRY.all() if t.tier is Tier.DESTRUCTIVE}
    assert smoke.WRITE_PLAN_DESTRUCTIVE <= tier
    assert smoke.destructive_tools() == tier


def test_a_plan_calling_a_destructive_tool_is_a_write_plan(smoke: ModuleType) -> None:
    plan = [{"tool": "dockhand_prune", "args": {"environment_id": 1, "scope": "all"}}]
    assert smoke.is_write_plan(plan)
    with pytest.raises(smoke.PlanRefusedError):
        smoke.check_write_plan(plan, None)
    with pytest.raises(smoke.PlanRefusedError):
        smoke.check_write_plan(plan, TEST_ENV)


def test_match_expectations(smoke: ModuleType) -> None:
    result = {"data": {"items": [{"name": "a", "state": "running"}, {"name": "b"}]}}
    check = smoke.check_expectations
    assert (
        check(result, {"includes_match": {"data.items": {"name": "a", "state": "running"}}}) == []
    )
    assert len(check(result, {"includes_match": {"data.items": {"name": "a", "state": "x"}}})) == 1
    assert check(result, {"excludes_match": {"data.items": {"name": "c"}}}) == []
    assert len(check(result, {"excludes_match": {"data.items": {"name": "b"}}})) == 1
    assert len(check(result, {"excludes_match": {"data.missing": {"name": "b"}}})) == 1


# --- picking a usable resource from a list (read.json robustness) -----------------------------


class FakeResult:
    def __init__(self, structured: dict[str, Any]) -> None:
        self.structured_content = structured
        self.is_error = not structured["ok"]


class ProbeClient:
    """Answers `dockhand_get_stack_compose` ok only for the stacks in `readable`."""

    def __init__(self, readable: set[str]) -> None:
        self.readable = readable
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, tool: str, args: dict[str, Any]) -> FakeResult:
        self.calls.append((tool, args))
        ok = args.get("stack") in self.readable
        return FakeResult({"ok": ok, "data": {"content": "services: {}\n"} if ok else None})


def _read_plan_stack_pick(smoke: ModuleType) -> dict[str, Any]:
    plan = smoke.load_plan(SMOKE.parent / "smoke-plans" / "read.json")
    step = next(s for s in plan if s["tool"] == "dockhand_list_stacks")
    where: dict[str, Any] = step["save"]["stack"]
    return where


async def test_read_plan_picks_a_readable_stack_that_is_not_a_smoke_leftover(
    smoke: ModuleType,
) -> None:
    where = _read_plan_stack_pick(smoke)
    listed = {
        "ok": True,
        "data": {
            "items": [
                {"name": "mcp-smoke-0a1b2c3d"},  # a leftover; its compose is readable
                {"name": "discovered"},  # listed, but no readable compose here
                {"name": "shop"},
                {"name": "blog"},
            ]
        },
    }
    client = ProbeClient({"mcp-smoke-0a1b2c3d", "shop", "blog"})
    picked = await smoke.pick_value(client, listed, where, {"env": 7})
    assert picked == "shop"
    probed = [args["stack"] for _, args in client.calls]
    assert probed == ["discovered", "shop"]  # the leftover is never even probed
    assert all(tool == "dockhand_get_stack_compose" for tool, _ in client.calls)
    assert all(args["environment_id"] == 7 for _, args in client.calls)


async def test_read_plan_pick_finds_nothing_when_no_stack_qualifies(smoke: ModuleType) -> None:
    where = _read_plan_stack_pick(smoke)
    listed = {"ok": True, "data": {"items": [{"name": "mcp-smoke-x"}, {"name": "discovered"}]}}
    picked = await smoke.pick_value(ProbeClient(set()), listed, where, {"env": 7})
    assert picked is smoke._MISSING


async def test_run_plan_saves_a_picked_value(smoke: ModuleType) -> None:
    class Client(ProbeClient):
        async def call_tool(self, tool: str, args: dict[str, Any]) -> FakeResult:
            if tool == "dockhand_list_stacks":
                items = [{"name": "mcp-smoke-1"}, {"name": "discovered"}, {"name": "shop"}]
                return FakeResult({"ok": True, "data": {"items": items}})
            if tool == "dockhand_get_stack_env":
                return FakeResult({"ok": args["stack"] == "shop", "data": {}})
            return await super().call_tool(tool, args)

    plan = [
        {
            "tool": "dockhand_list_stacks",
            "args": {"environment_id": 7},
            "save": {"stack": _read_plan_stack_pick(smoke)},
        },
        {
            "tool": "dockhand_get_stack_env",
            "args": {"environment_id": 7, "stack": "${stack}"},
            "expect": {"ok": True},
        },
    ]
    lines: list[str] = []
    code = await smoke.run_plan(Client({"shop"}), plan, out=lines.append, seed={"env": 7})
    assert code == 0, lines
    assert "2/2 steps passed, 0 skipped" in lines[-1]
