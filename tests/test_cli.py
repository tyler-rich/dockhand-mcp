# SPDX-License-Identifier: Apache-2.0
"""The dockhand-mcp CLI: serve | check | tools (F-13) and the SECURITY §6 DockHand checks.

DockHand responses are invented from the spec's schemas.
"""

import hashlib
import json
from typing import Any

import httpx
import pytest
import respx
from conftest import (
    DOCKHAND_TOKEN,
    MCP_TOKEN,
    SetEnv,
    destructive_tool_names,
    healthy_dockhand,
    operator_tool_names,
    read_tool_names,
)

from dockhand_mcp.__main__ import main
from dockhand_mcp.client.envelope import Envelope

ENV7 = {"id": 7, "name": "example", "connectionType": "socket"}
DOMAINS = ("containers", "stacks", "images", "volumes", "networks")


def mock_dockhand(
    router: respx.MockRouter,
    *,
    auth_enabled: bool = True,
    roles: int = 403,
    environments: int = 200,
    domains: int = 200,
) -> None:
    healthy_dockhand(router)
    router.get("/api/auth/settings").respond(
        200, json={"authEnabled": auth_enabled, "defaultProvider": "local"}
    )
    router.get("/api/environments").respond(
        environments, json=[ENV7] if environments == 200 else {"error": "x"}
    )
    # The edition probe's body is never read: make it unparseable to prove it.
    router.get("/api/roles").respond(roles, content=b"\x00not json")
    for domain in DOMAINS:
        router.get(f"/api/{domain}", params={"env": "7"}).respond(domains, json=[])


def run_check(capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any], str]:
    code = main(["check"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out) if captured.out else {}, captured.err


# --- tools ------------------------------------------------------------------------------------


def schema_hash(schema: dict[str, Any]) -> str:
    text = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode()).hexdigest()


def test_tools_prints_the_catalogue(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tools"]) == 0
    first = capsys.readouterr().out
    assert main(["tools"]) == 0
    assert capsys.readouterr().out == first  # deterministic
    catalogue = json.loads(first)
    assert [t["name"] for t in catalogue] == sorted(
        read_tool_names() + operator_tool_names() + destructive_tool_names()
    )
    by_name = {t["name"]: t for t in catalogue}
    health = by_name["dockhand_health"]
    assert set(health) == {
        "name",
        "title",
        "tier",
        "endpoints",
        "description",
        "input_schema_sha256",
        "output_schema_sha256",
    }
    assert health["tier"] == "read"
    assert health["endpoints"] == [["GET", "/api/health"], ["GET", "/api/health/database"]]
    assert health["output_schema_sha256"] == schema_hash(Envelope.model_json_schema())
    assert by_name["dockhand_get_operation"]["endpoints"] == []
    for tool in catalogue:
        assert len(tool["input_schema_sha256"]) == 64


# --- check ------------------------------------------------------------------------------------


def test_check_without_configuration_fails_with_one_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["check"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "dockhand-mcp: configuration error: DOCKHAND_URL is required\n"


def test_check_reports_free_edition(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand, roles=403)
    code, report, _ = run_check(capsys)
    assert code == 0, report
    assert report["profile"] == "read-only"
    assert report["tools"] == read_tool_names()
    dh = report["dockhand"]
    assert dh["health"] == "ok"
    assert dh["database_healthy"] is True
    assert dh["auth_enabled"] is True
    assert dh["token"] == "accepted"
    assert dh["edition"] == "free"
    assert dh["permissions"] == dict.fromkeys(DOMAINS, "ok")
    assert report["problems"] == []


def test_check_reports_enterprise_edition(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand, roles=200)
    code, report, _ = run_check(capsys)
    assert code == 0
    assert report["dockhand"]["edition"] == "enterprise"


def test_check_reports_denied_domains(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand, roles=200, domains=403)
    code, report, _ = run_check(capsys)
    assert code == 0  # best-effort: reported, not fatal
    assert report["dockhand"]["permissions"] == dict.fromkeys(DOMAINS, "denied (403)")


def test_check_fails_when_the_token_is_rejected(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand, environments=401)
    code, report, _ = run_check(capsys)
    assert code == 1
    assert report["dockhand"]["token"] == "rejected"
    assert any("token" in p for p in report["problems"])


def test_check_fails_without_token_when_dockhand_auth_is_enabled(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env()
    mock_dockhand(dockhand, auth_enabled=True)
    code, report, _ = run_check(capsys)
    assert code == 1
    assert report["dockhand"]["token"] == "not configured"
    assert (
        "DOCKHAND_TOKEN is required: DockHand reports authentication enabled" in report["problems"]
    )


def test_check_warns_when_dockhand_auth_is_disabled(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env()
    mock_dockhand(dockhand, auth_enabled=False)
    code, report, err = run_check(capsys)
    assert code == 0
    assert report["dockhand"]["auth_enabled"] is False
    assert "the MCP profile is the only control" in err


def test_check_fails_when_dockhand_is_unreachable(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    dockhand.route().mock(side_effect=httpx.ConnectError("refused"))
    code, report, _ = run_check(capsys)
    assert code == 1
    assert report["dockhand"]["health"] == "unreachable"


def test_check_never_prints_tokens(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand)
    main(["check"])
    captured = capsys.readouterr()
    for secret in (DOCKHAND_TOKEN, DOCKHAND_TOKEN[3:], MCP_TOKEN):
        assert secret not in captured.out
        assert secret not in captured.err
    assert json.loads(captured.out)["config"]["DOCKHAND_MCP_TOKEN"] == "*** (set)"


def test_check_calls_only_the_allowed_internal_endpoints(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand)
    main(["check"])
    paths = {call.request.url.path for call in dockhand.calls}
    assert paths == {
        "/api/health",
        "/api/health/database",
        "/api/auth/settings",
        "/api/environments",
        "/api/roles",
        *(f"/api/{d}" for d in DOMAINS),
    }


# --- check: environments sharing one Docker daemon (#21) ----------------------------------------

ENV8 = {"id": 8, "name": "staging", "connectionType": "socket"}
SHARED_WARNING = (
    "Environments 7 (example) and 8 (staging) appear to share one Docker daemon. Stacks can "
    "collide across them. Point each environment at its own daemon."
)


def cid(n: int) -> str:
    return f"{n:064x}"


def mock_two_environments(
    router: respx.MockRouter, ids7: list[str], ids8: list[str], *, status8: int = 200
) -> None:
    # respx answers with the first matching route, and `params` matches by containment, so the
    # container lists go before mock_dockhand's `env=7` probe. A route with an identical pattern
    # replaces the earlier one, so the environment list goes after it.
    containers = {"7": ids7, "8": ids8}
    for env, ids in containers.items():
        items = [{"id": i, "name": f"c{n}", "state": "exited"} for n, i in enumerate(ids)]
        status = status8 if env == "8" else 200
        router.get("/api/containers", params={"env": env, "all": "true"}).respond(
            status, json=items if status == 200 else {"error": "x"}
        )
    mock_dockhand(router)
    router.get("/api/environments").respond(200, json=[ENV7, ENV8])


def test_check_warns_when_two_environments_share_a_container(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_two_environments(dockhand, [cid(1), cid(2)], [cid(2), cid(3)])
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert report["problems"] == []
    assert f"dockhand-mcp: warning: {SHARED_WARNING}\n" in err
    for n in (1, 2, 3):  # no container details
        assert cid(n) not in err
        assert cid(n)[:12] not in err
    stopped = [
        c.request.url.params.get("all")
        for c in dockhand.calls
        if c.request.url.path == "/api/containers" and c.request.url.params.get("env") == "8"
    ]
    assert stopped == ["true"]


def test_check_does_not_warn_for_disjoint_environments(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_two_environments(dockhand, [cid(1), cid(2)], [cid(3)])
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert "share one Docker daemon" not in err


def test_check_does_not_warn_for_one_environment(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_dockhand(dockhand)
    code, _, err = run_check(capsys)
    assert code == 0
    assert "share one Docker daemon" not in err


def test_check_reports_an_environment_it_cannot_compare(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN)
    mock_two_environments(dockhand, [cid(1)], [cid(1)], status8=403)
    code, report, err = run_check(capsys)
    assert code == 0, report
    assert "share one Docker daemon" not in err
    assert "cannot compare environment 8 (staging)" in err


# --- serve ------------------------------------------------------------------------------------


def test_serve_with_invalid_config_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["serve"]) == 1
    assert (
        capsys.readouterr().err == "dockhand-mcp: configuration error: DOCKHAND_URL is required\n"
    )


def test_serve_refuses_without_token_when_dockhand_auth_is_enabled(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env()
    mock_dockhand(dockhand, auth_enabled=True)
    assert main(["serve"]) == 1
    assert capsys.readouterr().err.endswith(
        "DOCKHAND_TOKEN is required: DockHand reports authentication enabled\n"
    )


def test_serve_refuses_without_token_when_dockhand_is_unreachable(
    base_env: SetEnv, dockhand: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env()
    dockhand.route().mock(side_effect=httpx.ConnectError("refused"))
    assert main(["serve"]) == 1
    assert "cannot confirm DockHand authentication is disabled" in capsys.readouterr().err


def test_serve_stdio_requires_auth_mode_none(
    base_env: SetEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    base_env(DOCKHAND_TOKEN=DOCKHAND_TOKEN, DOCKHAND_MCP_TRANSPORT="stdio")
    assert main(["serve"]) == 1
    assert capsys.readouterr().err.endswith(
        "DOCKHAND_MCP_TRANSPORT=stdio requires DOCKHAND_MCP_AUTH_MODE=none\n"
    )


def test_no_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
