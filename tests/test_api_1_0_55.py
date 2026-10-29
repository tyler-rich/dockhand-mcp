# SPDX-License-Identifier: Apache-2.0
"""DockHand 1.0.55 response shapes through the tools that read them (ARCHIVE §14, 1.0.55).

1.0.55 adds fields to responses existing tools pass through: `stack` on each container stats
entry; `minimumReleaseAgeHours` and per-item `pinnedToDigest`/`releaseAgeRemainingHours` on
pending updates; nullable `percentageSupported`/`storageDriver` on the disk warning; the
minimum-release-age fields on an environment's update check; `stacksUsing` on a git repository;
`rejectOlderImages` on semver settings and `newerVersions` on scanner settings; per-result
`warnings` on a batch update. General settings omit the operational fields for a caller without
settings:view. Each tool must accept the new shape against its outputSchema, keep the new fields,
and run them through the output redaction. The fixtures are invented (`*-1.0.55*.json`).

It also pins that the schedule tools refuse the schedule types 1.0.55 introduced, and
`deploy_log_reconcile`, before any request.
"""

import json
from typing import Any

import pytest
import respx
from conftest import IDS, SetEnv, fake_secret, load_fixture
from test_operation_output import TOKEN, URL_PASS, URL_USER
from test_operator_tools import CASES as OPERATOR_CASES
from test_operator_tools import call as operator_call
from test_operator_tools import mount as operator_mount
from test_read_tools import CASES as READ_CASES
from test_read_tools import E, Route, call, mount

from dockhand_mcp.guardrails.secrets import REDACTED

LEAK = f"see {TOKEN} at https://{URL_USER}:{URL_PASS}@registry.example.test"
PASSWORD = fake_secret("new-field-pass")


def fx(domain: str, name: str) -> Any:
    return load_fixture(domain, name)


def with_body(routes: list[Route], path_suffix: str, body: Any) -> list[Route]:
    """`routes` with the body of the one route whose path ends in `path_suffix` replaced."""
    assert sum(p.endswith(path_suffix) for _, p, _ in routes) == 1, path_suffix
    return [(m, p, body if p.endswith(path_suffix) else b) for m, p, b in routes]


def assert_no_leak(content: dict[str, Any]) -> None:
    text = json.dumps(content)
    assert TOKEN not in text
    assert URL_PASS not in text
    assert PASSWORD not in text


# --- read tools -------------------------------------------------------------------------------


async def test_all_container_stats_keep_stack(dockhand: respx.MockRouter, base_env: SetEnv) -> None:
    base_env()
    routes = READ_CASES["dockhand_get_all_container_stats"][1]
    mount(dockhand, with_body(routes, "/containers/stats", fx("containers", "stats-all-1.0.55")))
    env, _, _ = await call("dockhand_get_all_container_stats", E)
    assert env.ok is True, env.error
    assert env.warnings is None
    assert [(i["name"], i["stack"]) for i in env.data["items"]] == [
        ("web", "stack-a"),
        ("db", None),
    ]


async def test_pending_updates_keep_the_new_item_fields(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    body = fx("containers", "pending-updates-1.0.55")
    routes = READ_CASES["dockhand_get_pending_updates"][1]
    mount(dockhand, with_body(routes, "/pending-updates", body))
    env, _, _ = await call("dockhand_get_pending_updates", E)
    assert env.ok is True, env.error
    assert env.warnings is None
    assert env.data["pending_updates"] == body["pendingUpdates"]
    web, db = env.data["pending_updates"]
    assert (web["pinnedToDigest"], web["releaseAgeRemainingHours"]) == (False, 12)
    assert (db["pinnedToDigest"], db["hasImageUpdate"]) == (True, False)
    assert env.data["last_checked_at"] == "2026-01-02T03:04:05.000Z"


async def test_environment_disk_warning_unknown_and_release_age(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    routes = READ_CASES["dockhand_get_environment"][1]
    routes = with_body(routes, "/disk-warning", fx("environments", "disk-warning-1.0.55-unknown"))
    routes = with_body(routes, "/update-check", fx("environments", "update-check-1.0.55"))
    mount(dockhand, routes)
    env, _, _ = await call("dockhand_get_environment", E)
    assert env.ok is True, env.error
    assert env.warnings is None
    assert "errors" not in env.data
    disk = env.data["disk_warning"]
    assert (disk["percentageSupported"], disk["storageDriver"]) == (None, None)
    settings = env.data["update_check"]["settings"]
    assert settings["minimumReleaseAgeHours"] == 24
    assert settings["minimumReleaseAgeOverride"] is True
    assert settings["minimumReleaseAgeOverridden"] is True


async def test_settings_with_omitted_general_fields_and_new_scanner_semver_fields(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    general = fx("settings", "general-1.0.55-limited")
    routes = READ_CASES["dockhand_get_settings"][1]
    routes = with_body(routes, "/settings/general", general)
    routes = with_body(routes, "/settings/scanner", fx("settings", "scanner-1.0.55"))
    routes = with_body(routes, "/settings/semver", fx("settings", "semver-1.0.55"))
    mount(dockhand, routes)
    env, _, _ = await call("dockhand_get_settings", {})
    assert env.ok is True, env.error
    assert env.warnings is None
    # Omitted fields stay omitted: nothing is filled in or reported as an error.
    assert env.data["general"] == general
    assert "errors" not in env.data
    assert env.data["semver"]["rejectOlderImages"] is True
    assert env.data["scanner"]["newerVersions"] == {"grype": None, "trivy": None}


async def test_git_repository_keeps_stacks_using(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    dockhand.get("/api/git/repositories/1").respond(200, json=fx("git", "repository-1.0.55"))
    env, _, _ = await call("dockhand_list_git_repositories", {"repository_id": 1})
    assert env.ok is True, env.error
    repository = env.data["repository"]
    assert repository["stacksUsing"] == [
        {"stackName": "stack-a", "environmentId": 7},
        {"stackName": "stack-b", "environmentId": None},
    ]
    assert repository["webhookSecret"] == REDACTED


# The new object-valued fields go through the dispatcher's output redaction like any other data:
# the key-based pass on every key, the string layers under free-text keys (client/redaction.py).
# The other new fields are booleans, numbers or identifiers (`stack`, `stackName`), which the
# string layers leave alone everywhere, as they do a container's `name`.
EXTRA = {"password": PASSWORD, "message": LEAK}


def _extra_in_stacks_using(body: Any) -> Any:
    body["stacksUsing"][0].update(EXTRA)
    return body


def _extra_in_newer_versions(body: Any) -> Any:
    body["newerVersions"]["grype"] = dict(EXTRA)
    return body


async def test_stacks_using_passes_through_redaction(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    body = _extra_in_stacks_using(fx("git", "repository-1.0.55"))
    dockhand.get("/api/git/repositories/1").respond(200, json=body)
    env, content, _ = await call("dockhand_list_git_repositories", {"repository_id": 1})
    assert env.ok is True, env.error
    assert_no_leak(content)
    first = env.data["repository"]["stacksUsing"][0]
    assert first["password"] == REDACTED
    assert f"https://{REDACTED}@registry.example.test" in first["message"]
    assert first["stackName"] == "stack-a"


async def test_newer_versions_passes_through_redaction(
    dockhand: respx.MockRouter, base_env: SetEnv
) -> None:
    base_env()
    body = _extra_in_newer_versions(fx("settings", "scanner-1.0.55"))
    mount(dockhand, with_body(READ_CASES["dockhand_get_settings"][1], "/settings/scanner", body))
    env, content, _ = await call("dockhand_get_settings", {})
    assert env.ok is True, env.error
    assert_no_leak(content)
    grype = env.data["scanner"]["newerVersions"]["grype"]
    assert grype["password"] == REDACTED
    assert f"https://{REDACTED}@registry.example.test" in grype["message"]


# --- update_containers ------------------------------------------------------------------------


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


def _update_routes(answer: Any) -> list[Route]:
    return with_body(OPERATOR_CASES["dockhand_update_containers"][1], "/batch-update", answer)


async def test_update_containers_keeps_batch_warnings(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    answer = fx("containers", "batch-update-1.0.55")
    operator_mount(dockhand, _update_routes(answer))
    env, _ = await operator_call(
        "dockhand_update_containers", OPERATOR_CASES["dockhand_update_containers"][0]
    )
    assert env.ok is True, env.error
    results = env.data["result"]["results"]
    assert results[0]["warnings"] == answer["results"][0]["warnings"]
    assert "warnings" not in results[1]
    # The outcome is still judged on `success` alone (an open question, not changed here).
    assert {i["name"]: i["outcome"] for i in env.data["items"]} == {
        "web": "succeeded",
        "db": "succeeded",
    }


async def test_update_containers_redacts_batch_warning_messages(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    answer = fx("containers", "batch-update-1.0.55")
    answer["results"][0]["warnings"][0]["message"] = LEAK
    operator_mount(dockhand, _update_routes(answer))
    env, content = await operator_call(
        "dockhand_update_containers", OPERATOR_CASES["dockhand_update_containers"][0]
    )
    assert env.ok is True, env.error
    assert_no_leak(content)
    message = env.data["result"]["results"][0]["warnings"][0]["message"]
    assert f"https://{REDACTED}@registry.example.test" in message
    assert "dh_***" in message


# --- schedule types -----------------------------------------------------------------------------

# 1.0.55 added container_start and container_stop to the run and toggle routes;
# deploy_log_reconcile was already listed there in 1.0.49.
REFUSED_TYPES = ("container_start", "container_stop", "deploy_log_reconcile")


@pytest.mark.parametrize("tool", ["dockhand_run_schedule_now", "dockhand_toggle_schedule"])
@pytest.mark.parametrize("schedule_type", REFUSED_TYPES)
async def test_schedule_tools_refuse_the_new_types(
    tool: str, schedule_type: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    env, _ = await operator_call(tool, {"schedule_type": schedule_type, "schedule_id": 1})
    assert env.error is not None
    assert env.error.code == "validation_error"
    assert dockhand.calls.call_count == 0


def test_placeholder_ids_are_filled() -> None:
    body = fx("containers", "pending-updates-1.0.55")
    assert body["pendingUpdates"][0]["containerId"] == IDS["CID_WEB"]
    assert "{{" not in json.dumps(body)
