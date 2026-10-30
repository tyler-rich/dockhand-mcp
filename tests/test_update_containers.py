# SPDX-License-Identifier: Apache-2.0
"""`dockhand_update_containers` reports every failure DockHand's batch-update answer carries.

The spec's 200 answer is `{success, results: [{containerId, containerName, success, error?}],
summary: {total, success, failed}}`. Before this fix only a non-zero `summary.failed` was an
error, so an answer of top-level `success: false` that named no failed container came back
`ok: true` (S3f follow-up). Any failure indicator (top-level `success: false`, a failed
`results` item, a non-zero `summary.failed`) is now `operation_failed`, with each container's
outcome in `data.items`. The answers below are invented in the spec's shape, not recorded.

Issue #20: a container DockHand did not update must never read as `succeeded`. DockHand 1.0.55's
route (read in its public source) reports its one skip, the `dockhand.update=false` label, as
`success: true` with an `error` starting `Skipped`, and attaches `warnings: [{status, message}]`
whose only status, `warning`, is a minimum-release-age advisory for a pull that goes ahead. So:
a `Skipped` error is `skipped`; any other error on a success, a warning with another status, or
an unreadable warning is `unverified`; a `warning` is informational. The call is `ok: true` only
when every container `succeeded`: an `unknown` container, one DockHand's answer does not name,
now fails the call too (maintainer decision, reversing that part of #15).
"""

import json
from typing import Any, Final

import pytest
import respx
from conftest import ENV, IDS, SetEnv, fake_dh_token, hexid, load_fixture
from test_operation_output import TOKEN, URL_PASS, URL_USER
from test_operator_tools import CASES, Route, call, mount, sent

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.client.redaction import MAX_ENTRY_CHARS
from dockhand_mcp.guardrails.secrets import REDACTED
from dockhand_mcp.tools.registry import REGISTRY

TOOL: Final = "dockhand_update_containers"
ARGS, ROUTES = CASES[TOOL]
WEB, DB, WORKER = IDS["CID_WEB"], IDS["CID_DB"], IDS["CID_WORKER"]
BATCH: Final = "/api/containers/batch-update"
# DockHand 1.0.55's skip text, and the shape of its release-age advisory (image, times and
# minutes invented).
SKIPPED: Final = "Skipped - dockhand.update=false label"
ADVISORY: Final = (
    "This image digest of example/web:1 was created at 2026-10-01T00:00:00Z (30 minutes ago); "
    "90 minutes remain in the automatic-update cooldown. Pulling it anyway because this was "
    "requested manually."
)


@pytest.fixture(autouse=True)
def operator(base_env: SetEnv) -> None:
    base_env(DOCKHAND_MCP_PROFILE="operator")


def _item(cid: str, name: str, success: bool, error: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"containerId": cid, "containerName": name, "success": success}
    if error is not None:
        item["error"] = error
    return item


def answer(
    success: bool = True,
    web: bool = True,
    db: bool = True,
    failed: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    results = [_item(WEB, "web", web, None if web else error), _item(DB, "db", db)]
    if failed is None:
        failed = sum(1 for r in results if not r["success"])
    return {
        "success": success,
        "results": results,
        "summary": {"total": 2, "success": 2 - failed, "failed": failed},
    }


def routes(body: Any) -> list[Route]:
    return [(m, p, body if p == BATCH else b) for m, p, b in ROUTES]


async def run(
    dockhand: respx.MockRouter, body: Any, extra: list[Route] | None = None, **args: Any
) -> Envelope:
    mount(dockhand, routes(body) + (extra or []))
    envelope, _ = await call(TOOL, {**ARGS, **args})
    assert len(sent(dockhand, "POST", BATCH)) == 1
    return envelope


def outcomes(envelope: Envelope) -> dict[str, str]:
    assert isinstance(envelope.data, dict)
    return {i["name"]: i["outcome"] for i in envelope.data["items"]}


async def test_top_level_failure_without_a_failed_item_is_operation_failed(
    dockhand: respx.MockRouter,
) -> None:
    envelope = await run(dockhand, answer(success=False))
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "without naming a failed container" in envelope.error.message
    assert outcomes(envelope) == {"web": "succeeded", "db": "succeeded"}


async def test_a_failed_item_the_summary_does_not_count_is_operation_failed(
    dockhand: respx.MockRouter,
) -> None:
    envelope = await run(dockhand, answer(web=False, failed=0, error="pull failed"))
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "1 of 2 containers failed to update" in envelope.error.message
    assert outcomes(envelope) == {"web": "failed", "db": "succeeded"}


async def test_a_counted_failure_carries_the_item_detail(dockhand: respx.MockRouter) -> None:
    envelope = await run(dockhand, answer(success=False, web=False, error="pull failed"))
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert isinstance(envelope.data, dict)
    web = next(i for i in envelope.data["items"] if i["name"] == "web")
    assert web == {"id": WEB, "name": "web", "outcome": "failed", "message": "pull failed"}
    assert envelope.data["summary"] == summary(succeeded=1, failed=1)


async def test_item_messages_are_redacted(dockhand: respx.MockRouter) -> None:
    token = fake_dh_token("Upd4te" + "q" * 30)
    envelope = await run(dockhand, answer(web=False, error=f"registry said {token}"))
    assert envelope.error is not None
    assert token not in json.dumps(envelope.model_dump(mode="json"))


async def test_all_success_is_unchanged(dockhand: respx.MockRouter) -> None:
    envelope = await run(dockhand, answer())
    assert envelope.ok is True
    assert envelope.environment_id == ENV
    assert isinstance(envelope.data, dict)
    assert [c["name"] for c in envelope.data["containers"]] == ["web", "db"]
    assert envelope.data["result"]["success"] is True
    assert outcomes(envelope) == {"web": "succeeded", "db": "succeeded"}
    assert envelope.data["summary"] == summary(succeeded=2)
    assert envelope.warnings is None
    assert all("warnings" not in i and "message" not in i for i in envelope.data["items"])


async def test_an_answer_naming_no_container_is_operation_failed(
    dockhand: respx.MockRouter,
) -> None:
    """#20 reverses #15 here: a container the answer does not name was not shown to be updated."""
    envelope = await run(dockhand, {})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "2 of 2 containers" in envelope.error.message
    assert "2 unknown" in envelope.error.message
    assert outcomes(envelope) == {"web": "unknown", "db": "unknown"}
    assert isinstance(envelope.data, dict)
    assert envelope.data["summary"] == summary(unknown=2)


async def test_items_match_by_name_when_dockhand_answers_the_recreated_id(
    dockhand: respx.MockRouter,
) -> None:
    """Live (S3g): each `results` item carries the recreated container's new id, same name."""
    body = answer(web=False, error="pull failed")
    for result in body["results"]:
        result["containerId"] = hexid(f"recreated-{result['containerName']}")
    envelope = await run(dockhand, body)
    assert envelope.error is not None
    assert outcomes(envelope) == {"web": "failed", "db": "succeeded"}


# --- #20: skipped, unverified and informational outcomes ----------------------------------------


def summary(total: int = 2, **counts: int) -> dict[str, int]:
    keys = ("succeeded", "failed", "skipped", "unverified", "unknown")
    return {"total": total, **{key: counts.get(key, 0) for key in keys}}


def with_web(**fields: Any) -> dict[str, Any]:
    """The all-success answer with `fields` set on web's result."""
    body = answer()
    body["results"][0].update(fields)
    return body


def item(envelope: Envelope, name: str) -> dict[str, Any]:
    assert isinstance(envelope.data, dict)
    found: dict[str, Any] = next(i for i in envelope.data["items"] if i["name"] == name)
    return found


async def test_a_skip_reported_as_success_is_skipped(dockhand: respx.MockRouter) -> None:
    envelope = await run(dockhand, with_web(error=SKIPPED))
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "1 of 2 containers" in envelope.error.message
    assert "1 skipped" in envelope.error.message
    assert outcomes(envelope) == {"web": "skipped", "db": "succeeded"}
    assert item(envelope, "web")["message"] == SKIPPED
    assert isinstance(envelope.data, dict)
    assert envelope.data["summary"] == summary(succeeded=1, skipped=1)


async def test_an_unknown_warning_status_is_unverified(dockhand: respx.MockRouter) -> None:
    warning = {"status": "deferred", "message": "update postponed"}
    envelope = await run(dockhand, with_web(warnings=[warning]))
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "1 of 2 containers" in envelope.error.message
    assert "1 unverified" in envelope.error.message
    assert outcomes(envelope) == {"web": "unverified", "db": "succeeded"}
    assert item(envelope, "web")["warnings"] == [warning]
    assert isinstance(envelope.data, dict)
    assert envelope.data["summary"] == summary(succeeded=1, unverified=1)
    assert envelope.warnings is None


@pytest.mark.parametrize(
    "warnings",
    [
        [{"message": "no status"}],
        [{"status": "warning"}],
        ["not an object"],
        "not a list",
        [{"status": 3, "message": "status is not text"}],
    ],
)
async def test_an_unreadable_warning_is_unverified(
    dockhand: respx.MockRouter, warnings: Any
) -> None:
    envelope = await run(dockhand, with_web(warnings=warnings))
    assert envelope.ok is False
    assert outcomes(envelope) == {"web": "unverified", "db": "succeeded"}


async def test_an_unexplained_error_on_a_success_is_unverified(
    dockhand: respx.MockRouter,
) -> None:
    envelope = await run(dockhand, with_web(error="recreated without its network"))
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert outcomes(envelope) == {"web": "unverified", "db": "succeeded"}
    assert item(envelope, "web")["message"] == "recreated without its network"


async def test_a_release_age_advisory_is_informational(dockhand: respx.MockRouter) -> None:
    warning = {"status": "warning", "message": ADVISORY}
    envelope = await run(dockhand, with_web(warnings=[warning]))
    assert envelope.ok is True, envelope.error
    assert outcomes(envelope) == {"web": "succeeded", "db": "succeeded"}
    assert item(envelope, "web")["warnings"] == [warning]
    assert envelope.warnings is not None
    assert f"web: {ADVISORY}" in envelope.warnings
    assert isinstance(envelope.data, dict)
    assert envelope.data["summary"] == summary(succeeded=2)


async def test_an_empty_warning_list_is_a_plain_success(dockhand: respx.MockRouter) -> None:
    """Live DockHand 1.0.55 sends `warnings: []` on an ordinary successful update."""
    envelope = await run(dockhand, with_web(warnings=[]))
    assert envelope.ok is True, envelope.error
    assert outcomes(envelope) == {"web": "succeeded", "db": "succeeded"}
    assert "warnings" not in item(envelope, "web")
    assert envelope.warnings is None


async def test_a_skip_outranks_an_unknown_warning(dockhand: respx.MockRouter) -> None:
    body = with_web(error=SKIPPED, warnings=[{"status": "deferred", "message": "later"}])
    envelope = await run(dockhand, body)
    assert outcomes(envelope) == {"web": "skipped", "db": "succeeded"}


async def test_mixed_failed_skipped_and_succeeded(dockhand: respx.MockRouter) -> None:
    body = answer(success=False, web=False, error="pull failed")
    body["results"].append(_item(WORKER, "worker", True, SKIPPED))
    body["summary"] = {"total": 3, "success": 2, "failed": 1}
    inspect = load_fixture("containers", "inspect")
    extra: list[Route] = [("GET", f"/api/containers/{WORKER}", inspect)]
    envelope = await run(dockhand, body, extra, refs=["web", "db", "worker"])
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code == "operation_failed"
    assert "2 of 3 containers" in envelope.error.message
    assert "1 failed" in envelope.error.message
    assert "1 skipped" in envelope.error.message
    assert outcomes(envelope) == {"web": "failed", "db": "succeeded", "worker": "skipped"}
    assert isinstance(envelope.data, dict)
    assert envelope.data["summary"] == summary(3, succeeded=1, failed=1, skipped=1)


async def test_warning_messages_are_redacted_in_items(dockhand: respx.MockRouter) -> None:
    leak = f"see {TOKEN} at https://{URL_USER}:{URL_PASS}@registry.example.test"
    envelope = await run(dockhand, with_web(warnings=[{"status": "deferred", "message": leak}]))
    [warning] = item(envelope, "web")["warnings"]
    assert "dh_***" in warning["message"]
    assert f"https://{REDACTED}@registry.example.test" in warning["message"]
    dumped = json.dumps(envelope.model_dump(mode="json"))
    assert TOKEN not in dumped
    assert URL_PASS not in dumped


async def test_warning_messages_are_capped(dockhand: respx.MockRouter) -> None:
    envelope = await run(
        dockhand, with_web(warnings=[{"status": "warning", "message": "x" * 2000}])
    )
    [warning] = item(envelope, "web")["warnings"]
    assert len(warning["message"]) == MAX_ENTRY_CHARS + 1  # the cap, then the ellipsis
    assert envelope.warnings == [f"web: {warning['message']}"]


def test_output_schema_names_every_outcome_and_count() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == TOOL)
    schema = entry.tool.to_mcp().output_schema  # type: ignore[attr-defined]
    data = schema["properties"]["data"]["anyOf"][0]["properties"]
    outcome = data["items"]["items"]["properties"]["outcome"]
    assert set(outcome["enum"]) == {"succeeded", "failed", "skipped", "unverified", "unknown"}
    assert {"skipped", "unverified", "unknown"} <= set(data["summary"]["properties"])


def test_description_says_skipped_containers_fail_the_call() -> None:
    entry = next(t for t in REGISTRY.all() if t.name == TOOL)
    assert "skipped" in entry.tool.description.lower()  # type: ignore[attr-defined]
