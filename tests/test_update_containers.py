# SPDX-License-Identifier: Apache-2.0
"""`dockhand_update_containers` reports every failure DockHand's batch-update answer carries.

The spec's 200 answer is `{success, results: [{containerId, containerName, success, error?}],
summary: {total, success, failed}}`. Before this fix only a non-zero `summary.failed` was an
error, so an answer of top-level `success: false` that named no failed container came back
`ok: true` (S3f follow-up). Any failure indicator (top-level `success: false`, a failed
`results` item, a non-zero `summary.failed`) is now `operation_failed`, with each container's
outcome in `data.items`. The answers below are invented in the spec's shape, not recorded.
"""

import json
from typing import Any, Final

import pytest
import respx
from conftest import ENV, IDS, SetEnv, fake_dh_token, hexid
from test_operator_tools import CASES, Route, call, mount, sent

from dockhand_mcp.client.envelope import Envelope

TOOL: Final = "dockhand_update_containers"
ARGS, ROUTES = CASES[TOOL]
WEB, DB = IDS["CID_WEB"], IDS["CID_DB"]
BATCH: Final = "/api/containers/batch-update"


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


async def run(dockhand: respx.MockRouter, body: Any) -> Envelope:
    mount(dockhand, routes(body))
    envelope, _ = await call(TOOL, ARGS)
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
    assert envelope.data["summary"] == {"total": 2, "succeeded": 1, "failed": 1}


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
    assert envelope.data["summary"] == {"total": 2, "succeeded": 2, "failed": 0}


async def test_an_answer_with_no_verdict_stays_ok(dockhand: respx.MockRouter) -> None:
    """No failure indicator is not a failure: success semantics are otherwise unchanged."""
    envelope = await run(dockhand, {})
    assert envelope.ok is True
    assert outcomes(envelope) == {"web": "unknown", "db": "unknown"}


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
