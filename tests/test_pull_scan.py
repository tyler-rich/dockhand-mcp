# SPDX-License-Identifier: Apache-2.0
"""`dockhand_pull_image` with `scan_after_pull`: a failed scan after a successful pull (#17).

DockHand 1.0.46 reports the scan inside the pull's own event stream (its source,
`src/routes/api/images/pull/+server.ts`): `scanning`, then `scan-progress` events, then
`scan-complete`, or `scan-error` when the scan throws. A scanner that fails while another
completes (scanner setting `both`) is a `scan-progress` event with `stage: error`. Either way the
stream still ends with `result {status: complete}`, so the result alone reads as success.

Pull ok and scan failed → `ok: false`, `operation_failed`, `data.pulled: true`,
`data.scanned: false`, and the scan's redacted error in `data.steps`. Both ok, and a failed pull,
are unchanged. Live DockHand answers on the job channel (`{jobId}`); real streams are tested too.
"""

from typing import Any

import pytest
import respx
from conftest import ENV, SetEnv, fake_dh_token, load_fixture
from test_operator_tools import JOB, Sse, call, mount

from dockhand_mcp.client.envelope import Envelope
from dockhand_mcp.client.redaction import MAX_ENTRY_CHARS
from dockhand_mcp.guardrails.secrets import REDACTED

E = {"environment_id": ENV}
ARGS = {**E, "image": "nginx:1.28", "scan_after_pull": True}
PULL = ("POST", "/api/images/pull")
SCAN_ERROR = "failed to fetch vulnerability database"
CHANNELS = ["job", "stream"]


@pytest.fixture
def operator_env(base_env: SetEnv) -> SetEnv:
    def _set(**env: str) -> None:
        base_env(DOCKHAND_MCP_PROFILE="operator", **env)

    return _set


def job(name: str, error: str = SCAN_ERROR) -> dict[str, Any]:
    body = load_fixture("jobs", name, SCAN_ERROR=error)
    assert isinstance(body, dict)
    return body


def mount_pull(dockhand: respx.MockRouter, channel: str, recorded: dict[str, Any]) -> None:
    """DockHand's answer to the pull: a job to poll (live), or the same events as a stream."""
    if channel == "job":
        mount(dockhand, [(*PULL, {"jobId": JOB}), ("GET", f"/api/jobs/{JOB}", recorded)])
    else:
        events = [[line["event"], line["data"]] for line in recorded["lines"]]
        mount(dockhand, [(*PULL, Sse(events))])


def data(env: Envelope) -> dict[str, Any]:
    assert isinstance(env.data, dict)
    return env.data


@pytest.mark.parametrize("channel", CHANNELS)
async def test_pull_and_scan_both_ok_is_unchanged(
    channel: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount_pull(dockhand, channel, job("pull-scan-done"))
    env, _ = await call("dockhand_pull_image", ARGS)
    assert (env.ok, env.error, env.warnings) == (True, None, None)
    assert data(env)["result"] == {"status": "complete"}
    for key in ("pulled", "scanned", "steps"):
        assert key not in data(env)


@pytest.mark.parametrize("fixture", ["pull-scan-error", "pull-scanner-error"])
@pytest.mark.parametrize("channel", CHANNELS)
async def test_pull_ok_and_scan_failed_is_operation_failed(
    channel: str, fixture: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    mount_pull(dockhand, channel, job(fixture))
    env, _ = await call("dockhand_pull_image", ARGS)
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == "operation_failed"
    assert env.error.dockhand_status is None
    assert "scan" in env.error.message
    body = data(env)
    assert (body["pulled"], body["scanned"]) == (True, False)
    pull, scan = body["steps"]
    assert pull == {"step": "pull", "outcome": "succeeded", "message": None}
    assert (scan["step"], scan["outcome"]) == ("scan", "failed")
    assert SCAN_ERROR in scan["message"]
    assert body["result"] == {"status": "complete"}


@pytest.mark.parametrize("channel", CHANNELS)
async def test_scan_error_message_is_redacted_and_capped(
    channel: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    operator_env()
    token = fake_dh_token("ScanToken_0123456789abcdef")
    password = "pw-" + "s3cr3t"
    leaky = f"registry https://robot:{password}@registry.example.test/v2 denied; token {token} "
    mount_pull(dockhand, channel, job("pull-scan-error", error=leaky + "x" * 2000))
    env, structured = await call("dockhand_pull_image", ARGS)
    assert env.error is not None
    assert env.error.code == "operation_failed"
    message = data(env)["steps"][1]["message"]
    assert REDACTED in message
    assert len(message) <= MAX_ENTRY_CHARS + 1  # the cap, then the ellipsis marking the cut
    text = str(structured)
    assert token not in text
    assert password not in text


@pytest.mark.parametrize("channel", CHANNELS)
async def test_failed_pull_is_unchanged(
    channel: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """The pull itself failing: DockHand fails the job (`error`, `success: false`)."""
    operator_env()
    failed = {
        "id": JOB,
        "status": "error",
        "lines": [
            {"event": "progress", "data": {"status": "error", "error": "manifest unknown"}},
            {"event": "result", "data": {"status": "error", "error": "manifest unknown"}},
        ],
        "result": {"success": False, "error": "manifest unknown"},
    }
    if channel == "job":
        mount_pull(dockhand, channel, failed)
    else:
        events = [["progress", {"status": "error"}], ["result", failed["result"]]]
        mount(dockhand, [(*PULL, Sse(events))])
    env, _ = await call("dockhand_pull_image", ARGS)
    assert env.error is not None
    assert env.error.code == "operation_failed"
    for key in ("pulled", "scanned", "steps"):
        assert key not in data(env)


async def test_pull_without_scan_ignores_scan_events(
    dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """Without scan_after_pull the tool does not judge a scan (DockHand skips it)."""
    operator_env()
    mount_pull(dockhand, "job", job("pull-scan-error"))
    env, _ = await call("dockhand_pull_image", {**ARGS, "scan_after_pull": False})
    assert (env.ok, env.error) == (True, None)
    assert "scanned" not in data(env)


@pytest.mark.parametrize("channel", CHANNELS)
async def test_scan_requested_but_not_run_is_a_warning(
    channel: str, dockhand: respx.MockRouter, operator_env: SetEnv
) -> None:
    """DockHand's scanner setting `none` skips the scan silently: the pull succeeded, and the
    result says no scan ran."""
    operator_env()
    recorded = job("pull-scan-done")
    lines = recorded["lines"]
    first_scan = next(n for n, line in enumerate(lines) if line["data"].get("status") == "scanning")
    recorded = {**recorded, "lines": [*lines[:first_scan], lines[-1]]}
    mount_pull(dockhand, channel, recorded)
    env, _ = await call("dockhand_pull_image", ARGS)
    assert (env.ok, env.error) == (True, None)
    assert env.warnings is not None
    assert any("no vulnerability scan" in w for w in env.warnings)
