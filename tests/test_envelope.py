# SPDX-License-Identifier: Apache-2.0
"""The uniform result envelope (ARCHITECTURE §6) and its MCP rendering (F-12)."""

import json

import jsonschema
import pytest
from pydantic import ValidationError

from dockhand_mcp.client.envelope import (
    ERROR_CODES,
    MAX_TEXT_BYTES,
    OUTPUT_SCHEMA,
    Envelope,
    async_op,
    err,
    from_error,
    ok,
    render,
)
from dockhand_mcp.client.errors import DockhandError


def test_error_codes_are_the_closed_set() -> None:
    assert set(ERROR_CODES) == {
        "validation_error",
        "not_found",
        "ambiguous_name",
        "dockhand_http_error",
        "dockhand_unreachable",
        "unexpected_redirect",
        "guardrail_blocked",
        "confirmation_required",
        "timeout",
        "operation_unknown",
        "profile_denied",
        "not_available",
        "verification_failed",
        "operation_failed",
    }


def test_ok_envelope() -> None:
    env = ok({"a": 1}, environment_id=7, warnings=["w"])
    assert env.model_dump(mode="json", exclude_none=True) == {
        "ok": True,
        "environment_id": 7,
        "data": {"a": 1},
        "warnings": ["w"],
    }


def test_err_envelope() -> None:
    env = err("not_found", "no such container", dockhand_status=404)
    assert env.model_dump(mode="json", exclude_none=True) == {
        "ok": False,
        "error": {"code": "not_found", "message": "no such container", "dockhand_status": 404},
    }


def test_unknown_error_code_is_rejected() -> None:
    with pytest.raises(ValidationError):
        err("teapot", "x")  # type: ignore[arg-type]


def test_async_op_envelope() -> None:
    env = async_op("job", "j-1", "running", 60.0, True)
    dumped = env.model_dump(mode="json", exclude_none=True)
    assert dumped == {
        "ok": True,
        "operation": {
            "kind": "job",
            "id": "j-1",
            "status": "running",
            "waited_seconds": 60.0,
            "timed_out": True,
        },
    }


def test_from_error_carries_status_retry_and_detail() -> None:
    e = DockhandError(429, "dockhand_http_error", "rate limited", "slow down", retry_after=30)
    env = from_error(e, environment_id=7)
    assert env.error is not None
    assert (env.error.dockhand_status, env.error.retry_after, env.error.detail) == (
        429,
        30,
        "slow down",
    )
    assert env.environment_id == 7


def test_output_schema_validates_every_builder() -> None:
    assert OUTPUT_SCHEMA["type"] == "object"
    for env in (
        ok(None),
        ok([1, 2]),
        err("timeout", "t"),
        async_op("detached", "x", "completed", 1.5, False, data={"r": 1}),
    ):
        jsonschema.validate(env.model_dump(mode="json", exclude_none=True), OUTPUT_SCHEMA)


def test_envelope_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Envelope.model_validate({"ok": True, "surprise": 1})


def test_render_small_result() -> None:
    result = render(ok({"a": 1}))
    assert result.is_error is False
    assert result.structured_content == {"ok": True, "data": {"a": 1}}
    assert json.loads(result.content[0].text) == {"ok": True, "data": {"a": 1}}  # type: ignore[union-attr]


def test_render_error_sets_is_error() -> None:
    assert render(err("timeout", "t")).is_error is True


def test_render_large_result_points_to_structured_content() -> None:
    big = ok({"blob": "x" * (MAX_TEXT_BYTES + 10)})
    result = render(big)
    text = result.content[0].text  # type: ignore[union-attr]
    assert len(text.encode()) <= MAX_TEXT_BYTES
    assert "truncated, see structured content" in text
    assert result.structured_content is not None
    assert result.structured_content["data"]["blob"] == "x" * (MAX_TEXT_BYTES + 10)
