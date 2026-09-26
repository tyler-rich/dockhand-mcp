# SPDX-License-Identifier: Apache-2.0
"""Destructive-call approval (D-006, ARCHITECTURE §7): challenges, replay, mode matrix.

Keys are generated at runtime; no challenge, MAC or key appears as a literal.
"""

import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import pytest
from mcp_types import ClientCapabilities, ElicitRequest, ElicitResult

from dockhand_mcp.auth import approval
from dockhand_mcp.auth.approval import (
    APPROVE_FIELD,
    CHALLENGE_LIFETIME_S,
    INPUT_KEY,
    SCOPE_ACK_FIELD,
    ApprovalContext,
    ApprovalState,
    Approved,
    ChallengeError,
    ClientView,
    InputRequired,
    Preview,
    Refused,
    ReplayCache,
    approve_or_request,
    args_sha256,
    choose_path,
    mint_challenge,
    verify_challenge,
)
from dockhand_mcp.transport.ratelimit import DestructiveRateLimiter

TOOL = "dockhand_delete_stack"
TITLE = "delete stack"
ARGS: dict[str, Any] = {"environment_id": 7, "stack": "shop", "force": False, "confirm": False}
PREVIEW = Preview(
    summary="Delete stack shop in environment 7.",
    data={"stack": "shop"},
    counts={"volumes": 1},
    target={"stack": "shop"},
)
ELICITING = ClientView(modern=True, form_elicitation=True)
NOT_ELICITING = ClientView(modern=True, form_elicitation=False)


class Clock:
    def __init__(self) -> None:
        self.now = 1_900_000_000.0

    def __call__(self) -> float:
        return self.now


def state(mode: str = "auto", clock: Clock | None = None) -> ApprovalState:
    return ApprovalState(
        key=secrets.token_bytes(32),
        mode=mode,  # type: ignore[arg-type]
        limiter=DestructiveRateLimiter(1000),
        clock=clock or Clock(),
    )


def ctx(st: ApprovalState, client: ClientView = ELICITING, principal: str = "alice") -> Any:
    return ApprovalContext(state=st, principal=principal, client=client)


def answer(
    token: str | None, action: str = "accept", content: Mapping[str, Any] | None = None
) -> ClientView:
    body = dict(content) if content is not None else {APPROVE_FIELD: True}
    result = ElicitResult(action=action, content=body)  # type: ignore[arg-type]
    return ClientView(
        modern=True, form_elicitation=True, input_responses={INPUT_KEY: result}, request_state=token
    )


def ask(st: ApprovalState, args: Mapping[str, Any] = ARGS, preview: Preview = PREVIEW) -> str:
    decision = approve_or_request(ctx(st), TOOL, args, preview, title=TITLE)
    assert isinstance(decision, InputRequired)
    token = decision.result.request_state
    assert isinstance(token, str)
    return token


def decide(
    st: ApprovalState,
    client: ClientView,
    *,
    args: Mapping[str, Any] = ARGS,
    tool: str = TOOL,
    principal: str = "alice",
    preview: Preview = PREVIEW,
) -> Any:
    return approve_or_request(ctx(st, client, principal), tool, args, preview, title=TITLE)


def assert_fresh_challenge(decision: Any, old_token: str | None) -> None:
    assert isinstance(decision, InputRequired), decision
    assert decision.result.request_state != old_token


# --- the elicitation round trip ---------------------------------------------------------------


def test_first_call_asks_the_human_with_the_preview() -> None:
    st = state()
    decision = approve_or_request(ctx(st), TOOL, ARGS, PREVIEW, title=TITLE)
    assert isinstance(decision, InputRequired)
    result = decision.result
    assert result.result_type == "input_required"
    assert result.input_requests is not None
    assert list(result.input_requests) == [INPUT_KEY]
    request = result.input_requests[INPUT_KEY]
    assert isinstance(request, ElicitRequest)
    params = request.params
    assert params.mode == "form"
    assert PREVIEW.summary in params.message
    schema = params.requested_schema  # type: ignore[union-attr]
    # Form mode asks only for approve/deny: one boolean, nothing else (never a secret).
    assert schema["properties"] == {
        APPROVE_FIELD: {
            "type": "boolean",
            "title": "Approve",
            "description": f"Run: {TITLE}",
            "default": False,
        }
    }
    assert schema["required"] == [APPROVE_FIELD]
    assert isinstance(result.request_state, str)


def test_valid_challenge_and_approval_is_approved() -> None:
    st = state()
    token = ask(st)
    decision = decide(st, answer(token))
    assert isinstance(decision, Approved)
    assert decision.method == "elicitation"
    assert decision.nonce is not None


@pytest.mark.parametrize(
    ("action", "content"),
    [("decline", {}), ("cancel", {}), ("accept", {APPROVE_FIELD: False})],
)
def test_deny_is_refused(action: str, content: dict[str, Any]) -> None:
    st = state()
    token = ask(st)
    decision = decide(st, answer(token, action, content))
    assert isinstance(decision, Refused)
    assert decision.code == "confirmation_required"
    assert decision.nonce is not None


def test_a_denied_challenge_cannot_be_reused_to_approve() -> None:
    st = state()
    token = ask(st)
    assert isinstance(decide(st, answer(token, "decline", {})), Refused)
    assert_fresh_challenge(decide(st, answer(token)), token)


def _tamper(token: str) -> str:
    payload, mac = token.split(".")
    flipped = ("A" if mac[0] != "A" else "B") + mac[1:]
    return f"{payload}.{flipped}"


def _forge_payload(token: str, **changes: Any) -> str:
    payload, mac = token.split(".")
    claims = json.loads(approval._b64u_decode(payload))
    claims.update(changes)
    return f"{approval._b64u(approval.canonical_json(claims).encode())}.{mac}"


def test_tampered_mac_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    assert_fresh_challenge(decide(st, answer(_tamper(token))), token)


def test_tampered_payload_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    forged = _forge_payload(token, exp=int(st.clock()) + 10_000)
    assert_fresh_challenge(decide(st, answer(forged)), token)


def test_expired_challenge_gets_a_fresh_challenge() -> None:
    clock = Clock()
    st = state(clock=clock)
    token = ask(st)
    clock.now += CHALLENGE_LIFETIME_S + 1
    assert_fresh_challenge(decide(st, answer(token)), token)


def test_challenge_is_valid_until_it_expires() -> None:
    clock = Clock()
    st = state(clock=clock)
    token = ask(st)
    clock.now += CHALLENGE_LIFETIME_S - 1
    assert isinstance(decide(st, answer(token)), Approved)


def test_replayed_challenge_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    assert isinstance(decide(st, answer(token)), Approved)
    assert_fresh_challenge(decide(st, answer(token)), token)


def test_wrong_principal_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    assert_fresh_challenge(decide(st, answer(token), principal="mallory"), token)


def test_wrong_tool_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    assert_fresh_challenge(decide(st, answer(token), tool="dockhand_prune"), token)


@pytest.mark.parametrize(
    "changed",
    [
        {**ARGS, "stack": "other"},
        {**ARGS, "force": True},
        {**ARGS, "environment_id": 8},
        {**ARGS, "delete_files": True},
    ],
)
def test_changed_arguments_get_a_fresh_challenge(changed: dict[str, Any]) -> None:
    st = state()
    token = ask(st)
    assert_fresh_challenge(decide(st, answer(token), args=changed), token)


def test_a_different_target_gets_a_fresh_challenge() -> None:
    st = state()
    token = ask(st)
    moved = replace(PREVIEW, target={"stack": "shop", "id": "another"})
    assert_fresh_challenge(decide(st, answer(token), preview=moved), token)


def test_confirm_does_not_change_the_hash() -> None:
    st = state()
    token = ask(st)
    assert isinstance(decide(st, answer(token), args={**ARGS, "confirm": True}), Approved)


def test_approval_without_any_challenge_is_not_approved() -> None:
    st = state()
    decision = decide(st, answer(None))
    assert isinstance(decision, InputRequired)


def test_challenge_from_another_key_is_not_approved() -> None:
    st, other = state(), state()
    token = ask(other)
    assert_fresh_challenge(decide(st, answer(token)), token)


@pytest.mark.parametrize(
    "responses",
    [
        None,
        {},
        {"something_else": ElicitResult(action="accept", content={APPROVE_FIELD: True})},
        {INPUT_KEY: ElicitResult(action="accept", content={})},
        {INPUT_KEY: ElicitResult(action="accept", content={APPROVE_FIELD: "yes"})},
        {INPUT_KEY: {"action": "accept"}},
    ],
)
def test_missing_or_malformed_response_asks_again(responses: Any) -> None:
    st = state()
    token = ask(st)
    client = ClientView(
        modern=True, form_elicitation=True, input_responses=responses, request_state=token
    )
    decision = decide(st, client)
    assert isinstance(decision, InputRequired)
    # ... and the unconsumed challenge still works once a proper answer comes.
    assert isinstance(decide(st, answer(token)), Approved)


def test_response_as_a_plain_mapping_is_accepted() -> None:
    st = state()
    token = ask(st)
    client = ClientView(
        modern=True,
        form_elicitation=True,
        input_responses={INPUT_KEY: {"action": "accept", "content": {APPROVE_FIELD: True}}},
        request_state=token,
    )
    assert isinstance(decide(st, client), Approved)


@pytest.mark.parametrize("garbage", ["", ".", "a.b.c", "x" * 2000, "!!!.???", 7])
def test_garbage_challenges_are_never_approved(garbage: Any) -> None:
    st = state()
    client = replace(answer(None), request_state=garbage)
    assert isinstance(decide(st, client), InputRequired)


# --- the scope-all acknowledgement ------------------------------------------------------------

PRUNE_ALL = replace(PREVIEW, requires_scope_ack=True)


def test_scope_all_form_asks_for_both() -> None:
    st = state()
    decision = approve_or_request(ctx(st), TOOL, ARGS, PRUNE_ALL, title=TITLE)
    assert isinstance(decision, InputRequired)
    assert decision.result.input_requests is not None
    params = decision.result.input_requests[INPUT_KEY].params
    schema = params.requested_schema  # type: ignore[union-attr]
    assert set(schema["properties"]) == {APPROVE_FIELD, SCOPE_ACK_FIELD}
    assert set(schema["required"]) == {APPROVE_FIELD, SCOPE_ACK_FIELD}


@pytest.mark.parametrize(
    ("content", "approved"),
    [
        ({APPROVE_FIELD: True}, False),
        ({APPROVE_FIELD: True, SCOPE_ACK_FIELD: False}, False),
        ({APPROVE_FIELD: False, SCOPE_ACK_FIELD: True}, False),
        ({APPROVE_FIELD: True, SCOPE_ACK_FIELD: True}, True),
    ],
)
def test_scope_all_needs_both_approvals(content: dict[str, bool], approved: bool) -> None:
    st = state()
    token = ask(st, preview=PRUNE_ALL)
    decision = decide(st, answer(token, "accept", content), preview=PRUNE_ALL)
    assert isinstance(decision, Approved) is approved
    if not approved:
        assert isinstance(decision, Refused)


@pytest.mark.parametrize(
    ("confirm", "ack", "approved"),
    [(False, False, False), (True, False, False), (False, True, False), (True, True, True)],
)
def test_scope_all_param_path_needs_both(confirm: bool, ack: bool, approved: bool) -> None:
    st = state("param")
    args = {**ARGS, "confirm": confirm, SCOPE_ACK_FIELD: ack}
    decision = decide(st, NOT_ELICITING, args=args, preview=PRUNE_ALL)
    assert isinstance(decision, Approved) is approved


# --- the MAC and the challenge itself ---------------------------------------------------------


def test_mac_compare_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    key = secrets.token_bytes(32)
    token, _ = mint_challenge(key, principal="alice", tool=TOOL, args_hash="h", now=100.0)
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(approval.hmac, "compare_digest", spy)
    verify_challenge(key, token, principal="alice", tool=TOOL, args_hash="h", now=101.0)
    assert calls, "the MAC must be compared with hmac.compare_digest"
    mac = approval._b64u_decode(token.split(".")[1])
    assert (approval._mac(key, token.split(".")[0]), mac) == calls[0]


def test_verification_follows_the_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    key = secrets.token_bytes(32)
    token, _ = mint_challenge(key, principal="alice", tool=TOOL, args_hash="h", now=100.0)
    monkeypatch.setattr(approval.hmac, "compare_digest", lambda a, b: False)
    with pytest.raises(ChallengeError, match="signature"):
        verify_challenge(key, token, principal="alice", tool=TOOL, args_hash="h", now=101.0)


def test_challenge_payload_shape() -> None:
    key = secrets.token_bytes(32)
    token, challenge = mint_challenge(key, principal="alice", tool=TOOL, args_hash="h", now=100.0)
    payload = json.loads(approval._b64u_decode(token.split(".")[0]))
    assert set(payload) == {"nonce", "principal", "tool", "args_sha256", "exp"}
    assert payload["exp"] == 100 + CHALLENGE_LIFETIME_S
    assert payload["nonce"] == challenge.nonce
    other, _ = mint_challenge(key, principal="alice", tool=TOOL, args_hash="h", now=100.0)
    assert other != token  # a fresh nonce every time


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"principal": "bob"}, "principal"),
        ({"tool": "dockhand_prune"}, "tool"),
        ({"args_hash": "other"}, "arguments"),
        ({"now": 100.0 + CHALLENGE_LIFETIME_S}, "expired"),
    ],
)
def test_verify_rejects_mismatches(kwargs: dict[str, Any], reason: str) -> None:
    key = secrets.token_bytes(32)
    token, _ = mint_challenge(key, principal="alice", tool=TOOL, args_hash="h", now=100.0)
    call = {"principal": "alice", "tool": TOOL, "args_hash": "h", "now": 101.0, **kwargs}
    with pytest.raises(ChallengeError, match=reason):
        verify_challenge(key, token, **call)


# --- canonical arguments ----------------------------------------------------------------------


def test_args_hash_is_canonical() -> None:
    a = {"b": 1, "a": {"y": [1, 2], "x": "é"}}
    b = {"a": {"x": "é", "y": [1, 2]}, "b": 1}
    assert args_sha256(a) == args_sha256(b)
    assert args_sha256(a) != args_sha256({**a, "b": 2})


def test_args_hash_excludes_the_approval_fields() -> None:
    base = {"stack": "shop"}
    assert args_sha256(base) == args_sha256({**base, "confirm": True})
    assert args_sha256(base) == args_sha256({**base, SCOPE_ACK_FIELD: True})


# --- replay cache -----------------------------------------------------------------------------


def test_replay_cache_is_single_use() -> None:
    cache = ReplayCache()
    assert cache.consume("n1", exp=200.0, now=100.0) is True
    assert cache.consume("n1", exp=200.0, now=101.0) is False
    assert cache.seen("n1")


def test_replay_cache_is_bounded_and_fails_closed() -> None:
    cache = ReplayCache(max_entries=2)
    assert cache.consume("n1", exp=200.0, now=100.0)
    assert cache.consume("n2", exp=300.0, now=100.0)
    # Full of live entries: refuse rather than forget one that could then be replayed.
    assert cache.consume("n3", exp=300.0, now=150.0) is False
    assert len(cache) == 2
    # Once n1 has expired it can be dropped (an expired challenge never verifies anyway).
    assert cache.consume("n3", exp=400.0, now=250.0) is True
    assert len(cache) == 2
    assert not cache.seen("n1")


# --- the mode matrix --------------------------------------------------------------------------

MODERN_ELICIT = ClientView.from_request(
    "2026-07-28", ClientCapabilities.model_validate({"elicitation": {"form": {}}})
)
MODERN_NONE = ClientView.from_request("2026-07-28", ClientCapabilities())
LEGACY_ELICIT = ClientView.from_request(
    "2025-11-25", ClientCapabilities.model_validate({"elicitation": {"form": {}}})
)
LEGACY_NONE = ClientView.from_request("2025-11-25", None)


def test_client_view_reads_the_capability() -> None:
    assert MODERN_ELICIT.form_elicitation is True
    assert MODERN_NONE.form_elicitation is False
    # An empty elicitation object means form mode (spec, backwards compatibility).
    empty = ClientView.from_request(
        "2026-07-28", ClientCapabilities.model_validate({"elicitation": {}})
    )
    assert empty.form_elicitation is True
    url_only = ClientView.from_request(
        "2026-07-28", ClientCapabilities.model_validate({"elicitation": {"url": {}}})
    )
    assert url_only.form_elicitation is False
    # 2025-11-25 has no MRTR: never elicit, and ignore any MRTR fields.
    assert LEGACY_ELICIT.form_elicitation is False
    legacy = ClientView.from_request("2025-11-25", None, {INPUT_KEY: {}}, "state")
    assert (legacy.input_responses, legacy.request_state) == (None, None)


@pytest.mark.parametrize(
    ("mode", "client", "expected"),
    [
        ("auto", MODERN_ELICIT, "elicitation"),
        ("auto", MODERN_NONE, "param"),
        ("auto", LEGACY_ELICIT, "param"),
        ("auto", LEGACY_NONE, "param"),
        ("elicitation", MODERN_ELICIT, "elicitation"),
        ("elicitation", MODERN_NONE, "refuse"),
        ("elicitation", LEGACY_ELICIT, "refuse"),
        ("elicitation", LEGACY_NONE, "refuse"),
        ("param", MODERN_ELICIT, "param"),
        ("param", MODERN_NONE, "param"),
        ("param", LEGACY_ELICIT, "param"),
        ("param", LEGACY_NONE, "param"),
    ],
)
@pytest.mark.parametrize("confirm", [False, True])
def test_mode_matrix(mode: str, client: ClientView, expected: str, confirm: bool) -> None:
    assert choose_path(mode, client) == expected  # type: ignore[arg-type]
    decision = decide(state(mode), client, args={**ARGS, "confirm": confirm})
    if expected == "elicitation":
        # confirm is ignored: only the human can approve.
        assert isinstance(decision, InputRequired)
    elif expected == "refuse":
        assert isinstance(decision, Refused)
        assert decision.code == "confirmation_required"
        assert "elicitation" in decision.message
        assert decision.with_preview is False
    elif confirm:
        assert isinstance(decision, Approved)
        assert decision.method == "param"
    else:
        assert isinstance(decision, Refused)
        assert decision.code == "confirmation_required"
        assert decision.with_preview is True


def test_approved_cannot_be_made_outside_the_approval_module() -> None:
    with pytest.raises(TypeError):
        Approved("param", None, _mint=object())
    with pytest.raises(TypeError):
        Approved("param", None)  # type: ignore[call-arg]
