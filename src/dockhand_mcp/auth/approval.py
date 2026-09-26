# SPDX-License-Identifier: Apache-2.0
"""Human approval for destructive calls (D-006, ARCHITECTURE §7).

The decision comes from the human, through the client, not from an argument the model can set:

1. An unapproved destructive call answers with an MCP 2026-07-28 `input_required` result. It
   carries one form-mode elicitation (`INPUT_KEY`) showing the preview and asking only for
   approve/deny (plus, for a prune of everything, an acknowledgement), and a server-minted
   challenge as its `requestState`.
2. The client asks the human and retries the same call with `inputResponses` and the challenge.
3. The retry is approved only when the challenge's HMAC verifies (constant-time compare), it is
   unexpired, this principal, tool and canonical-argument hash match, it has never been used
   (single-use replay cache), and the human explicitly approved. Anything else is answered with
   a fresh challenge, never an approval.

The challenge is `base64url(json{nonce, principal, tool, args_sha256, exp}) "." base64url(mac)`,
where `mac = HMAC-SHA256(key, <the base64url payload text>)`. The server keeps no state about
issued challenges; the replay cache records only used ones, bounded and expiring with them.

Clients that do not declare the form elicitation capability on a 2026-07-28 request fall back
per `DOCKHAND_MCP_CONFIRM_MODE`: `auto` and `param` use the `confirm` argument, `elicitation`
refuses. Handshake-era (2025-11-25) requests never elicit: the SDK's stateless HTTP transport has
no channel back to the client and does not see the handshake's capabilities, and MRTR does not
exist in that revision.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, final

from mcp_types import (
    ClientCapabilities,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from dockhand_mcp.client.errors import ErrorCode
from dockhand_mcp.transport.ratelimit import DestructiveRateLimiter

if TYPE_CHECKING:
    from dockhand_mcp.config import Settings

log = logging.getLogger(__name__)

CHALLENGE_LIFETIME_S: Final = 120
# Challenges are minted only by rate-limited calls (DOCKHAND_MCP_DESTRUCTIVE_PER_MIN <= 1000), so
# at most 2000 can be consumed within one lifetime; a full cache of live entries refuses.
REPLAY_CACHE_MAX: Final = 4096
MAX_CHALLENGE_CHARS: Final = 1024
# Arguments that carry the approval itself; never part of the argument hash.
APPROVAL_FIELDS: Final = frozenset({"confirm", "scope_all_acknowledged"})
# The key under which the preview's resolved target joins the hashed arguments.
TARGET_KEY: Final = "_target"
INPUT_KEY: Final = "dockhand_approval"
APPROVE_FIELD: Final = "approve"
SCOPE_ACK_FIELD: Final = "scope_all_acknowledged"
MAX_MESSAGE_CHARS: Final = 4000

ConfirmMode = Literal["auto", "elicitation", "param"]
ApprovalMethod = Literal["elicitation", "param"]
Path = Literal["elicitation", "param", "refuse"]
Clock = Callable[[], float]

_B64URL: Final = re.compile(r"^[A-Za-z0-9_-]+$")
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# --- canonical arguments ----------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, ASCII only."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def args_sha256(args: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical arguments, the approval fields excluded."""
    kept = {k: v for k, v in args.items() if k not in APPROVAL_FIELDS}
    return hashlib.sha256(canonical_json(kept).encode("ascii")).hexdigest()


# --- challenges -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Challenge:
    nonce: str
    principal: str
    tool: str
    args_sha256: str
    exp: int


class ChallengeError(Exception):
    """A challenge that does not verify; the message is a log-only reason."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    """Strict inverse of `_b64u`: only the canonical unpadded encoding decodes."""
    if not _B64URL.match(text):
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64u(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def _mac(key: bytes, payload: str) -> bytes:
    return hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()


def mint_challenge(
    key: bytes,
    *,
    principal: str,
    tool: str,
    args_hash: str,
    now: float,
    lifetime_s: int = CHALLENGE_LIFETIME_S,
) -> tuple[str, Challenge]:
    """A signed challenge for this principal, tool and argument hash, valid `lifetime_s`."""
    challenge = Challenge(
        nonce=secrets.token_urlsafe(16),
        principal=principal,
        tool=tool,
        args_sha256=args_hash,
        exp=int(now) + lifetime_s,
    )
    payload = _b64u(canonical_json(asdict(challenge)).encode("ascii"))
    return f"{payload}.{_b64u(_mac(key, payload))}", challenge


def _parse_payload(payload: str) -> Challenge:
    try:
        claims = json.loads(_b64u_decode(payload))
    except ValueError, binascii.Error:
        raise ChallengeError("malformed") from None
    if not isinstance(claims, dict) or set(claims) != {
        "nonce",
        "principal",
        "tool",
        "args_sha256",
        "exp",
    }:
        raise ChallengeError("malformed")
    exp = claims["exp"]
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise ChallengeError("malformed")
    strings = (claims["nonce"], claims["principal"], claims["tool"], claims["args_sha256"])
    if not all(isinstance(s, str) for s in strings):
        raise ChallengeError("malformed")
    return Challenge(**claims)


def verify_challenge(
    key: bytes,
    token: object,
    *,
    principal: str,
    tool: str,
    args_hash: str,
    now: float,
    lifetime_s: int = CHALLENGE_LIFETIME_S,
) -> Challenge:
    """The challenge in `token` if it is ours, unexpired, and bound to exactly this call.

    Raises `ChallengeError` otherwise. The MAC is checked (in constant time) before anything in
    the payload is trusted. Single use is the replay cache's job, not this function's.
    """
    if not isinstance(token, str) or len(token) > MAX_CHALLENGE_CHARS or token.count(".") != 1:
        raise ChallengeError("malformed")
    payload, mac_text = token.split(".")
    if not _B64URL.match(payload):
        raise ChallengeError("malformed")
    try:
        given = _b64u_decode(mac_text)
    except ValueError, binascii.Error:
        raise ChallengeError("malformed") from None
    if not hmac.compare_digest(_mac(key, payload), given):
        raise ChallengeError("signature")
    challenge = _parse_payload(payload)
    if not now < challenge.exp:
        raise ChallengeError("expired")
    if challenge.exp > now + lifetime_s + 1:
        raise ChallengeError("lifetime")
    if not hmac.compare_digest(challenge.principal.encode(), principal.encode()):
        raise ChallengeError("principal")
    if challenge.tool != tool:
        raise ChallengeError("tool")
    if challenge.args_sha256 != args_hash:
        raise ChallengeError("arguments")
    return challenge


class ReplayCache:
    """Nonces of challenges already used, each kept until its challenge expires.

    Bounded: when full of unexpired entries, `consume` refuses (fails closed) rather than
    forgetting a nonce that could then be replayed.
    """

    def __init__(self, max_entries: int = REPLAY_CACHE_MAX) -> None:
        self._used: OrderedDict[str, float] = OrderedDict()
        self._max = max_entries

    def _purge(self, now: float) -> None:
        for nonce in [n for n, exp in self._used.items() if exp <= now]:
            del self._used[nonce]

    def seen(self, nonce: str) -> bool:
        return nonce in self._used

    def consume(self, nonce: str, exp: float, now: float) -> bool:
        """Record `nonce` as used. False if it was used before, or the cache is full."""
        if nonce in self._used:
            return False
        if len(self._used) >= self._max:
            self._purge(now)
            if len(self._used) >= self._max:
                log.warning("approval_replay_cache_full", extra={"entries": len(self._used)})
                return False
        self._used[nonce] = exp
        return True

    def __len__(self) -> int:
        return len(self._used)


# --- what the client can do -------------------------------------------------------------------


@dataclass(frozen=True)
class ClientView:
    """What this request says about the client, as the SDK reports it."""

    modern: bool
    form_elicitation: bool
    input_responses: Mapping[str, Any] | None = None
    request_state: str | None = None

    @classmethod
    def from_request(
        cls,
        protocol_version: str | None,
        capabilities: ClientCapabilities | None,
        input_responses: Mapping[str, Any] | None = None,
        request_state: str | None = None,
    ) -> ClientView:
        modern = protocol_version in MODERN_PROTOCOL_VERSIONS
        elicitation = capabilities.elicitation if capabilities is not None else None
        # An empty `elicitation: {}` means form mode (spec, for backwards compatibility).
        form = elicitation is not None and (elicitation.form is not None or elicitation.url is None)
        return cls(
            modern=modern,
            form_elicitation=modern and form,
            input_responses=input_responses if modern else None,
            request_state=request_state if modern else None,
        )


def choose_path(mode: ConfirmMode, client: ClientView) -> Path:
    """The D-006 mode matrix."""
    if mode == "param":
        return "param"
    if client.modern and client.form_elicitation:
        return "elicitation"
    return "param" if mode == "auto" else "refuse"


# --- process and request state ----------------------------------------------------------------


@dataclass
class ApprovalState:
    """Process-wide: the challenge key, the replay cache and the destructive rate limit."""

    key: bytes
    mode: ConfirmMode
    limiter: DestructiveRateLimiter
    replay: ReplayCache = field(default_factory=ReplayCache)
    clock: Clock = time.time

    @classmethod
    def from_settings(cls, settings: Settings) -> ApprovalState:
        return cls(
            key=settings.challenge_key_bytes,
            mode=settings.confirm_mode,
            limiter=DestructiveRateLimiter(settings.destructive_per_min),
        )


@dataclass(frozen=True)
class ApprovalContext:
    """One call's view: the process state, who is calling, and what their client sent."""

    state: ApprovalState
    principal: str
    client: ClientView


@dataclass(frozen=True)
class Preview:
    """What a destructive call would do, from DockHand's read endpoints.

    `summary` is shown to the human (our text plus DockHand names; no values), `data` is returned
    on the confirm path, `counts` goes to the audit log. `target` holds the resolved IDs the call
    will act on: the execute step uses them, and the challenge is bound to them as well as to the
    arguments, so a name that resolves to something else on the retry needs a new approval.
    `requires_scope_ack` asks for the extra acknowledgement (a prune of everything).
    """

    summary: str
    data: Mapping[str, Any]
    counts: Mapping[str, int] = field(default_factory=dict)
    target: Mapping[str, Any] = field(default_factory=dict)
    requires_scope_ack: bool = False


# --- decisions --------------------------------------------------------------------------------

_MINT: Final = object()


@final
class Approved:
    """Proof of approval. Only `approve_or_request` creates one; destructive work requires it."""

    __slots__ = ("method", "nonce")

    method: ApprovalMethod
    nonce: str | None

    def __init__(self, method: ApprovalMethod, nonce: str | None, *, _mint: object) -> None:
        if _mint is not _MINT:
            raise TypeError("Approved is created only by approve_or_request")
        self.method = method
        self.nonce = nonce

    def __repr__(self) -> str:
        return f"Approved(method={self.method!r})"


@dataclass(frozen=True)
class InputRequired:
    result: InputRequiredResult
    nonce: str


@dataclass(frozen=True)
class Refused:
    code: ErrorCode
    message: str
    nonce: str | None = None
    with_preview: bool = False


Decision = Approved | InputRequired | Refused

ELICITATION_REQUIRED: Final = (
    "This server requires human approval through the client (DOCKHAND_MCP_CONFIRM_MODE="
    "elicitation), and this request did not declare the form elicitation capability. Nothing "
    "was done. Use a client that supports MCP 2026-07-28 elicitation."
)
CONFIRM_NEEDED: Final = (
    "Not approved: nothing was done. data.preview shows what this call would do; to go ahead, "
    "repeat the call with confirm=true"
)
DECLINED: Final = "The human did not approve this operation. Nothing was done."
ACK_MISSING: Final = (
    "Approved without acknowledging that every unused container, image, network and volume "
    "will be pruned. Nothing was done."
)


def _clean(text: str) -> str:
    return _CONTROL.sub(" ", text)


def _message(title: str, preview: Preview) -> str:
    text = (
        f"dockhand-mcp asks for approval to run a destructive operation: {title}.\n\n"
        f"{_clean(preview.summary)}\n\n"
        "It cannot be undone. Nothing happens unless you approve."
    )
    if len(text) > MAX_MESSAGE_CHARS:
        text = text[: MAX_MESSAGE_CHARS - 1] + "…"
    return text


def _form(title: str, preview: Preview) -> ElicitRequest:
    properties: dict[str, Any] = {
        APPROVE_FIELD: {
            "type": "boolean",
            "title": "Approve",
            "description": f"Run: {title}",
            "default": False,
        }
    }
    if preview.requires_scope_ack:
        properties[SCOPE_ACK_FIELD] = {
            "type": "boolean",
            "title": "Prune everything unused",
            "description": "I understand this prunes every unused container, image, network "
            "and volume in the environment.",
            "default": False,
        }
    return ElicitRequest(
        params=ElicitRequestFormParams(
            message=_message(title, preview),
            requested_schema={
                "type": "object",
                "properties": properties,
                "required": list(properties),
            },
        )
    )


def _response(client: ClientView) -> tuple[str, dict[str, Any]] | None:
    """The (action, content) the client sent for our input request, if well-formed."""
    responses = client.input_responses
    raw = responses.get(INPUT_KEY) if isinstance(responses, Mapping) else None
    if isinstance(raw, Mapping):
        try:
            raw = ElicitResult.model_validate(raw)
        except ValueError:
            return None
    if not isinstance(raw, ElicitResult):
        return None
    content = dict(raw.content or {})
    if raw.action == "accept" and not isinstance(content.get(APPROVE_FIELD), bool):
        return None
    return raw.action, content


def _fresh(
    ctx: ApprovalContext, tool: str, args_hash: str, title: str, preview: Preview
) -> InputRequired:
    token, challenge = mint_challenge(
        ctx.state.key,
        principal=ctx.principal,
        tool=tool,
        args_hash=args_hash,
        now=ctx.state.clock(),
    )
    result = InputRequiredResult(
        input_requests={INPUT_KEY: _form(title, preview)}, request_state=token
    )
    return InputRequired(result=result, nonce=challenge.nonce)


def _elicitation(
    ctx: ApprovalContext, tool: str, args: Mapping[str, Any], preview: Preview, title: str
) -> Decision:
    args_hash = args_sha256({**args, TARGET_KEY: dict(preview.target)})
    client = ctx.client
    if client.request_state is None and not client.input_responses:
        return _fresh(ctx, tool, args_hash, title, preview)
    now = ctx.state.clock()
    try:
        challenge = verify_challenge(
            ctx.state.key,
            client.request_state,
            principal=ctx.principal,
            tool=tool,
            args_hash=args_hash,
            now=now,
        )
    except ChallengeError as e:
        log.warning("approval_challenge_rejected", extra={"tool": tool, "reason": str(e)})
        return _fresh(ctx, tool, args_hash, title, preview)
    answer = _response(client)
    if answer is None:
        log.warning("approval_response_missing", extra={"tool": tool, "nonce": challenge.nonce})
        return _fresh(ctx, tool, args_hash, title, preview)
    if not ctx.state.replay.consume(challenge.nonce, challenge.exp, now):
        log.warning(
            "approval_challenge_rejected",
            extra={"tool": tool, "reason": "replayed", "nonce": challenge.nonce},
        )
        return _fresh(ctx, tool, args_hash, title, preview)
    action, content = answer
    if action != "accept" or content.get(APPROVE_FIELD) is not True:
        return Refused("confirmation_required", DECLINED, nonce=challenge.nonce)
    if preview.requires_scope_ack and content.get(SCOPE_ACK_FIELD) is not True:
        return Refused("confirmation_required", ACK_MISSING, nonce=challenge.nonce)
    return Approved("elicitation", challenge.nonce, _mint=_MINT)


def _param(args: Mapping[str, Any], preview: Preview) -> Decision:
    confirmed = args.get("confirm") is True
    acknowledged = not preview.requires_scope_ack or args.get(SCOPE_ACK_FIELD) is True
    if confirmed and acknowledged:
        return Approved("param", None, _mint=_MINT)
    message = CONFIRM_NEEDED + (
        " and scope_all_acknowledged=true." if preview.requires_scope_ack else "."
    )
    return Refused("confirmation_required", message, with_preview=True)


def approve_or_request(
    ctx: ApprovalContext, tool: str, args: Mapping[str, Any], preview: Preview, *, title: str
) -> Decision:
    """Approve this call, ask the human (a fresh challenge), or refuse.

    `args` are the call's canonical arguments (validated, defaults filled, the environment
    resolved), approval fields included. `Approved` is returned only for a verified, unused
    challenge the human approved, or for `confirm=true` where the mode allows the param path.
    """
    path = choose_path(ctx.state.mode, ctx.client)
    if path == "refuse":
        return Refused("confirmation_required", ELICITATION_REQUIRED)
    if path == "param":
        return _param(args, preview)
    return _elicitation(ctx, tool, args, preview, title)
