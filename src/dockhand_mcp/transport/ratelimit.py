# SPDX-License-Identifier: Apache-2.0
"""Rate limits (S-03, S-11) and client-IP resolution.

- Global limit: a token bucket per client IP (`DOCKHAND_MCP_RATE_LIMIT_PER_MIN`).
- Auth failures: 10 wrong tokens from one IP within 5 minutes block it for 5 minutes (DockHand's
  own policy for its tokens).
- Destructive calls: a token bucket per principal (`DOCKHAND_MCP_DESTRUCTIVE_PER_MIN`), wired by
  the destructive tools.

Every table is LRU-bounded at `MAX_KEYS`. The client IP is the socket peer, unless
`DOCKHAND_MCP_TRUST_PROXY=true`, in which case it is the right-most `X-Forwarded-For` entry: the
one our proxy appended. Entries to its left are whatever the client sent.
"""

import ipaddress
import json
import math
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

if TYPE_CHECKING:
    from dockhand_mcp.auth.principal import Principal

MAX_KEYS: Final = 10_000
AUTH_MAX_FAILURES: Final = 10
AUTH_WINDOW_S: Final = 300.0
AUTH_BLOCK_S: Final = 300.0

Clock = Callable[[], float]


def client_ip(scope: Scope, trust_proxy: bool) -> str:
    peer = scope.get("client")
    ip = str(peer[0]) if peer else "unknown"
    if not trust_proxy:
        return ip
    forwarded = b",".join(v for k, v in scope["headers"] if k == b"x-forwarded-for")
    entries = [e.strip() for e in forwarded.decode("latin-1").split(",") if e.strip()]
    if not entries:
        return ip
    try:
        return str(ipaddress.ip_address(entries[-1]))
    except ValueError:
        return ip


def scope_client_ip(scope: Scope) -> str:
    """The client IP resolved by `RateLimitMiddleware` earlier in the pipeline."""
    ip = scope.get("state", {}).get("client_ip")
    return str(ip) if ip is not None else client_ip(scope, trust_proxy=False)


class _Lru[V]:
    def __init__(self, max_keys: int) -> None:
        self._items: OrderedDict[str, V] = OrderedDict()
        self._max = max_keys

    def get(self, key: str) -> V | None:
        value = self._items.get(key)
        if value is not None:
            self._items.move_to_end(key)
        return value

    def put(self, key: str, value: V) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)

    def pop(self, key: str) -> None:
        self._items.pop(key, None)

    def __len__(self) -> int:
        return len(self._items)


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    """`per_minute` requests per key, refilled continuously, with a burst of `per_minute`."""

    def __init__(
        self, per_minute: int, *, max_keys: int = MAX_KEYS, clock: Clock = time.monotonic
    ) -> None:
        self._capacity = float(per_minute)
        self._rate = per_minute / 60.0
        self._clock = clock
        self._buckets: _Lru[_Bucket] = _Lru(max_keys)

    def acquire(self, key: str) -> float | None:
        """Take a token: None if allowed, else the seconds until one is available."""
        now = self._clock()
        bucket = self._buckets.get(key) or _Bucket(self._capacity, now)
        bucket.tokens = min(self._capacity, bucket.tokens + (now - bucket.updated) * self._rate)
        bucket.updated = now
        self._buckets.put(key, bucket)
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return None
        return (1.0 - bucket.tokens) / self._rate

    def __len__(self) -> int:
        return len(self._buckets)


@dataclass
class _Failures:
    times: deque[float]
    blocked_until: float = 0.0


class AuthFailureLimiter:
    def __init__(
        self,
        max_failures: int = AUTH_MAX_FAILURES,
        window_s: float = AUTH_WINDOW_S,
        block_s: float = AUTH_BLOCK_S,
        *,
        max_keys: int = MAX_KEYS,
        clock: Clock = time.monotonic,
    ) -> None:
        self._max = max_failures
        self._window = window_s
        self._block = block_s
        self._clock = clock
        self._entries: _Lru[_Failures] = _Lru(max_keys)

    def blocked(self, key: str) -> float | None:
        """Seconds left on this key's block, or None if it is not blocked."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        remaining = entry.blocked_until - self._clock()
        return remaining if remaining > 0 else None

    def record_failure(self, key: str) -> None:
        now = self._clock()
        entry = self._entries.get(key) or _Failures(deque(maxlen=self._max))
        while entry.times and now - entry.times[0] >= self._window:
            entry.times.popleft()
        entry.times.append(now)
        if len(entry.times) >= self._max:
            entry.blocked_until = now + self._block
            entry.times.clear()
        self._entries.put(key, entry)

    def __len__(self) -> int:
        return len(self._entries)


class DestructiveRateLimiter:
    """Per-principal limit on destructive calls (S-11), independent of the global limit."""

    def __init__(self, per_minute: int, *, clock: Clock = time.monotonic) -> None:
        self._buckets = TokenBucketLimiter(per_minute, clock=clock)

    def acquire(self, principal: Principal) -> float | None:
        return self._buckets.acquire(principal.name)


def too_many(retry_after: float) -> Response:
    body = json.dumps({"error": "rate_limited"}, separators=(",", ":"))
    return Response(
        body,
        status_code=429,
        media_type="application/json",
        headers={"retry-after": str(max(1, math.ceil(retry_after)))},
    )


class RateLimitMiddleware:
    """Resolve the client IP (kept for later stages) and apply the global per-IP limit."""

    def __init__(self, app: ASGIApp, limiter: TokenBucketLimiter, *, trust_proxy: bool) -> None:
        self.app = app
        self.limiter = limiter
        self.trust_proxy = trust_proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = client_ip(scope, self.trust_proxy)
        scope["state"] = {**scope.get("state", {}), "client_ip": ip}
        retry_after = self.limiter.acquire(ip)
        if retry_after is not None:
            await too_many(retry_after)(scope, receive, send)
            return
        await self.app(scope, receive, send)
