# SPDX-License-Identifier: Apache-2.0
"""Rate limiters and client-IP resolution (S-03, S-11)."""

from typing import Any

import pytest

from dockhand_mcp.auth.principal import Principal
from dockhand_mcp.tools.registry import Profile
from dockhand_mcp.transport.ratelimit import (
    MAX_KEYS,
    AuthFailureLimiter,
    DestructiveRateLimiter,
    TokenBucketLimiter,
    client_ip,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def scope(peer: str | None = "192.0.2.1", *xff: str) -> dict[str, Any]:
    headers = [(b"x-forwarded-for", v.encode()) for v in xff]
    return {
        "type": "http",
        "client": (peer, 5000) if peer is not None else None,
        "headers": headers,
    }


def test_token_bucket_allows_the_rate_then_refills() -> None:
    clock = FakeClock()
    bucket = TokenBucketLimiter(60, clock=clock)  # one per second
    assert all(bucket.acquire("a") is None for _ in range(60))
    retry = bucket.acquire("a")
    assert retry == pytest.approx(1.0)
    assert bucket.acquire("b") is None  # per key
    clock.now += 1.0
    assert bucket.acquire("a") is None
    assert bucket.acquire("a") is not None


def test_token_bucket_is_lru_bounded() -> None:
    bucket = TokenBucketLimiter(1, max_keys=3, clock=FakeClock())
    for key in "abcd":
        bucket.acquire(key)
    assert len(bucket) == 3
    assert bucket.acquire("a") is None  # evicted, so it starts fresh
    assert MAX_KEYS == 10_000


def test_auth_failures_block_after_ten_for_five_minutes() -> None:
    clock = FakeClock()
    failures = AuthFailureLimiter(clock=clock)
    for _ in range(9):
        failures.record_failure("ip")
    assert failures.blocked("ip") is None
    failures.record_failure("ip")
    assert failures.blocked("ip") == pytest.approx(300.0)
    assert failures.blocked("other") is None
    clock.now += 299
    assert failures.blocked("ip") == pytest.approx(1.0)
    clock.now += 1.5
    assert failures.blocked("ip") is None
    failures.record_failure("ip")  # the count restarts after the block
    assert failures.blocked("ip") is None


def test_auth_failures_outside_the_window_are_forgotten() -> None:
    clock = FakeClock()
    failures = AuthFailureLimiter(clock=clock)
    for _ in range(9):
        failures.record_failure("ip")
    clock.now += 301
    failures.record_failure("ip")
    assert failures.blocked("ip") is None


def test_auth_failures_are_lru_bounded() -> None:
    failures = AuthFailureLimiter(max_keys=2, clock=FakeClock())
    for key in ("a", "b", "c"):
        failures.record_failure(key)
    assert len(failures) == 2


def test_destructive_limiter_is_per_principal() -> None:
    clock = FakeClock()
    limiter = DestructiveRateLimiter(2, clock=clock)
    alice = Principal("alice", Profile.ADMIN)
    bob = Principal("bob", Profile.ADMIN)
    assert limiter.acquire(alice) is None
    assert limiter.acquire(alice) is None
    assert limiter.acquire(alice) == pytest.approx(30.0)
    assert limiter.acquire(bob) is None


def test_client_ip_is_the_socket_peer_by_default() -> None:
    assert client_ip(scope("192.0.2.1", "203.0.113.5"), trust_proxy=False) == "192.0.2.1"


def test_client_ip_uses_the_right_most_forwarded_entry_when_trusted() -> None:
    s = scope("192.0.2.1", "198.51.100.1, 198.51.100.2", "203.0.113.5")
    assert client_ip(s, trust_proxy=True) == "203.0.113.5"
    assert client_ip(scope("192.0.2.1", "198.51.100.1,203.0.113.6 "), True) == "203.0.113.6"


def test_client_ip_falls_back_to_the_peer() -> None:
    assert client_ip(scope("192.0.2.1"), trust_proxy=True) == "192.0.2.1"
    assert client_ip(scope("192.0.2.1", "not-an-ip"), trust_proxy=True) == "192.0.2.1"
    assert client_ip(scope(None), trust_proxy=False) == "unknown"
