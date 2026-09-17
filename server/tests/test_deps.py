# Drishti v0.1 — rate limiter eviction tests | 11-Jul-2026
"""TokenBucket bucket eviction (core/deps.py) — the per-key dict must not grow
unboundedly with the number of distinct agent/user IDs seen over the process
lifetime.
"""
import time

from app.core.deps import TokenBucket


def test_check_evicts_stale_buckets_once_past_threshold():
    bucket = TokenBucket(rate_per_minute=60, burst=5)
    bucket._EVICT_THRESHOLD = 10
    bucket._EVICT_TTL_SECONDS = 60.0

    now = time.monotonic()
    for i in range(20):
        bucket.check(f"stale-{i}")
    for b in bucket.buckets.values():
        b.last = now - 3600.0  # force everything past the TTL

    assert len(bucket.buckets) == 20
    bucket.check("fresh")  # dict is past threshold, so this sweeps first
    assert len(bucket.buckets) == 1
    assert "fresh" in bucket.buckets


def test_check_keeps_recently_active_buckets():
    bucket = TokenBucket(rate_per_minute=60, burst=5)
    bucket._EVICT_THRESHOLD = 1
    bucket._EVICT_TTL_SECONDS = 3600.0

    bucket.check("active")
    bucket.check("also-active")
    bucket.check("also-active")  # dict is now past threshold, sweep runs but nothing is stale

    assert "active" in bucket.buckets
    assert "also-active" in bucket.buckets


def test_check_does_not_sweep_below_threshold():
    bucket = TokenBucket(rate_per_minute=60, burst=5)
    bucket._EVICT_THRESHOLD = 10_000
    bucket._EVICT_TTL_SECONDS = 0.0  # everything would be "stale" if swept

    for i in range(5):
        bucket.check(f"key-{i}")

    assert len(bucket.buckets) == 5
