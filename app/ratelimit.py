"""Per-account + per-source login rate limiting with exponential backoff.

Key shape: ``(username_or_sentinel, source_ip)``. Failed attempts are
counted; once the threshold is reached, further attempts (even with the
correct password) are refused with ``429`` and an exponentially growing
``Retry-After``. A quiet window resets the counter.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class Bucket:
    failures: int = 0
    first_failure_at: float = 0.0
    locked_until: float = 0.0


class LoginRateLimiter:
    def __init__(
        self,
        max_attempts: int = 5,
        backoff_base: float = 1.0,
        backoff_multiplier: float = 2.0,
        backoff_max: float = 300.0,
        window_seconds: float = 900.0,
    ) -> None:
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.backoff_multiplier = backoff_multiplier
        self.backoff_max = backoff_max
        self.window_seconds = window_seconds
        self._buckets: dict[tuple[str, str], Bucket] = {}
        self._lock = threading.Lock()

    def _key(self, username: str, source: str) -> tuple[str, str]:
        # Normalize usernames so attempts against unknown accounts are also
        # throttled; missing username gets a fixed sentinel.
        return (username.strip().lower() or "<none>", source or "unknown")

    def _backoff_for(self, strikes: int) -> float:
        exponent = max(0, strikes - self.max_attempts)
        return min(
            self.backoff_max,
            self.backoff_base * (self.backoff_multiplier ** exponent),
        )

    def check(self, username: str, source: str, now: float | None = None) -> float:
        """Return 0 if allowed, otherwise required wait in seconds."""
        now = time.time() if now is None else now
        with self._lock:
            bucket = self._buckets.get(self._key(username, source))
            if bucket is None:
                return 0.0
            if bucket.first_failure_at and now - bucket.first_failure_at > self.window_seconds:
                self._buckets.pop(self._key(username, source), None)
                return 0.0
            if bucket.locked_until > now:
                return bucket.locked_until - now
            return 0.0

    def record_failure(self, username: str, source: str, now: float | None = None) -> float:
        """Register a failed login; return new required wait (0 while under cap)."""
        now = time.time() if now is None else now
        with self._lock:
            key = self._key(username, source)
            bucket = self._buckets.get(key)
            if bucket is None or (
                bucket.first_failure_at and now - bucket.first_failure_at > self.window_seconds
            ):
                bucket = Bucket(failures=0, first_failure_at=now)
                self._buckets[key] = bucket
            bucket.failures += 1
            if bucket.failures >= self.max_attempts:
                bucket.locked_until = now + self._backoff_for(bucket.failures)
                return bucket.locked_until - now
            return 0.0

    def record_success(self, username: str, source: str) -> None:
        with self._lock:
            self._buckets.pop(self._key(username, source), None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
