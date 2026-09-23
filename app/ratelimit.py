"""登录失败限流与指数退避：按 (账号, 来源 IP) 双维度计数。

- 滑动窗口内失败达到阈值 -> 进入锁定
- 锁定过期后重新计数，但历史触发次数保留，锁定时长按 2 的幂次增长，封顶
- 锁定期间 check() 直接以 RATE_LIMITED 拒绝
- 登录成功清零
"""

from __future__ import annotations

import logging
import threading
import time

from app.errors import AuthError, ErrorCode

logger = logging.getLogger("auth_sessions.ratelimit")


class LoginRateLimiter:
    def __init__(self, window: int, max_failures: int,
                 base_lockout: int, max_lockout: int) -> None:
        self.window = window
        self.max_failures = max_failures
        self.base_lockout = base_lockout
        self.max_lockout = max_lockout
        self._lock = threading.Lock()
        self._failures: dict[tuple[str, str], list[float]] = {}
        self._counts: dict[tuple[str, str], int] = {}          # 累计触发次数（升级用）
        self._lockouts: dict[tuple[str, str], float] = {}      # 锁定截止时间

    def _key(self, username: str, source: str) -> tuple[str, str]:
        return (username, source)

    def check(self, username: str, source: str, now: float | None = None) -> None:
        """若处于退避锁定中，抛出 RATE_LIMITED（携带 Retry-After 秒数）。"""
        now = time.time() if now is None else now
        key = self._key(username, source)
        with self._lock:
            until = self._lockouts.get(key)
            if until is not None and now < until:
                retry = int(until - now) + 1
                count = self._counts.get(key, 1)
                logger.warning(
                    "login rate-limited username=%s source=%s "
                    "backoff_count=%d retry_after=%ds",
                    username, source, count, retry,
                )
                raise AuthError(
                    ErrorCode.RATE_LIMITED,
                    f"backoff active, retry after {retry}s",
                    extra={"retry_after": retry, "backoff_count": count},
                )

    def record_failure(self, username: str, source: str,
                       now: float | None = None) -> int:
        """记录失败；窗口内累计达到阈值时进入/延长指数退避。返回窗口失败数。"""
        now = time.time() if now is None else now
        key = self._key(username, source)
        with self._lock:
            until = self._lockouts.get(key)
            if until is not None:
                if now < until:
                    return self.max_failures  # 锁定中，不重复计数
                # 锁定过期：窗口重新计数，触发次数保留
                self._lockouts.pop(key, None)
                self._failures.pop(key, None)

            recent = [t for t in self._failures.get(key, [])
                      if now - t < self.window]
            recent.append(now)
            self._failures[key] = recent

            if len(recent) >= self.max_failures:
                count = self._counts.get(key, 0) + 1
                self._counts[key] = count
                delay = min(
                    self.base_lockout * (2 ** (count - 1)),
                    self.max_lockout,
                )
                self._lockouts[key] = now + delay
                logger.warning(
                    "login failures=%d threshold=%d -> backoff %ds (count=%d)",
                    len(recent), self.max_failures, delay, count,
                )
            return len(recent)

    def record_success(self, username: str, source: str) -> None:
        key = self._key(username, source)
        with self._lock:
            self._failures.pop(key, None)
            self._counts.pop(key, None)
            self._lockouts.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._counts.clear()
            self._lockouts.clear()

    def retry_after(self, username: str, source: str,
                    now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            until = self._lockouts.get(self._key(username, source))
            if until is None or now >= until:
                return 0
            return int(until - now) + 1
