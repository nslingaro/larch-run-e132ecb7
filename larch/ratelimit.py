"""In-process fixed-window rate limiter.

Counters live in the process, so limits apply per running instance. Run one Uvicorn
worker per container (the Dockerfile does) and treat the managed edge (WAF) as the
fleet-wide control.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from larch.config import RateLimit

MAX_TRACKED_KEYS = 100_000


@dataclass
class _Window:
    started: float
    count: int


class RateLimitExceeded(Exception):
    def __init__(self, bucket: str, retry_after: int) -> None:
        super().__init__(bucket)
        self.bucket = bucket
        self.retry_after = retry_after


class RateLimiter:
    def __init__(self, limits: dict[str, RateLimit], clock=time.monotonic) -> None:
        self._limits = limits
        self._clock = clock
        self._windows: dict[tuple[str, str], _Window] = {}
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str) -> None:
        """Count one request against ``bucket`` for ``key``; raise when over the limit."""
        limit = self._limits[bucket]
        now = self._clock()
        with self._lock:
            if len(self._windows) >= MAX_TRACKED_KEYS:
                self._evict(now)
            window = self._windows.get((bucket, key))
            if window is None or now - window.started >= limit.window_seconds:
                window = _Window(started=now, count=0)
                self._windows[(bucket, key)] = window
            window.count += 1
            if window.count > limit.limit:
                retry_after = max(1, math.ceil(window.started + limit.window_seconds - now))
                raise RateLimitExceeded(bucket, retry_after)

    def _evict(self, now: float) -> None:
        expired = [
            k for k, w in self._windows.items() if now - w.started >= self._limits[k[0]].window_seconds
        ]
        for k in expired:
            del self._windows[k]
        if len(self._windows) >= MAX_TRACKED_KEYS:
            # Still full of live windows: drop the oldest half rather than grow without bound.
            for k in sorted(self._windows, key=lambda k: self._windows[k].started)[: MAX_TRACKED_KEYS // 2]:
                del self._windows[k]

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
