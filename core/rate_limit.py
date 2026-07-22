"""In-memory sliding-window rate limiter (ported from ``core/rate_limit.py``).

The upstream module could back its counters with Upstash/Redis for multi-node
deployments.  Per the locked-in decisions that branch is removed: this is the
**in-memory single-node path only**, used to protect the dashboard's HTTP
endpoint from being hammered.  A per-key deque of request timestamps is trimmed
to the window on each call — no external store, thread-safe.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateDecision:
    allowed: bool
    remaining: int
    retry_after: float  # seconds until the next slot frees (0 if allowed)
    limit: int


class RateLimiter:
    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        time_func=time.monotonic,
    ) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._time = time_func
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> None:
        dq = self._hits[key]
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def check(self, key: str) -> RateDecision:
        """Register a hit for ``key`` and report whether it is within budget.

        A rejected request is *not* recorded, so a client that backs off is not
        penalised further while it waits.
        """

        now = self._time()
        with self._lock:
            self._trim(key, now)
            dq = self._hits[key]
            if len(dq) >= self.max_requests:
                retry_after = max(0.0, self.window - (now - dq[0]))
                return RateDecision(False, 0, retry_after, self.max_requests)
            dq.append(now)
            return RateDecision(
                True, self.max_requests - len(dq), 0.0, self.max_requests
            )

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)
