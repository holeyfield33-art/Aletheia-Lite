"""Token-velocity guard (ported from ``guards/token_velocity.py``).

A pure in-process sliding-window tracker of token spend per key (agent/session).
It enforces two things at once: a *rate* (events per window) and a *budget*
(summed token cost per window).  No external store — a deque of timestamps per
key, trimmed on each call.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any


@dataclass
class VelocityResult:
    allowed: bool
    reason: str
    tokens_in_window: int
    events_in_window: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "tokens_in_window": self.tokens_in_window,
            "events_in_window": self.events_in_window,
        }


class TokenVelocityGuard:
    def __init__(
        self,
        max_tokens: int = 100_000,
        window_seconds: float = 60.0,
        max_events: int | None = None,
        time_func=time.monotonic,
    ) -> None:
        self.max_tokens = max_tokens
        self.window = window_seconds
        self.max_events = max_events
        self._time = time_func
        # key -> deque[(timestamp, tokens)]
        self._events: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> None:
        dq = self._events[key]
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def check(self, key: str, tokens: int) -> VelocityResult:
        """Test whether spending ``tokens`` for ``key`` is allowed — and if so,
        record it.  A rejected request is *not* recorded (it did not spend)."""

        now = self._time()
        with self._lock:
            self._trim(key, now)
            dq = self._events[key]
            cur_tokens = sum(t for _, t in dq)
            cur_events = len(dq)

            if cur_tokens + tokens > self.max_tokens:
                return VelocityResult(
                    False,
                    f"token budget exceeded: {cur_tokens + tokens} > {self.max_tokens}",
                    cur_tokens,
                    cur_events,
                )
            if self.max_events is not None and cur_events + 1 > self.max_events:
                return VelocityResult(
                    False,
                    f"event rate exceeded: {cur_events + 1} > {self.max_events}",
                    cur_tokens,
                    cur_events,
                )

            dq.append((now, tokens))
            return VelocityResult(True, "ok", cur_tokens + tokens, cur_events + 1)

    def usage(self, key: str) -> tuple[int, int]:
        """Return ``(tokens, events)`` currently in the window for ``key``."""

        now = self._time()
        with self._lock:
            self._trim(key, now)
            dq = self._events[key]
            return sum(t for _, t in dq), len(dq)
