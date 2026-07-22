"""In-process circuit breaker (ported from ``guards/circuit_breaker.py``).

A pure, thread-safe, dependency-free breaker that protects the pipeline from
resource-exhaustion: after ``max_failures`` consecutive failures it trips
``OPEN`` and short-circuits calls for ``reset_timeout`` seconds, then allows a
single ``HALF_OPEN`` trial before closing again.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any


class State(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """Raised when a call is attempted while the breaker is OPEN."""


class CircuitBreaker:
    def __init__(
        self,
        max_failures: int = 5,
        reset_timeout: float = 30.0,
        time_func=time.monotonic,
    ) -> None:
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self._time = time_func
        self._state = State.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> State:
        with self._lock:
            self._maybe_half_open()
            return self._state

    def _maybe_half_open(self) -> None:
        if self._state is State.OPEN and self._time() - self._opened_at >= self.reset_timeout:
            self._state = State.HALF_OPEN

    def allow(self) -> bool:
        """Whether a call may proceed right now."""

        with self._lock:
            self._maybe_half_open()
            return self._state is not State.OPEN

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = State.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state is State.HALF_OPEN or self._failures >= self.max_failures:
                self._state = State.OPEN
                self._opened_at = self._time()

    def call(self, func, *args, **kwargs) -> Any:
        """Execute ``func`` under the breaker, updating state on the outcome."""

        if not self.allow():
            raise CircuitOpenError("circuit breaker is open")
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._maybe_half_open()
            return {
                "state": self._state.value,
                "failures": self._failures,
                "max_failures": self.max_failures,
            }
