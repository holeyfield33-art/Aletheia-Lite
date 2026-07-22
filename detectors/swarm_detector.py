"""SPRT swarm detector (ported from ``detectors/swarm_detector.py``).

Coordinated multi-session attacks look benign one request at a time but shift
the *rate* of suspicious requests across a population of sessions.  A Sequential
Probability Ratio Test (SPRT) accumulates evidence per observation and declares
"swarm" or "benign" only when the log-likelihood ratio crosses a boundary set by
the target error rates — so it reaches a decision with the fewest observations
while bounding false positives/negatives.

Always enabled, no external dependencies.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SPRTResult:
    decision: str  # "swarm" | "benign" | "continue"
    log_lr: float
    observations: int
    upper: float
    lower: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "log_lr": round(self.log_lr, 4),
            "observations": self.observations,
            "upper": round(self.upper, 4),
            "lower": round(self.lower, 4),
        }


class SwarmDetector:
    """Bernoulli SPRT over a stream of binary "suspicious?" observations.

    Parameters
    ----------
    p0: benign suspicious-rate (null hypothesis)
    p1: attack suspicious-rate (alternative hypothesis), must exceed ``p0``
    alpha: tolerated false-positive rate
    beta: tolerated false-negative rate
    """

    def __init__(
        self,
        p0: float = 0.15,
        p1: float = 0.65,
        alpha: float = 0.05,
        beta: float = 0.05,
    ) -> None:
        if not 0 < p0 < p1 < 1:
            raise ValueError("require 0 < p0 < p1 < 1")
        self.p0 = p0
        self.p1 = p1
        # Wald boundaries on the log scale.
        self.upper = math.log((1 - beta) / alpha)
        self.lower = math.log(beta / (1 - alpha))
        self._log_lr = 0.0
        self._n = 0
        self._lock = threading.Lock()
        # Precomputed per-observation increments.
        self._inc_pos = math.log(p1 / p0)
        self._inc_neg = math.log((1 - p1) / (1 - p0))

    def reset(self) -> None:
        with self._lock:
            self._log_lr = 0.0
            self._n = 0

    def observe(self, suspicious: bool) -> SPRTResult:
        """Feed one observation and return the current decision state."""

        with self._lock:
            self._log_lr += self._inc_pos if suspicious else self._inc_neg
            self._n += 1
            if self._log_lr >= self.upper:
                decision = "swarm"
            elif self._log_lr <= self.lower:
                decision = "benign"
            else:
                decision = "continue"
            result = SPRTResult(decision, self._log_lr, self._n, self.upper, self.lower)
            # Reset after a terminal decision so the test can run again.
            if decision != "continue":
                self._log_lr = 0.0
                self._n = 0
            return result
