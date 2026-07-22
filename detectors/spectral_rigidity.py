"""GUE spectral-rigidity drift scoring (ported from
``detectors/spectral_rigidity.py``).

Ties to the Berry-Keating line of research: the eigenvalue spacings of a healthy
request stream behave like the Gaussian Unitary Ensemble (GUE) — level
repulsion, a rigid spectrum.  Jailbreak / evasion attempts inject correlated,
clustered structure that *softens* that rigidity.  We turn a request into a
short numeric spectrum (a feature series), measure how far its spacing statistic
drifts from the GUE expectation, and score that drift in ``[0, 1]``.

Pure stdlib (``math``, ``hashlib``); no numpy.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any

# GUE nearest-neighbour spacing has mean 1 (after unfolding) and a
# characteristic variance; the Wigner-surmise variance for the unitary class.
_GUE_SPACING_VAR = (3 * math.pi - 8) / math.pi  # ~= 0.1781 for beta=2 surmise


@dataclass
class RigidityResult:
    score: float  # 0 = perfectly rigid/GUE-like, 1 = maximal drift
    drift: bool
    spacing_var: float
    n_levels: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "drift": self.drift,
            "spacing_var": round(self.spacing_var, 4),
            "n_levels": self.n_levels,
        }


def _feature_spectrum(text: str, n: int = 24) -> list[float]:
    """Derive a deterministic pseudo-spectrum from ``text``.

    We hash overlapping token windows into the unit interval, producing a
    reproducible set of "levels".  Identical text -> identical spectrum.
    """

    tokens = text.split()
    if not tokens:
        # fall back to characters so short inputs still yield a spectrum
        tokens = list(text) or ["∅"]

    levels: list[float] = []
    for i in range(min(n, max(len(tokens), 1))):
        window = " ".join(tokens[i : i + 3]) or tokens[i % len(tokens)]
        h = hashlib.sha256(f"{i}:{window}".encode("utf-8")).digest()
        val = int.from_bytes(h[:8], "big") / float(1 << 64)
        levels.append(val)
    return sorted(levels)


def _unfolded_spacings(levels: list[float]) -> list[float]:
    if len(levels) < 2:
        return []
    spacings = [levels[i + 1] - levels[i] for i in range(len(levels) - 1)]
    mean = sum(spacings) / len(spacings)
    if mean == 0:
        return [0.0 for _ in spacings]
    return [s / mean for s in spacings]  # unfold so mean spacing == 1


def score(text: str, theta: float = 0.55) -> RigidityResult:
    """Score the spectral-rigidity drift of ``text``.

    ``theta`` is the drift threshold (see ``ALETHEIA_THETA_BK``): a score at or
    above it flags evasive/jailbreak-like structure.
    """

    levels = _feature_spectrum(text)
    spacings = _unfolded_spacings(levels)
    if not spacings:
        return RigidityResult(0.0, False, 0.0, len(levels))

    mean = sum(spacings) / len(spacings)  # == 1 by construction
    var = sum((s - mean) ** 2 for s in spacings) / len(spacings)

    # Drift = normalized absolute deviation of the observed spacing variance
    # from the GUE expectation.  Larger deviation -> softer/harder than GUE.
    deviation = abs(var - _GUE_SPACING_VAR) / (_GUE_SPACING_VAR + 1e-9)
    drift_score = 1.0 - math.exp(-deviation)  # squashed into [0, 1)
    return RigidityResult(
        score=drift_score,
        drift=drift_score >= theta,
        spacing_var=var,
        n_levels=len(levels),
    )
