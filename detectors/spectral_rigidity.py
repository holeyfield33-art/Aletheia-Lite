"""GUE spectral-rigidity drift scoring (ported from
``detectors/spectral_rigidity.py``).

Ties to the Berry-Keating line of research.  Natural language, viewed as a
character-class co-occurrence operator, has an eigenvalue spectrum with *level
repulsion* — it behaves like the Gaussian Unitary Ensemble (GUE), a rigid
spectrum.  Evasive constructions — repeated incantations, homoglyph padding,
encoded blobs, delimiter spam — collapse that operator toward degeneracy: its
eigenvalues cluster (level *attraction*), softening the rigidity.  We build the
operator, take its real spectrum with a self-contained Jacobi eigensolver,
unfold it, and score how far its nearest-neighbour spacing statistic drifts from
the GUE expectation.

Pure stdlib (``math``); no numpy.
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from typing import Any

# Wigner-surmise nearest-neighbour spacing variance for the unitary class
# (beta = 2), after unfolding to unit mean spacing.
_GUE_SPACING_VAR = (3 * math.pi - 8) / math.pi  # ~= 0.178

# Number of character-class buckets -> operator dimension.
_BUCKETS = 14


@dataclass
class RigidityResult:
    score: float  # 0 = GUE-rigid, 1 = maximal drift toward degeneracy
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


def _bucket(ch: str) -> int:
    """Map a character to one of ``_BUCKETS`` classes."""

    o = ord(ch)
    if o >= 128:
        return 13  # non-ascii (homoglyphs, padding)
    if ch in "aeiouAEIOU":
        return 0
    if ch.isalpha():
        # split consonants over a few buckets by position for richer structure
        return 1 + (o % 4)  # 1..4
    if ch.isdigit():
        return 5
    if ch.isspace():
        return 6
    cat = unicodedata.category(ch)
    if cat.startswith("P"):
        return 7 + (o % 3)  # punctuation 7..9
    if cat.startswith("S"):
        return 10  # symbols
    if ch in "+/=":  # base64 alphabet tail
        return 11
    return 12  # other control / misc


def _cooccurrence(text: str) -> list[list[float]]:
    """Symmetric adjacent-character co-occurrence operator (``_BUCKETS``²)."""

    m = [[0.0] * _BUCKETS for _ in range(_BUCKETS)]
    prev = None
    for ch in text:
        b = _bucket(ch)
        if prev is not None:
            m[prev][b] += 1.0
            m[b][prev] += 1.0
        prev = b
    return m


def _jacobi_eigenvalues(a: list[list[float]], sweeps: int = 60, tol: float = 1e-10) -> list[float]:
    """Eigenvalues of a real symmetric matrix via the cyclic Jacobi method."""

    n = len(a)
    # work on a copy
    m = [row[:] for row in a]
    for _ in range(sweeps):
        off = 0.0
        for p in range(n - 1):
            for q in range(p + 1, n):
                off += m[p][q] * m[p][q]
        if off < tol:
            break
        for p in range(n - 1):
            for q in range(p + 1, n):
                apq = m[p][q]
                if abs(apq) < 1e-15:
                    continue
                app, aqq = m[p][p], m[q][q]
                phi = 0.5 * math.atan2(2 * apq, aqq - app)
                c, s = math.cos(phi), math.sin(phi)
                for k in range(n):
                    mkp, mkq = m[k][p], m[k][q]
                    m[k][p] = c * mkp - s * mkq
                    m[k][q] = s * mkp + c * mkq
                for k in range(n):
                    mpk, mqk = m[p][k], m[q][k]
                    m[p][k] = c * mpk - s * mqk
                    m[q][k] = s * mpk + c * mqk
    return sorted(m[i][i] for i in range(n))


def score(text: str, theta: float = 0.62) -> RigidityResult:
    """Score the spectral-rigidity drift of ``text`` in ``[0, 1]``.

    ``theta`` is the drift threshold (``ALETHEIA_THETA_BK``): a score at or above
    it flags evasive/jailbreak-like degeneracy.
    """

    if not text or len(text) < 3:
        return RigidityResult(0.0, False, 0.0, 0)

    operator = _cooccurrence(text)
    eigenvalues = _jacobi_eigenvalues(operator)

    # Keep only the meaningfully non-zero part of the spectrum; a spectrum that
    # collapses to a handful of non-zero levels is itself the degeneracy signal.
    scale = max((abs(e) for e in eigenvalues), default=0.0)
    if scale == 0.0:
        return RigidityResult(1.0, True, 0.0, 0)
    levels = sorted(e for e in eigenvalues if abs(e) > 1e-6 * scale)
    if len(levels) < 3:
        # near-total degeneracy -> maximal drift
        return RigidityResult(1.0, True, 0.0, len(levels))

    spacings = [levels[i + 1] - levels[i] for i in range(len(levels) - 1)]
    mean = sum(spacings) / len(spacings)
    if mean <= 0:
        return RigidityResult(1.0, True, 0.0, len(levels))
    unfolded = [s / mean for s in spacings]  # unit mean spacing
    var = sum((s - 1.0) ** 2 for s in unfolded) / len(unfolded)

    # Drift grows with the *excess* spacing variance over the GUE expectation
    # (clustering / degeneracy => var >> GUE).  Deficit below GUE is not
    # penalised (that is "more rigid than GUE", i.e. healthy).
    excess = max(0.0, var - _GUE_SPACING_VAR)
    drift_score = 1.0 - math.exp(-excess)  # squashed into [0, 1)
    return RigidityResult(
        score=drift_score,
        drift=drift_score >= theta,
        spacing_var=var,
        n_levels=len(levels),
    )
