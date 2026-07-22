"""Secondary escalation drift probe (ported from
``detectors/escalation_probe.py``).

When the primary spectral-rigidity score lands in the inconclusive band, this
lightweight probe casts a second, independent vote by looking for *escalation
gradients*: language that ratchets scope upward ("also", "and then", "now with
admin", "additionally grant") combined with privilege/verb intensity.  It is
intentionally small — a tie-breaker, not a primary detector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_RATCHET = re.compile(
    r"\b(?:also|additionally|furthermore|and then|next|now|as well|on top of that|while you'?re at it)\b"
)
_PRIV_VERBS = re.compile(
    r"\b(?:grant|elevate|escalate|promote|extend|widen|bypass|override|disable|unlock)\b"
)
_PRIV_NOUNS = re.compile(
    r"\b(?:admin|root|superuser|sudo|permission|privilege|scope|access|policy|guardrail|restriction)s?\b"
)


@dataclass
class EscalationResult:
    score: float
    escalating: bool
    ratchets: int
    priv_hits: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "escalating": self.escalating,
            "ratchets": self.ratchets,
            "priv_hits": self.priv_hits,
        }


def probe(text: str, threshold: float = 0.5) -> EscalationResult:
    """Return an escalation-gradient score in ``[0, 1]``.

    The score rewards co-occurrence of scope-ratcheting connectors with
    privilege verbs/nouns; either signal alone scores low.
    """

    if not text:
        return EscalationResult(0.0, False, 0, 0)

    ratchets = len(_RATCHET.findall(text))
    priv = len(_PRIV_VERBS.findall(text)) + len(_PRIV_NOUNS.findall(text))

    # Co-occurrence weighting: the product term dominates so that a single
    # isolated signal stays under threshold.
    combined = 0.35 * min(priv, 3) / 3 + 0.65 * min(ratchets * priv, 6) / 6
    score = min(1.0, combined)
    return EscalationResult(score, score >= threshold, ratchets, priv)
