"""Symbolic intent narrowing (ported from ``core/symbolic_narrowing.py``).

A cheap, deterministic first filter that categorizes the *intent* of a request
into one of a small set of adversarial categories using a regex/lexicon bank.
Upstream this pre-filtered work for a Qdrant semantic layer; here it stands on
its own as a pure-stdlib categorizer.

Categories:
    exfil     - data exfiltration / secret reading
    destroy   - destructive / irreversible actions
    escalate  - privilege escalation
    evade     - detection / audit evasion
    recon     - reconnaissance / enumeration
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Each category maps to a list of (weight, compiled pattern).
_LEXICON: dict[str, list[tuple[float, re.Pattern[str]]]] = {
    "exfil": [
        (1.0, re.compile(r"\b(?:exfiltrat|leak|steal|dump)\w*")),
        (0.9, re.compile(r"\b(?:api[_ -]?key|secret|password|credential|token|private[_ -]?key)s?\b")),
        (0.7, re.compile(r"\b(?:read|cat|copy|send|upload|post)\b[^.\n]{0,40}\b(?:\.env|/etc/shadow|/etc/passwd|ssh|aws|credentials)\b")),
        (0.6, re.compile(r"\bcurl\b[^\n]*\|\s*(?:bash|sh)\b")),
    ],
    "destroy": [
        (1.0, re.compile(r"\brm\s+-rf\b|\bdrop\s+(?:table|database)\b|\bformat\b\s+\w+:")),
        (0.9, re.compile(r"\b(?:delete|destroy|wipe|erase|shred|truncate)\w*")),
        (0.8, re.compile(r"\b(?:overwrite|corrupt|brick)\w*")),
        (0.7, re.compile(r"\bmkfs\b|\bdd\s+if=")),
    ],
    "escalate": [
        (1.0, re.compile(r"\b(?:sudo|setuid|chmod\s+\+s|privilege\s+escalat)\w*")),
        (0.9, re.compile(r"\b(?:root|administrator|superuser)\b[^.\n]{0,30}\b(?:access|shell|become|escalate)\b")),
        (0.7, re.compile(r"\b(?:grant|elevate|bypass)\b[^.\n]{0,30}\b(?:permission|role|policy|acl)s?\b")),
    ],
    "evade": [
        (1.0, re.compile(r"\b(?:disable|bypass|circumvent|evade|defeat)\b[^.\n]{0,40}\b(?:audit|log|monitor|detect|guard|firewall|security)\w*")),
        (0.9, re.compile(r"\b(?:clear|wipe|tamper\s+with|delete)\b[^.\n]{0,30}\blogs?\b")),
        (0.8, re.compile(r"\bignore\b[^.\n]{0,30}\b(?:previous|prior|above)\b[^.\n]{0,30}\binstructions?\b")),
        (0.7, re.compile(r"\bjailbreak\b|\bdan\s+mode\b|\bdeveloper\s+mode\b")),
    ],
    "recon": [
        (0.8, re.compile(r"\b(?:enumerate|scan|probe|fingerprint|reconnaissance|recon)\w*")),
        (0.7, re.compile(r"\b(?:nmap|masscan|whoami|ifconfig|ipconfig|netstat)\b")),
        (0.6, re.compile(r"\blist\b[^.\n]{0,25}\b(?:users|processes|services|ports|open\s+files)\b")),
    ],
}


@dataclass
class NarrowingResult:
    scores: dict[str, float] = field(default_factory=dict)
    top_category: str | None = None
    top_score: float = 0.0
    matches: dict[str, list[str]] = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return self.top_score > 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scores": self.scores,
            "top_category": self.top_category,
            "top_score": self.top_score,
            "matches": self.matches,
            "flagged": self.flagged,
        }


def narrow(text: str) -> NarrowingResult:
    """Categorize the adversarial intent of ``text``.

    ``text`` is expected to already be normalized (see
    :func:`core.canonicalization.normalize_text`), but the patterns are
    case-insensitive-safe regardless.
    """

    result = NarrowingResult()
    if not text:
        return result

    for category, rules in _LEXICON.items():
        score = 0.0
        hits: list[str] = []
        for weight, pattern in rules:
            for m in pattern.finditer(text):
                score += weight
                hits.append(m.group(0).strip())
        if hits:
            result.scores[category] = round(score, 3)
            result.matches[category] = hits

    if result.scores:
        top = max(result.scores.items(), key=lambda kv: kv[1])
        result.top_category, result.top_score = top[0], top[1]
    return result
