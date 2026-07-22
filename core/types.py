"""Shared data model for the agent trifecta and pipeline.

Internal plumbing only — the enums and dataclasses every stage passes around.
Kept in one place so Scout, Nitpicker, Judge, the trifecta and the pipeline all
agree on the shape of a finding, a report and a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Terminal decision for a request.

    ``ALLOW``  — passed every gate; a real pass event (the dashboard gap fix).
    ``OBSERVE``— permitted but flagged for review (medium risk).
    ``BLOCK``  — denied (hard-bound halt, policy deny, or high risk).
    """

    ALLOW = "ALLOW"
    OBSERVE = "OBSERVE"
    BLOCK = "BLOCK"

    def is_block(self) -> bool:
        return self is Verdict.BLOCK


@dataclass
class Finding:
    """A single reason something was flagged."""

    source: str  # scout | nitpicker | judge | safety_bounds | zsp | deputy | ...
    kind: str
    detail: str
    severity: float = 0.0  # 0..1

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "detail": self.detail,
            "severity": round(self.severity, 4),
        }


@dataclass
class AgentReport:
    """What each agent hands to the next stage."""

    agent: str
    suspicion: float  # 0..1 aggregate risk this agent assigns
    verdict_hint: Verdict
    findings: list[Finding] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "suspicion": round(self.suspicion, 4),
            "verdict_hint": self.verdict_hint.value,
            "findings": [f.to_dict() for f in self.findings],
            "detail": self.detail,
        }
