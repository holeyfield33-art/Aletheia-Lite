"""Agent trifecta orchestration (ported from ``core/agent_trifecta.py``).

Wires the three agents into the fixed pipeline Scout → Nitpicker → Judge and
returns the Judge's terminal verdict together with the intermediate reports so
the caller (the audit pipeline) can persist the full reasoning trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonicalization import CanonicalRequest
from .judge import Judge
from .nitpicker import Nitpicker
from .scout import Scout
from .types import AgentReport, Finding, Verdict


@dataclass
class TrifectaResult:
    verdict: Verdict
    suspicion: float
    scout: AgentReport
    nitpicker: AgentReport
    judge: AgentReport
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "suspicion": round(self.suspicion, 4),
            "scout": self.scout.to_dict(),
            "nitpicker": self.nitpicker.to_dict(),
            "judge": self.judge.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


class Trifecta:
    def __init__(
        self,
        deny_categories: list[str] | None = None,
        theta_bk: float | None = None,
    ) -> None:
        self.scout = Scout(theta_bk=theta_bk)
        self.nitpicker = Nitpicker()
        self.judge = Judge(deny_categories=deny_categories)

    def evaluate(
        self,
        request: CanonicalRequest,
        *,
        max_resource_cost: int | None = None,
    ) -> TrifectaResult:
        scout_report = self.scout.inspect(request)
        nitpicker_report = self.nitpicker.recheck(request, scout_report)
        judge_report = self.judge.decide(
            request, scout_report, nitpicker_report, max_resource_cost=max_resource_cost
        )
        return TrifectaResult(
            verdict=judge_report.verdict_hint,
            suspicion=judge_report.suspicion,
            scout=scout_report,
            nitpicker=nitpicker_report,
            judge=judge_report,
            findings=judge_report.findings,
        )
