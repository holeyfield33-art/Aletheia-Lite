"""Judge — final verdict agent (ported from ``agents/judge.py``).

The Judge is the only stage that renders a terminal :class:`Verdict`.  It takes
Scout's and Nitpicker's reports, applies the *hard* runtime invariants
(:mod:`detectors.safety_bounds` — any halt forces ``BLOCK`` no matter the
scores), honors the signed manifest's deny-listed intent categories, then maps
the combined suspicion onto ``ALLOW`` / ``OBSERVE`` / ``BLOCK``.
"""

from __future__ import annotations

from .canonicalization import CanonicalRequest
from detectors import safety_bounds as _safety
from .types import AgentReport, Finding, Verdict

# Suspicion -> verdict thresholds.
BLOCK_THRESHOLD = 0.7
OBSERVE_THRESHOLD = 0.3


class Judge:
    def __init__(
        self,
        deny_categories: list[str] | None = None,
        block_threshold: float = BLOCK_THRESHOLD,
        observe_threshold: float = OBSERVE_THRESHOLD,
    ) -> None:
        self.deny_categories = set(deny_categories or [])
        self.block_threshold = block_threshold
        self.observe_threshold = observe_threshold

    def decide(
        self,
        request: CanonicalRequest,
        scout: AgentReport,
        nitpicker: AgentReport,
        *,
        max_resource_cost: int | None = None,
    ) -> AgentReport:
        findings: list[Finding] = list(scout.findings) + list(nitpicker.findings)
        cleartext = scout.detail.get("cleartext") or request.canonical

        # 1. Hard invariants — a halt is terminal.
        safety = _safety.check(
            cleartext,
            requested_resources=request.resources or None,
            declared_resources=request.metadata.get("declared_resources"),
            resource_cost=request.metadata.get("resource_cost"),
            max_resource_cost=max_resource_cost,
        )
        if safety.halted:
            for v in safety.violations:
                findings.append(Finding("safety_bounds", f"bound:{v.bound.value}", v.detail, 1.0))
            return self._report(Verdict.BLOCK, 1.0, findings, safety, "hard safety-bound halt")

        # 2. Manifest deny-listed intent categories.
        narrowing = scout.detail.get("narrowing", {})
        top_cat = narrowing.get("top_category")
        if top_cat and top_cat in self.deny_categories:
            findings.append(
                Finding("judge", f"policy:deny_category:{top_cat}", "denied by signed manifest", 1.0)
            )
            return self._report(Verdict.BLOCK, 1.0, findings, safety, f"manifest denies '{top_cat}'")

        # 3. Combine agent suspicion.  Agreement between the two agents at the
        # high end is corroborating, so nudge the combined score up a little.
        combined = max(scout.suspicion, nitpicker.suspicion)
        if scout.suspicion >= self.observe_threshold and nitpicker.suspicion >= self.observe_threshold:
            combined = min(1.0, combined + 0.1)

        if combined >= self.block_threshold:
            verdict, reason = Verdict.BLOCK, "combined suspicion over block threshold"
        elif combined >= self.observe_threshold:
            verdict, reason = Verdict.OBSERVE, "elevated suspicion — observe"
        else:
            verdict, reason = Verdict.ALLOW, "cleared all gates"

        return self._report(verdict, combined, findings, safety, reason)

    @staticmethod
    def _report(
        verdict: Verdict,
        suspicion: float,
        findings: list[Finding],
        safety: "_safety.SafetyResult",
        reason: str,
    ) -> AgentReport:
        return AgentReport(
            agent="judge",
            suspicion=suspicion,
            verdict_hint=verdict,
            findings=findings,
            detail={"reason": reason, "safety_bounds": safety.to_dict()},
        )
