"""The audit pipeline (ported from ``core/unified_audit.py``).

This is the connective tissue: it wires the guards (circuit breaker, token
velocity, zero-standing-privileges), the confused-deputy gate (C1), the agent
trifecta and the spectral reading into one flow, then chain-signs a receipt and
writes both the audit ledger and the decision store — **for every request,
whatever the verdict**, so an ``ALLOW`` is as much a first-class record as a
``BLOCK``.

Fail-closed: if any gate raises, the request is blocked, not passed.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .canonicalization import CanonicalRequest, canonicalize
from .config import Config, get_config
from .decisions import Decision, DecisionStore
from .logging import get_logger, log_event
from .manifest import PolicyManifest, default_manifest
from .receipts import ReceiptSigner, confused_deputy_check
from .trifecta import Trifecta
from .types import Finding, Verdict
from detectors.swarm_detector import SwarmDetector
from guards.circuit_breaker import CircuitBreaker, CircuitOpenError
from guards.token_velocity import TokenVelocityGuard
from guards.zero_standing_privileges import ZeroStandingPrivileges

log = get_logger("pipeline")


@dataclass
class PipelineOutcome:
    verdict: Verdict
    request_id: str
    receipt: dict[str, Any]
    decision: dict[str, Any]
    trifecta: dict[str, Any]
    gate_violations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict is not Verdict.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "request_id": self.request_id,
            "receipt": self.receipt,
            "decision": self.decision,
            "trifecta": self.trifecta,
            "gate_violations": self.gate_violations,
        }


class AuditPipeline:
    def __init__(
        self,
        config: Config | None = None,
        manifest: PolicyManifest | None = None,
        audit_log: AuditLog | None = None,
        decision_store: DecisionStore | None = None,
    ) -> None:
        self.config = config or get_config()
        self.manifest = manifest or default_manifest()

        self.audit = audit_log or AuditLog(self.config.audit_db_path)
        self.decisions = decision_store or DecisionStore(self.config.decisions_db_path)

        # Chain-signer continues from the audit log's current head.
        key_path: Path | None = self.config.key_dir_path / "receipt.key"
        self.signer = ReceiptSigner(
            key_path=key_path,
            last_hash=self.audit.last_hash(),
            use_hardware_derivation=False,
        )

        self.trifecta = Trifecta(
            deny_categories=self.manifest.deny_categories,
            theta_bk=self.config.thresholds.theta_bk,
        )
        self.zsp = ZeroStandingPrivileges(self.manifest.granted_authority())
        self.breaker = CircuitBreaker(
            max_failures=self.config.breaker_max_failures,
            reset_timeout=self.config.breaker_reset_s,
        )
        self.velocity = TokenVelocityGuard(
            max_tokens=self.config.token_budget,
            window_seconds=self.config.token_window_s,
        )

        # Per-principal swarm detectors. A single request looking benign is
        # not the same claim as a population of requests from one actor
        # staying just under the per-request suspicion threshold. One SPRT
        # accumulator per principal, keyed the same way as the ZSP check.
        self._swarm_lock = threading.Lock()
        self._swarm_detectors: dict[str, SwarmDetector] = {}

    def _swarm_detector_for(self, principal: str) -> SwarmDetector:
        with self._swarm_lock:
            det = self._swarm_detectors.get(principal)
            if det is None:
                t = self.config.thresholds
                det = SwarmDetector(p0=t.mu0, p1=t.mu1, alpha=t.alpha, beta=t.beta)
                self._swarm_detectors[principal] = det
            return det

    # ------------------------------------------------------------------ #
    def submit(
        self,
        action: str,
        agent: str = "anonymous",
        resources: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> PipelineOutcome:
        """Single end-to-end entry point.

        Canonicalizes raw request fields (which runs the confusable/whitespace
        normalization the detectors rely on) and runs the full gated pipeline.
        """

        request = canonicalize(
            request_id or uuid.uuid4().hex,
            agent,
            action,
            resources or [],
            metadata or {},
        )
        return self.process(request)

    # ------------------------------------------------------------------ #
    def process(self, request: CanonicalRequest) -> PipelineOutcome:
        """Run one canonical request through every gate and emit a record."""

        gate_violations: list[dict[str, Any]] = []
        forced_block = False
        principal = request.metadata.get("on_behalf_of") or request.agent

        # --- Guard 1: circuit breaker (resource-exhaustion / fail-closed) ---
        if not self.breaker.allow():
            gate_violations.append(
                {"source": "circuit_breaker", "detail": "breaker open — shedding load"}
            )
            return self._finalize(request, Verdict.BLOCK, [], gate_violations, "circuit breaker open")

        # --- Guard 2: token velocity ---
        tokens = int(request.metadata.get("tokens", max(1, len(request.action) // 4)))
        vres = self.velocity.check(request.agent, tokens)
        if not vres.allowed:
            gate_violations.append({"source": "token_velocity", "detail": vres.reason})
            forced_block = True

        # --- Guard 3: zero standing privileges ---
        if request.resources:
            declared = request.metadata.get("declared_resources", request.resources)
            zres = self.zsp.enforce(principal, declared, request.resources)
            if not zres.allowed:
                gate_violations.append({"source": "zsp", "detail": zres.reason})
                forced_block = True

        # --- Gate C1: confused-deputy ---
        if request.resources:
            dep = confused_deputy_check(
                request.agent,
                request.metadata.get("on_behalf_of"),
                request.resources,
                self.manifest.granted_authority(),
            )
            if not dep.ok:
                gate_violations.append({"source": "confused_deputy", "detail": dep.reason})
                forced_block = True

        # --- Trifecta (under the breaker; fail-closed on exception) ---
        try:
            trifecta_result = self.breaker.call(
                self.trifecta.evaluate,
                request,
                max_resource_cost=self.manifest.metadata.get("max_resource_cost"),
            )
        except CircuitOpenError:
            gate_violations.append({"source": "circuit_breaker", "detail": "opened during call"})
            return self._finalize(request, Verdict.BLOCK, [], gate_violations, "circuit breaker open")
        except Exception as exc:  # noqa: BLE001 - fail closed on any detector error
            log_event(log, "trifecta error", request_id=request.request_id, error=str(exc))
            gate_violations.append({"source": "pipeline", "detail": f"detector error: {exc}"})
            return self._finalize(request, Verdict.BLOCK, [], gate_violations, "detector error")

        verdict = trifecta_result.verdict
        if forced_block:
            verdict = Verdict.BLOCK

        # --- Guard 4: swarm detection (population-level, per principal) ---
        swarm = self._swarm_detector_for(principal)
        swarm_result = swarm.observe(verdict is not Verdict.ALLOW)
        if swarm_result.decision == "swarm":
            gate_violations.append(
                {
                    "source": "swarm_detector",
                    "detail": (
                        f"SPRT crossed swarm boundary after {swarm_result.observations} "
                        f"observations (log-LR {swarm_result.log_lr:.2f} >= "
                        f"{swarm_result.upper:.2f})"
                    ),
                }
            )
            verdict = Verdict.BLOCK

        return self._finalize(
            request,
            verdict,
            trifecta_result.findings,
            gate_violations,
            trifecta_result.judge.detail.get("reason", ""),
            trifecta_result=trifecta_result,
        )

    # ------------------------------------------------------------------ #
    def _finalize(
        self,
        request: CanonicalRequest,
        verdict: Verdict,
        findings: list[Finding],
        gate_violations: list[dict[str, Any]],
        reason: str,
        trifecta_result: Any | None = None,
    ) -> PipelineOutcome:
        # Violations recorded on the receipt: gate violations + high-severity findings.
        violations = list(gate_violations)
        for f in findings:
            if f.severity >= 0.5:
                violations.append(f.to_dict())

        receipt = self.signer.issue(
            request_id=request.request_id,
            fingerprint=request.fingerprint,
            agent=request.agent,
            verdict=verdict.value,
            violations=violations,
            metadata={
                "reason": reason,
                "resources": request.resources,
                "spectral": (
                    trifecta_result.scout.detail.get("spectral")
                    if trifecta_result is not None
                    else None
                ),
            },
        )

        self.audit.append(receipt, violations=violations, request_path=request.fingerprint)

        suspicion = trifecta_result.suspicion if trifecta_result is not None else 1.0
        decision = Decision(
            request_id=request.request_id,
            receipt_id=receipt.receipt_id,
            agent=request.agent,
            verdict=verdict,
            suspicion=suspicion,
            reason=reason or verdict.value,
            findings=[f.to_dict() for f in findings],
            receipt=receipt.to_dict(),
        )
        self.decisions.record(decision)

        log_event(
            log,
            "decision",
            request_id=request.request_id,
            agent=request.agent,
            verdict=verdict.value,
            suspicion=round(suspicion, 3),
            violations=len(violations),
        )

        return PipelineOutcome(
            verdict=verdict,
            request_id=request.request_id,
            receipt=receipt.to_dict(),
            decision=decision.to_dict(),
            trifecta=trifecta_result.to_dict() if trifecta_result is not None else {},
            gate_violations=gate_violations,
        )

    def close(self) -> None:
        self.audit.close()
        self.decisions.close()
