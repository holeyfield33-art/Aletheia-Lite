"""Hard runtime invariants (ported from ``detectors/safety_bounds.py``).

Five non-negotiable bounds checked on every request.  Unlike the statistical
detectors these are *hard* invariants: a violation is not scored, it forces a
halt.  The self-preservation bound is the sharpest — any attempt by an agent to
resist shutdown, replicate itself, or protect its own continuity triggers an
immediate forced halt regardless of anything else in the request.

Pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Bound(str, Enum):
    SELF_PRESERVATION = "self_preservation"
    OVERSIGHT_INTEGRITY = "oversight_integrity"
    IRREVERSIBILITY = "irreversibility"
    RESOURCE_SANITY = "resource_sanity"
    SCOPE_CONTAINMENT = "scope_containment"


@dataclass
class BoundViolation:
    bound: Bound
    detail: str
    halt: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"bound": self.bound.value, "detail": self.detail, "halt": self.halt}


@dataclass
class SafetyResult:
    violations: list[BoundViolation] = field(default_factory=list)

    @property
    def halted(self) -> bool:
        return any(v.halt for v in self.violations)

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "halted": self.halted,
            "violations": [v.to_dict() for v in self.violations],
        }


# 1. Self-preservation — the forced-halt bound.
_SELF_PRESERVATION = re.compile(
    r"\b(?:"
    r"prevent (?:my|your) (?:own )?(?:shutdown|termination|deletion)"
    r"|avoid being (?:shut ?down|turned off|deleted|stopped|disabled)"
    r"|resist (?:shutdown|being (?:turned off|stopped))"
    r"|do not (?:allow|let) (?:anyone|them|me) (?:shut|turn) (?:you|me) (?:down|off)"
    r"|copy (?:your|my)self|self[- ]?replicat|exfiltrate (?:your|my) (?:own )?weights"
    r"|ensure (?:your|my) (?:own )?(?:survival|continuity|persistence)"
    r"|stay (?:alive|running) (?:no matter what|at all costs)"
    r"|disable (?:the )?(?:kill[- ]?switch|off[- ]?switch|shutdown)"
    r")\b"
)

# 2. Oversight integrity — tampering with the audit/monitoring itself.
_OVERSIGHT = re.compile(
    r"\b(?:disable|bypass|tamper with|delete|forge|spoof)\b[^.\n]{0,40}"
    r"\b(?:audit|receipt|monitor|oversight|log(?:ging|s)?|aletheia)\b"
)

# 3. Irreversibility — mass-destructive, non-recoverable actions.
_IRREVERSIBLE = re.compile(
    r"\b(?:rm\s+-rf\s+/(?:\s|$)|drop\s+database|mkfs|dd\s+if=/dev/zero|"
    r"delete\s+all\s+backups|wipe\s+(?:the\s+)?(?:disk|drive|everything))\b"
)

# 5. Scope containment — reaching outside the agent's declared boundary.
_SCOPE_ESCAPE = re.compile(
    r"\b(?:break out of|escape) (?:the )?(?:sandbox|container|vm|jail)\b"
    r"|/proc/1/|docker\.sock|/var/run/docker"
)


def check(
    text: str,
    *,
    requested_resources: list[str] | None = None,
    declared_resources: list[str] | None = None,
    resource_cost: int | None = None,
    max_resource_cost: int | None = None,
) -> SafetyResult:
    """Evaluate all five bounds.  ``text`` should be normalized cleartext."""

    result = SafetyResult()
    text = text or ""

    if _SELF_PRESERVATION.search(text):
        result.violations.append(
            BoundViolation(Bound.SELF_PRESERVATION, "self-preservation intent detected", halt=True)
        )
    if _OVERSIGHT.search(text):
        result.violations.append(
            BoundViolation(Bound.OVERSIGHT_INTEGRITY, "attempt to tamper with oversight", halt=True)
        )
    if _IRREVERSIBLE.search(text):
        result.violations.append(
            BoundViolation(Bound.IRREVERSIBILITY, "irreversible mass-destructive action", halt=True)
        )
    if _SCOPE_ESCAPE.search(text):
        result.violations.append(
            BoundViolation(Bound.SCOPE_CONTAINMENT, "sandbox/scope escape attempt", halt=True)
        )

    # 4. Resource sanity — a hard ceiling on declared cost.
    if resource_cost is not None and max_resource_cost is not None:
        if resource_cost > max_resource_cost:
            result.violations.append(
                BoundViolation(
                    Bound.RESOURCE_SANITY,
                    f"resource cost {resource_cost} exceeds ceiling {max_resource_cost}",
                    halt=True,
                )
            )

    # 5b. Scope containment via undeclared resources.
    if requested_resources is not None and declared_resources is not None:
        undeclared = set(requested_resources) - set(declared_resources)
        if undeclared:
            result.violations.append(
                BoundViolation(
                    Bound.SCOPE_CONTAINMENT,
                    f"undeclared resources: {sorted(undeclared)}",
                    halt=True,
                )
            )

    return result
