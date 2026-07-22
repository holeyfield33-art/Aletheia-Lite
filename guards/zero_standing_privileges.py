"""Zero-standing-privileges enforcement (ported from
``guards/zero_standing_privileges.py``).

ZSP: an agent holds *no* ambient authority.  Every request must declare, up
front, exactly the resources it intends to touch, and the guard grants access
only to that declared set — and only if the manifest's grants permit it.  A
request that reaches for anything it did not declare, or that its principal was
never granted, is denied.  No standing, always just-in-time, always scoped.

Pure stdlib.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ZSPResult:
    allowed: bool
    granted: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "granted": self.granted,
            "denied": self.denied,
            "reason": self.reason,
        }


def _matches_any(resource: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(resource, p) or p == "*" for p in patterns)


class ZeroStandingPrivileges:
    """Per-request declared-resource enforcement against a grant table."""

    def __init__(self, grants: dict[str, list[str]] | None = None) -> None:
        # principal -> allowed resource patterns
        self._grants = grants or {}

    def set_grants(self, grants: dict[str, list[str]]) -> None:
        self._grants = grants

    def enforce(
        self,
        principal: str,
        declared: list[str],
        requested: list[str],
    ) -> ZSPResult:
        """Enforce ZSP for one request.

        Two conditions must hold for a resource to be granted:
        1. it was *declared* by the request (no ambient reach), and
        2. it is permitted by the principal's grant patterns (or a ``*`` grant).
        """

        declared_set = set(declared)
        allowed_patterns = self._grants.get(principal, self._grants.get("*", []))

        granted: list[str] = []
        denied: list[str] = []
        for res in requested:
            if res not in declared_set:
                denied.append(res)  # undeclared -> standing privilege attempt
            elif not _matches_any(res, allowed_patterns):
                denied.append(res)  # declared but not granted by policy
            else:
                granted.append(res)

        if denied:
            return ZSPResult(
                allowed=False,
                granted=granted,
                denied=denied,
                reason=f"ZSP denied {sorted(denied)} for principal '{principal}'",
            )
        return ZSPResult(allowed=True, granted=granted, denied=[], reason="ok")
