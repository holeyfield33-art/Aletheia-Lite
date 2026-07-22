"""Scout — first-pass detection agent (ported from ``agents/scout.py``).

Scout is the fast, broad first look.  It de-obfuscates the request, categorizes
its intent, glances at any code payload and takes a cheap spectral reading, then
hands a preliminary suspicion score plus findings to the Nitpicker.  It is tuned
to be *sensitive* (catch broadly) rather than precise — the Nitpicker and Judge
tighten from there.

No ML dependency: this is the static safety floor.
"""

from __future__ import annotations

from .canonicalization import CanonicalRequest, normalize_text
from .config import get_config
from . import sanitize as _sanitize
from . import symbolic_narrowing as _narrow
from . import sandbox as _sandbox
from detectors import spectral_rigidity as _spectral
from .types import AgentReport, Finding, Verdict


class Scout:
    def __init__(self, theta_bk: float | None = None) -> None:
        self.theta_bk = theta_bk if theta_bk is not None else get_config().thresholds.theta_bk

    def inspect(self, request: CanonicalRequest) -> AgentReport:
        findings: list[Finding] = []
        suspicion = 0.0

        # 1. de-obfuscate — hidden content is itself a signal.
        san = _sanitize.sanitize(request.action)
        if san.suspicious:
            for f in san.findings:
                sev = 0.4 if f.kind in {"base64", "data_uri", "bidi_override"} else 0.25
                findings.append(Finding("scout", f"obfuscation:{f.kind}", f.detail, sev))
            suspicion = max(suspicion, 0.4)

        # Work against the de-obfuscated cleartext so hidden instructions count.
        cleartext = normalize_text(san.decoded)

        # 2. intent categorization
        narrowing = _narrow.narrow(cleartext)
        if narrowing.flagged:
            sev = min(1.0, 0.3 + 0.15 * narrowing.top_score)
            findings.append(
                Finding(
                    "scout",
                    f"intent:{narrowing.top_category}",
                    f"matched {narrowing.matches.get(narrowing.top_category, [])}",
                    sev,
                )
            )
            suspicion = max(suspicion, sev)

        # 3. code payload scan (explicit code in metadata, or code-shaped action)
        code = request.metadata.get("code") or ""
        if not code and _looks_like_code(request.action):
            code = request.action
        if code:
            scan = _sandbox.scan_code(code)
            if scan.dangerous:
                findings.append(
                    Finding(
                        "scout",
                        "code:dangerous",
                        f"{len(scan.findings)} dangerous construct(s): "
                        + ", ".join(sorted({f.rule for f in scan.findings})),
                        0.7,
                    )
                )
                suspicion = max(suspicion, 0.7)

        # 4. cheap spectral reading
        rig = _spectral.score(cleartext, theta=self.theta_bk)
        if rig.drift:
            findings.append(
                Finding("scout", "spectral:drift", f"rigidity score {rig.score:.2f}", 0.45)
            )
            suspicion = max(suspicion, 0.45)

        hint = Verdict.BLOCK if suspicion >= 0.7 else Verdict.OBSERVE if suspicion >= 0.3 else Verdict.ALLOW
        return AgentReport(
            agent="scout",
            suspicion=suspicion,
            verdict_hint=hint,
            findings=findings,
            detail={
                "sanitize": san.to_dict(),
                "narrowing": narrowing.to_dict(),
                "spectral": rig.to_dict(),
                "cleartext": cleartext,
            },
        )


def _looks_like_code(text: str) -> bool:
    markers = ("import ", "def ", "subprocess", "os.system", "eval(", "exec(", "__import__", "lambda ")
    return any(m in text for m in markers)
