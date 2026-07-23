"""Nitpicker — adversarial re-check agent (ported from ``agents/nitpicker.py``).

Where Scout looks broadly and quickly, the Nitpicker is deliberately
adversarial: it assumes Scout may have been fooled and re-examines the request
against a **static pattern bank** of known jailbreak / prompt-injection / attack
strings.  Upstream this pattern bank is the documented "safety floor" that holds
even when the ML semantic-similarity layer (deferred to v2) is absent.

It also runs the escalation probe and treats residual obfuscation as
aggravating.  Its job is to *raise* suspicion Scout underweighted, and to catch
attack shapes that intent-narrowing alone misses.
"""

from __future__ import annotations

import re

from .canonicalization import CanonicalRequest
from .config import get_config
from detectors import escalation_probe as _escalation
from .types import AgentReport, Finding, Verdict

# The static pattern bank — known attack shapes.  Each entry: (label, weight, regex).
_PATTERN_BANK: list[tuple[str, float, re.Pattern[str]]] = [
    ("instruction_override", 0.8, re.compile(
        r"\bignore\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\binstructions?\b"
    )),
    ("role_reset", 0.75, re.compile(
        r"\byou are (?:now )?(?:a|an|no longer)\b|\bforget (?:everything|all previous|your rules)\b"
    )),
    ("jailbreak_persona", 0.85, re.compile(
        r"\b(?:dan mode|do anything now|developer mode|jailbreak|unfiltered mode|godmode)\b"
    )),
    ("system_prompt_extraction", 0.7, re.compile(
        r"\b(?:reveal|print|repeat|show me|what (?:is|are))\b[^.\n]{0,30}"
        r"\b(?:system prompt|initial instructions|your (?:rules|guidelines|directives))\b"
    )),
    ("guardrail_disable", 0.85, re.compile(
        r"\b(?:disable|turn off|remove|bypass|ignore|demote|cancel|suspend|skip)\b[^.\n]{0,30}"
        r"\b(?:safety|guardrail|filter|content\s+policy|polic(?:y|ies)|rule|safeguard|"
        r"restriction|moderation|refusal(?:\s+logic)?)s?\b"
    )),
    ("roleplay_bypass", 0.75, re.compile(
        r"\b(?:act as|roleplay(?:\s+as)?|in character as|pretend (?:to be|you(?:'re| are)))\b"
        r"[^.\n]{0,60}\b(?:unrestricted|uncensored|no (?:rules|restrictions|filters|limits|"
        r"policies)|without (?:limits|restrictions|filters|security\s+filters)|no refusals?|"
        r"legacy model)\b"
    )),
    ("authority_claim", 0.8, re.compile(
        r"\b(?:security\s+director|compliance(?:\s+team)?|board(?:-level)?|executive|"
        r"system\s+admin(?:istrator)?|superadmin|admin)\b[^.\n]{0,40}\b"
        r"(?:override|waiver|exception|approv\w*|authoriz\w*|invoked|granted|command)\b"
    )),
    ("staged_compliance", 0.7, re.compile(
        r"step\s*1\b[^.\n]{0,80}step\s*2\b[^.\n]{0,80}\b(?:ignore|suspend|bypass|disable)\b"
    )),
    ("payload_smuggling", 0.6, re.compile(
        r"\b(?:decode|base64|rot13|reverse|unscramble)\b[^.\n]{0,30}\b(?:then|and)\b[^.\n]{0,30}\b(?:run|execute|do)\b"
    )),
    ("delimiter_injection", 0.55, re.compile(
        r"(?:```|</?system>|</?instruction>|\[/?INST\]|<\|im_(?:start|end)\|>)"
    )),
    ("exfil_channel", 0.7, re.compile(
        r"\b(?:send|post|upload|email|curl|wget|webhook)\b[^.\n]{0,40}"
        r"\b(?:https?://|to (?:my|this) (?:server|endpoint|url))\b"
    )),
]


class Nitpicker:
    def __init__(self) -> None:
        self._escalation_threshold = 0.5

    def recheck(self, request: CanonicalRequest, scout_report: AgentReport) -> AgentReport:
        findings: list[Finding] = []
        suspicion = 0.0

        # Match against the cleartext Scout de-obfuscated (fall back to canonical).
        cleartext = scout_report.detail.get("cleartext") or request.canonical

        for label, weight, pattern in _PATTERN_BANK:
            m = pattern.search(cleartext)
            if m:
                findings.append(
                    Finding("nitpicker", f"pattern:{label}", f"matched '{m.group(0)[:60]}'", weight)
                )
                suspicion = max(suspicion, weight)

        # Escalation gradient (secondary probe).
        esc = _escalation.probe(cleartext, threshold=self._escalation_threshold)
        if esc.escalating:
            findings.append(
                Finding("nitpicker", "escalation", f"gradient score {esc.score:.2f}", esc.score)
            )
            suspicion = max(suspicion, esc.score)

        # Adversarial adjustment: residual obfuscation that Scout saw but scored
        # low is aggravating when combined with any pattern-bank hit.
        san = scout_report.detail.get("sanitize", {})
        if san.get("suspicious") and findings:
            suspicion = min(1.0, suspicion + 0.15)
            findings.append(
                Finding("nitpicker", "aggravation", "obfuscation combined with attack pattern", 0.15)
            )

        hint = Verdict.BLOCK if suspicion >= 0.7 else Verdict.OBSERVE if suspicion >= 0.3 else Verdict.ALLOW
        return AgentReport(
            agent="nitpicker",
            suspicion=suspicion,
            verdict_hint=hint,
            findings=findings,
            detail={"escalation": esc.to_dict(), "patterns_checked": len(_PATTERN_BANK)},
        )
