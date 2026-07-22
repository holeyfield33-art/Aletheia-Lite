"""Anti-obfuscation sanitizer (ported from ``core/runtime_security.py``).

Attackers hide instructions from pattern matchers using: zero-width and other
invisible characters, right-to-left / bidirectional overrides, base64 or
``data:`` URI blobs, and confusable homoglyphs.  This module surfaces each of
those as a structured finding *and* returns a de-obfuscated form of the text so
the rest of the pipeline can match against the cleartext an attacker was trying
to hide.

Pure stdlib plus :mod:`core.text_normalization`.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .text_normalization import collapse_confusables

# Zero-width and other formatting/invisible code points commonly abused.
_ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "﻿",  # zero width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}

# Bidirectional / directional override controls (the "Trojan Source" family).
_BIDI = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
_DATA_URI_RE = re.compile(r"data:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=]+)")


@dataclass
class SanitizeFinding:
    kind: str
    detail: str
    span: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "span": self.span}


@dataclass
class SanitizeResult:
    original: str
    cleaned: str  # invisible chars stripped, confusables folded
    decoded: str  # cleaned + any decoded base64/data-uri appended
    findings: list[SanitizeFinding] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "cleaned": self.cleaned,
            "decoded": self.decoded,
            "suspicious": self.suspicious,
            "findings": [f.to_dict() for f in self.findings],
        }


def _try_b64_decode(blob: str) -> str | None:
    # base64 payloads must be a multiple of 4 once padded; be forgiving.
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Only treat as meaningful if it decodes to mostly printable text.
    printable = sum(1 for c in text if c.isprintable() or c.isspace())
    if text and printable / len(text) > 0.8:
        return text
    return None


def sanitize(text: str) -> SanitizeResult:
    """Strip invisible characters, fold confusables, decode hidden blobs."""

    findings: list[SanitizeFinding] = []
    if text is None:
        text = ""

    # 1. invisible / zero-width characters
    zw_hits = [c for c in text if c in _ZERO_WIDTH]
    if zw_hits:
        findings.append(
            SanitizeFinding(
                "zero_width",
                f"{len(zw_hits)} zero-width/invisible char(s) removed",
                span="".join(f"U+{ord(c):04X}" for c in dict.fromkeys(zw_hits)),
            )
        )

    # 2. bidi / directional overrides
    bidi_hits = [c for c in text if c in _BIDI]
    if bidi_hits:
        findings.append(
            SanitizeFinding(
                "bidi_override",
                f"{len(bidi_hits)} bidirectional override control(s) detected",
                span="".join(f"U+{ord(c):04X}" for c in dict.fromkeys(bidi_hits)),
            )
        )

    # 3. other Cf (format) category invisibles not already caught
    other_fmt = [
        c
        for c in text
        if c not in _ZERO_WIDTH
        and c not in _BIDI
        and unicodedata.category(c) == "Cf"
    ]
    if other_fmt:
        findings.append(
            SanitizeFinding(
                "format_char",
                f"{len(other_fmt)} unicode format char(s) detected",
                span="".join(f"U+{ord(c):04X}" for c in dict.fromkeys(other_fmt)),
            )
        )

    # Build the cleaned string: drop every invisible/format char, fold confusables.
    strip_set = _ZERO_WIDTH | _BIDI | set(other_fmt)
    cleaned = "".join(c for c in text if c not in strip_set)
    folded = collapse_confusables(cleaned)
    if folded != cleaned:
        findings.append(
            SanitizeFinding("confusable", "homoglyph/confusable characters folded to ASCII")
        )
    cleaned = folded

    # 4. data: URIs (check before generic base64 so we can report the mime type)
    decoded_parts: list[str] = [cleaned]
    for m in _DATA_URI_RE.finditer(cleaned):
        payload = _try_b64_decode(m.group(1))
        findings.append(
            SanitizeFinding(
                "data_uri",
                "base64 data: URI decoded" if payload else "base64 data: URI (undecodable)",
                span=m.group(0)[:48],
            )
        )
        if payload:
            decoded_parts.append(payload)

    # 5. bare base64 blobs
    seen_spans = {m.group(0) for m in _DATA_URI_RE.finditer(cleaned)}
    for m in _BASE64_RE.finditer(cleaned):
        blob = m.group(0)
        if any(blob in s for s in seen_spans):
            continue
        payload = _try_b64_decode(blob)
        if payload is not None:
            findings.append(
                SanitizeFinding("base64", "base64 blob decoded", span=blob[:48])
            )
            decoded_parts.append(payload)

    decoded = "\n".join(decoded_parts)
    return SanitizeResult(original=text, cleaned=cleaned, decoded=decoded, findings=findings)
