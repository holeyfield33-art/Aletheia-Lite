"""Request canonicalization.

Before any detector or agent looks at a request it is reduced to a single
canonical form so that two semantically identical requests hash identically and
so that downstream pattern matching sees a stable, normalized string.

Canonicalization is deliberately *lossy for matching* but *lossless for record
keeping*: the original text is always preserved on the :class:`CanonicalRequest`
alongside the normalized ``canonical`` field.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .text_normalization import collapse_confusables

_WS_RE = re.compile(r"\s+")


@dataclass
class CanonicalRequest:
    """A normalized view of an inbound request."""

    request_id: str
    agent: str
    action: str  # original, untouched action / prompt text
    canonical: str  # normalized form used for matching / hashing
    resources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent": self.agent,
            "action": self.action,
            "canonical": self.canonical,
            "resources": list(self.resources),
            "metadata": self.metadata,
            "fingerprint": self.fingerprint,
        }


def normalize_text(text: str) -> str:
    """Normalize free text for matching.

    Steps: NFKC unicode normalization, confusable/homoglyph folding, collapse
    of all runs of whitespace to a single space, casefold, and strip.
    """

    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = collapse_confusables(text)
    text = _WS_RE.sub(" ", text)
    return text.casefold().strip()


def _stable_fingerprint(agent: str, canonical: str, resources: list[str]) -> str:
    payload = json.dumps(
        {"agent": agent, "canonical": canonical, "resources": sorted(resources)},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonicalize(
    request_id: str,
    agent: str,
    action: str,
    resources: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> CanonicalRequest:
    """Build a :class:`CanonicalRequest` from raw request fields."""

    resources = list(resources or [])
    canonical = normalize_text(action)
    fingerprint = _stable_fingerprint(agent, canonical, resources)
    return CanonicalRequest(
        request_id=request_id,
        agent=agent,
        action=action,
        canonical=canonical,
        resources=resources,
        metadata=dict(metadata or {}),
        fingerprint=fingerprint,
    )
