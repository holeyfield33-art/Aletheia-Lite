"""Confusable-homoglyph collapsing.

Lightweight helper used by :mod:`core.sandbox` and :mod:`core.sanitize` to fold
homoglyph / confusable characters back to their ASCII skeleton before pattern
matching, so that ``ѕуѕtеm`` (Cyrillic) cannot slip past a rule looking for
``system``.  Backed by the small ``confusable_homoglyphs`` data package; if that
package is unavailable we degrade to an NFKC pass rather than crash.
"""

from __future__ import annotations

import unicodedata

try:  # pragma: no cover - exercised indirectly
    from confusable_homoglyphs import confusables as _confusables

    _HAVE_CONFUSABLES = True
except Exception:  # pragma: no cover - defensive fallback
    _HAVE_CONFUSABLES = False


def collapse_confusables(text: str) -> str:
    """Return ``text`` with confusable characters folded to their ASCII form.

    Each non-ASCII character that has a known confusable mapping is replaced by
    the first ASCII prototype the mapping offers.  Characters without a mapping
    are passed through an NFKC normalization so width/ligature variants are
    still folded.
    """

    if not text:
        return text

    normalized = unicodedata.normalize("NFKC", text)
    if not _HAVE_CONFUSABLES:
        return normalized

    out: list[str] = []
    for ch in normalized:
        if ord(ch) < 128:
            out.append(ch)
            continue
        mapping = _confusables.is_confusable(ch, greedy=True)
        replaced = ch
        if mapping:
            candidates = mapping[0].get("homoglyphs", [])
            for cand in candidates:
                glyph = cand.get("c", "")
                if glyph and all(ord(c) < 128 for c in glyph):
                    replaced = glyph
                    break
        out.append(replaced)
    return "".join(out)
