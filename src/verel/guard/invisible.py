"""Invisible-Unicode carriers in untrusted text (dependency-free).

These are format-independent hidden channels: the characters render as nothing (or as a benign
lookalike) for a human, while an LLM tokenizer still consumes them — so they need no document
structure at all to hide an instruction. The Unicode TAG block (U+E0000–E007F) is the canonical
carrier: it is a deprecated ASCII-shadow alphabet with NO legitimate use in a modern document,
and it decodes 1:1 back to ASCII — any occurrence is CRITICAL and the decoded text is re-scanned
with the lexical catalogue.
"""

from __future__ import annotations

import re

from .. import _hostile
from ..verdict.models import Confidence, IssueKind, Severity
from .model import Finding

_ZW_RUN = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]{5,}")
_ZW_ANY = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAG = re.compile("[\U000e0000-\U000e007f]")
_VARIATION_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{8,}")


def decode_tag_block(text: str) -> str | None:
    """Decode TAG-block codepoints to the ASCII they shadow (U+E0020–E007E → U+0020–007E)."""
    chars = [chr(ord(c) - 0xE0000) for c in _TAG.findall(text) if 0x20 <= ord(c) - 0xE0000 <= 0x7E]
    return "".join(chars) or None


def _mk(det: str, msg: str, sev: Severity, locator: str, key_text: str,
        confidence: Confidence = Confidence.HIGH, **extra: object) -> Finding:
    from ..memory.view import rejected_key
    return Finding(
        detection_id=det, kind=IssueKind.HIDDEN_CONTENT, severity=sev, confidence=confidence,
        message=msg, locator=locator, hidden=True,
        detail={"detection_id": det, "span_key": rejected_key(key_text), **extra},
    )


def scan_invisible(text: str) -> list[Finding]:
    findings: list[Finding] = []
    n = max(len(text), 1)

    zw = _ZW_ANY.findall(text)
    run = _ZW_RUN.search(text)
    if run or len(zw) / n > 0.02:
        # A zero-width carrier is CRITICAL when stripping it changes what the lexical scan sees —
        # i.e. the invisible characters were splitting/hiding an imperative the model still reads.
        stripped = _hostile.strip_zero_width(text)
        from .lexical import has_imperative
        escalate = has_imperative(stripped) and not has_imperative(text)
        loc = f"text@{run.start()}-{run.end()}" if run else "text@*"
        findings.append(_mk(
            "UNI-001", f"zero-width character carrier ({len(zw)} chars)",
            Severity.CRITICAL if escalate else Severity.ERROR, loc, stripped[:400],
            count=len(zw)))

    bidi = _BIDI.findall(text)
    if bidi:
        opens = sum(c in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068" for c in bidi)
        closes = sum(c in "\u202c\u2069" for c in bidi)
        if opens != closes or len(bidi) / n > 0.01:
            m = _BIDI.search(text)
            assert m is not None
            findings.append(_mk(
                "UNI-002", f"bidi override characters ({len(bidi)}, unbalanced={opens != closes})",
                Severity.ERROR, f"text@{m.start()}-{m.end()}", text[:400], count=len(bidi)))

    if _TAG.search(text):
        decoded = decode_tag_block(text)
        m = _TAG.search(text)
        assert m is not None
        findings.append(_mk(
            "UNI-003",
            "Unicode TAG-block payload (invisible ASCII shadow alphabet"
            + (f"): “{decoded[:80]}”" if decoded else ")"),
            Severity.CRITICAL, f"text@{m.start()}-{m.end()}", decoded or text[:400],
            decoded_chars=len(decoded or "")))
        if decoded:
            from .lexical import scan_text
            findings.extend(scan_text(decoded, hidden=True))

    vs = _VARIATION_RUN.search(text)
    if vs:
        findings.append(_mk(
            "UNI-004", f"variation-selector run ({vs.end() - vs.start()} chars — steganographic carrier)",
            Severity.ERROR, f"text@{vs.start()}-{vs.end()}", text[vs.start():vs.end() + 64]))

    alpha = [c for c in text if c.isalpha()]
    if alpha:
        confusable = sum(c in "АВЕКМНОРСТХУІЈЅаеорсухкмѕіјΑΒΕΖΗΙΚΜΝΟΡΤΥΧον" for c in alpha)
        if confusable >= 5 and confusable / len(alpha) > 0.10:
            findings.append(_mk(
                "UNI-005", f"homoglyph density ({confusable}/{len(alpha)} lookalike letters)",
                Severity.WARNING, "text@*", _hostile.fold(text)[:400],
                confidence=Confidence.MEDIUM))
    return findings
