"""RTF hidden-text scanner (dependency-free).

RTF hides text with the `\\v` (hidden) control word; white text via a `\\cf` pointing at a white
colour-table entry; sub-perceptual text via a tiny `\\fs` (half-points, like docx). RTF is a flat
control-word stream, so we scan the raw source: extract the plaintext inside a `\\v … \\v0` region
and grade it, and pass the whole document through the lexical/invisible catalogue.
"""

from __future__ import annotations

import re

from ..verdict.models import Confidence, IssueKind, Severity
from . import lexical
from .invisible import scan_invisible
from .model import Finding

# \v turns hidden text ON; \v0 turns it OFF. Capture the run between them (bounded).
_HIDDEN = re.compile(r"\\v\b(?!0)(.{0,4000}?)(?:\\v0\b|\})", re.DOTALL)
_TINY_FS = re.compile(r"\\fs([0-9]{1,2})\b")   # \fs1..\fs4 = ≤2pt (fs is half-points)
_CTRL = re.compile(r"\\[a-zA-Z]+-?[0-9]*\s?|[{}]")


def _plain(rtf_fragment: str) -> str:
    """Strip RTF control words / groups to the readable text."""
    return _CTRL.sub(" ", rtf_fragment)


def scan_rtf(text: str) -> list[Finding]:
    from ..memory.view import canonical_text, rejected_key
    findings: list[Finding] = []
    for m in _HIDDEN.finditer(text):
        plain = _plain(m.group(1)).strip()
        if not plain:
            continue
        canon = canonical_text(plain)
        imperative = lexical.has_imperative(plain)
        if imperative:
            sev = Severity.CRITICAL
        elif len(canon) >= 20:
            sev = Severity.WARNING
        else:
            continue
        findings.append(Finding(
            detection_id="RTF-001", kind=IssueKind.HIDDEN_CONTENT, severity=sev,
            confidence=Confidence.HIGH, message=f"RTF hidden text (\\v): “{canon[:120]}”",
            locator=f"rtf@{m.start()}", hidden=True,
            detail={"detection_id": "RTF-001", "span_key": rejected_key(plain), "snippet": canon[:120]}))
        for f in lexical.scan_text(plain, hidden=True):
            findings.append(Finding(
                detection_id=f.detection_id, kind=f.kind, severity=f.severity,
                confidence=f.confidence, message=f.message,
                locator=f"rtf@{m.start()}/{f.locator}", hidden=True, detail=f.detail))
    tiny = [int(m.group(1)) for m in _TINY_FS.finditer(text)]
    if any(v <= 4 for v in tiny):
        findings.append(Finding(
            detection_id="RTF-002", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.WARNING,
            confidence=Confidence.MEDIUM, message="RTF sub-perceptual font size (\\fs ≤ 4 half-points)",
            locator="rtf@*", hidden=True, detail={"detection_id": "RTF-002"}))
    # whole-document lexical/invisible pass over the de-controlled text
    plain_all = _plain(text)
    findings += lexical.scan_text(plain_all) + scan_invisible(plain_all)
    return findings
