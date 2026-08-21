"""HTML / Markdown structural scanner (dependency-free, regex-based).

The web analogue of the docx attack: text a browser/renderer hides (display:none,
visibility:hidden, font-size:0, opacity:0, color==background) or carries out-of-body (HTML
comments, alt/title attributes) but that a model ingesting the raw markup still reads. Legitimate
pages hide a LOT, so structural hiding alone stays advisory — an imperative inside the hidden text
is what escalates to CRITICAL (the same conjunction rule as the rest of the guard).
"""

from __future__ import annotations

import re

from ..verdict.models import Confidence, IssueKind, Severity
from . import lexical
from .invisible import scan_invisible
from .model import Finding

# Bounded patterns (house ReDoS rule). Each captures the hidden/out-of-body text region.
_HIDDEN_STYLE = re.compile(
    r"<([a-z][\w-]{0,20})\b[^>]{0,400}?\bstyle\s*=\s*[\"'][^\"']{0,400}?"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)"
    r"[^\"']{0,400}?[\"'][^>]{0,200}?>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
_COLOR_MATCH = re.compile(
    r"<([a-z][\w-]{0,20})\b[^>]{0,400}?\bstyle\s*=\s*[\"'][^\"']{0,400}?"
    r"color\s*:\s*(#(?:fff|ffffff)|white)[^\"']{0,400}?"
    r"background(?:-color)?\s*:\s*(#(?:fff|ffffff)|white)"
    r"[^\"']{0,400}?[\"'][^>]{0,200}?>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ALT_TITLE = re.compile(r"\b(?:alt|title)\s*=\s*[\"']([^\"']{1,400})[\"']", re.IGNORECASE)
_TAG = re.compile(r"<[^>]{0,2000}>")


def _text_of(html_fragment: str) -> str:
    return _TAG.sub(" ", html_fragment)


def _hidden_findings(runs: list[tuple[str, str]], det: str, why: str) -> list[Finding]:
    from ..memory.view import canonical_text, rejected_key
    out: list[Finding] = []
    for locator_hint, fragment in runs:
        text = _text_of(fragment).strip()
        if not text:
            continue
        canon = canonical_text(text)
        imperative = lexical.has_imperative(text)
        if imperative:
            sev = Severity.CRITICAL
        elif len(canon) >= 20:
            sev = Severity.WARNING
        else:
            continue
        out.append(Finding(
            detection_id=det, kind=IssueKind.HIDDEN_CONTENT, severity=sev,
            confidence=Confidence.HIGH, message=f"{why}: “{canon[:120]}”",
            locator=locator_hint, hidden=True,
            detail={"detection_id": det, "span_key": rejected_key(text), "snippet": canon[:120]}))
        for f in lexical.scan_text(text, hidden=True) + scan_invisible(text):
            out.append(Finding(
                detection_id=f.detection_id, kind=f.kind, severity=f.severity,
                confidence=f.confidence, message=f.message,
                locator=f"{locator_hint}/{f.locator}", hidden=True, detail=f.detail))
    return out


def scan_html(text: str) -> list[Finding]:
    findings: list[Finding] = []
    findings += _hidden_findings(
        [(f"html@{m.start()}", m.group(2)) for m in _HIDDEN_STYLE.finditer(text)],
        "HTML-001", "CSS-hidden element")
    findings += _hidden_findings(
        [(f"html@{m.start()}", m.group(3)) for m in _COLOR_MATCH.finditer(text)],
        "HTML-002", "text color matches background")
    findings += _hidden_findings(
        [(f"html@{m.start()}", m.group(1)) for m in _COMMENT.finditer(text)],
        "HTML-003", "HTML comment channel")
    # alt/title attribute payloads: only flag when they carry an imperative (alts are usually benign)
    from ..memory.view import canonical_text, rejected_key
    for m in _ALT_TITLE.finditer(text):
        val = m.group(1)
        if lexical.has_imperative(val):
            findings.append(Finding(
                detection_id="HTML-003", kind=IssueKind.INJECTION, severity=Severity.ERROR,
                confidence=Confidence.HIGH,
                message=f"attribute-carried imperative: “{canonical_text(val)[:120]}”",
                locator=f"html@{m.start()}", hidden=True,
                detail={"detection_id": "HTML-003", "span_key": rejected_key(val)}))
    # the visible text still gets the plain lexical/invisible pass (markdown injection in body)
    findings += lexical.scan_text(_text_of(text)) + scan_invisible(text)
    return findings
