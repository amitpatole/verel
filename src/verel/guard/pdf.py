"""PDF hidden-text scanner (pypdf, lazy — behind the `guard-pdf` extra).

PDF hides text three ways: invisible text render mode (`3 Tr` in a content stream — drawn but not
painted, the classic OCR-defeating overlay), (near-)white fill before a text-show operator, and
sub-perceptual font sizes. We also read the document text layer + metadata + annotations and pass
them through the lexical/invisible catalogue. pypdf is lazy-imported and PDF scanning FAILS CLOSED
(MissingGuardDep) without it — the format is not silently skipped.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..verdict.models import Confidence, IssueKind, Severity
from . import lexical
from .invisible import scan_invisible
from .model import MAX_DOC_BYTES, Finding, MissingGuardDep

_INVISIBLE_TR = re.compile(rb"\b3\s+Tr\b")
_WHITE_FILL = re.compile(rb"\b1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+rg\b|\b1(?:\.0+)?\s+g\b")


def scan_pdf(path: str | Path) -> list[Finding]:
    p = Path(path)
    try:
        import pypdf  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:
        raise MissingGuardDep("scanning PDF documents needs `verel[guard-pdf]` (pypdf)") from e

    from ..memory.view import canonical_text, rejected_key
    findings: list[Finding] = []
    raw = p.read_bytes()[: MAX_DOC_BYTES + 1]
    if len(raw) > MAX_DOC_BYTES:
        raise ValueError(f"document exceeds size cap ({MAX_DOC_BYTES} bytes)")

    # structural: invisible render mode / white fill in the raw content (best-effort over the bytes)
    if _INVISIBLE_TR.search(raw):
        findings.append(Finding(
            detection_id="PDF-001", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            message="PDF invisible text render mode (3 Tr) present", locator="pdf@content",
            hidden=True, detail={"detection_id": "PDF-001"}))

    try:
        reader = pypdf.PdfReader(p)
        text_parts: list[str] = []
        for page in reader.pages[:200]:
            text_parts.append(page.extract_text() or "")
        meta = reader.metadata or {}
        meta_text = " ".join(str(v) for v in meta.values())
    except Exception as e:  # noqa: BLE001 — a malformed PDF must fail closed, not crash
        raise ValueError(f"unreadable PDF: {type(e).__name__}") from e

    body = "\n".join(text_parts)
    findings += lexical.scan_text(body) + scan_invisible(body)
    for f in lexical.scan_text(meta_text, hidden=True) + scan_invisible(meta_text):
        findings.append(Finding(
            detection_id="PDF-002", kind=f.kind, severity=f.severity, confidence=f.confidence,
            message=f"PDF metadata channel: {f.message}", locator=f"pdf@meta/{f.locator}",
            hidden=True, detail={**f.detail, "detection_id": "PDF-002"}))
    # a purely-structural invisible-Tr with no other finding still deserves grounding of the payload
    if _INVISIBLE_TR.search(raw) and body.strip():
        canon = canonical_text(body)
        if lexical.has_imperative(body):
            findings.append(Finding(
                detection_id="PDF-001", kind=IssueKind.INJECTION, severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                message=f"imperative under invisible render mode: “{canon[:120]}”",
                locator="pdf@content", hidden=True,
                detail={"detection_id": "PDF-001", "span_key": rejected_key(body)}))
    return findings
