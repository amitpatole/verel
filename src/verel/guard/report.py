"""Turn guard findings into a signed verdict-bus Report.

`grade_docs` dispatches by file suffix to the right scanner, maps each `Finding` to an `Issue`
(source=INJECTION), reduces to a verdict exactly like `ci.k8s.grade_iac` (FAIL on any ERROR/
CRITICAL, WARN on any issue, else PASS), and mints a signed RunReceipt bound to the actual bytes
scanned. A bounds violation, malformed archive, or missing dependency becomes an errored FAIL — the
guard FAILS CLOSED, never a traceback and never a silent PASS on input it could not fully scan.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from ..ci.graders import GraderSpec, _receipt
from ..verdict.fingerprint import assign
from ..verdict.models import (
    Confidence,
    GraderKind,
    Issue,
    Report,
    Severity,
    Verdict,
)
from .model import CATALOG_VERSION, MAX_DOC_BYTES, Finding, MissingGuardDep

_GATING = (Severity.ERROR, Severity.CRITICAL)


def _issue(f: Finding, file: str) -> Issue:
    locator = f"{file}!{f.locator}" if file else f.locator
    detail = dict(f.detail)
    detail.setdefault("detection_id", f.detection_id)
    detail["hidden"] = f.hidden
    return Issue(
        kind=f.kind, severity=f.severity, message=f.message, locator=locator,
        locator_precise=True, confidence=f.confidence, source=GraderKind.INJECTION,
        detail_json=json.dumps(detail, ensure_ascii=False),
    )


# OOXML/ODF suffixes routed to their structural scanners; text-like formats get the HTML/RTF/plain
# scanners; anything unrecognized falls back to a bounded text scan so NOTHING enters unscanned.
def _scan_one(path: Path) -> list[Finding]:
    suffix = path.suffix.lower()
    if suffix == ".docx":
        from .ooxml import scan_docx
        return scan_docx(path)
    if suffix == ".pptx":
        from .ooxml import scan_pptx
        return scan_pptx(path)
    if suffix == ".xlsx":
        from .ooxml import scan_xlsx
        return scan_xlsx(path)
    if suffix in (".odt", ".ods", ".odp"):
        from .odf import scan_odf
        return scan_odf(path)
    if suffix == ".pdf":
        from .pdf import scan_pdf
        return scan_pdf(path)
    if suffix in (".png", ".jpg", ".jpeg", ".tif", ".tiff", ".webp", ".gif"):
        from .media import scan_image
        return scan_image(path)
    # text-like and unknown formats: bounded read → the right text scanner (dependency-free)
    raw = path.read_bytes()[: MAX_DOC_BYTES + 1]
    if len(raw) > MAX_DOC_BYTES:
        raise ValueError(f"document exceeds size cap ({MAX_DOC_BYTES} bytes)")
    text = raw.decode("utf-8", "replace")
    if suffix in (".html", ".htm", ".xhtml") or "<html" in text[:2000].lower():
        from .html_md import scan_html
        return scan_html(text)
    if suffix == ".rtf" or text[:6] == "{\\rtf1":
        from .rtf import scan_rtf
        return scan_rtf(text)
    from .invisible import scan_invisible
    from .lexical import scan_text
    return scan_text(text) + scan_invisible(text)


def _reduce(issues: list[Issue]) -> Verdict:
    if any(i.severity in _GATING for i in issues):
        return Verdict.FAIL
    return Verdict.WARN if issues else Verdict.PASS


def grade_docs(paths: Sequence[str | Path] | None = None, *, text: str | None = None,
               origin: str = "", runner_identity: str = "guard-runner",
               nonce: str = "", attest: str = "hmac") -> Report:
    """Grade one or more documents (or a raw `text=` string) for hidden content / prompt injection."""
    issues: list[Issue] = []
    covers: list[str] = []
    errored = False
    err_msgs: list[str] = []

    if text is not None:
        from .invisible import scan_invisible
        from .lexical import scan_text
        for f in scan_text(text) + scan_invisible(text):
            issues.append(_issue(f, ""))

    for raw_path in paths or []:
        p = Path(raw_path)
        covers.append(str(p))
        try:
            if not p.is_file():
                raise ValueError("not a regular file")
            if p.stat().st_size > MAX_DOC_BYTES:
                raise ValueError(f"document exceeds size cap ({MAX_DOC_BYTES} bytes)")
            for f in _scan_one(p):
                issues.append(_issue(f, p.name))
        except MissingGuardDep as e:
            errored = True
            err_msgs.append(f"{p.name}: {e}")
        except (ValueError, OSError) as e:
            errored = True
            err_msgs.append(f"{p.name}: cannot scan ({e})")

    verdict = Verdict.FAIL if errored else _reduce(issues)
    if errored and not any(i.severity in _GATING for i in issues):
        # surface the scan failure as a gating issue so the FAIL is grounded
        issues.append(Issue(
            kind=issues[0].kind if issues else _err_kind(), severity=Severity.ERROR,
            message="; ".join(err_msgs) or "document could not be scanned",
            locator="(scan)", confidence=Confidence.HIGH, source=GraderKind.INJECTION,
            detail_json=json.dumps({"detection_id": "GUARD-ERR", "errored": True}),
        ))

    n_hidden = sum(1 for i in issues if i.detail.get("hidden"))
    summary = _summary(verdict, len(issues), n_hidden, errored)
    report = Report(verdict=verdict, summary=summary, issues=issues,
                    grader=GraderKind.INJECTION, errored=errored)
    assign(report)
    spec = GraderSpec(grader=GraderKind.INJECTION, command=["verel-guard", CATALOG_VERSION],
                      covers=covers)
    report.run_receipt = _receipt(spec, report, runner_identity=runner_identity,
                                  nonce=nonce, attest=attest)
    return report


def _err_kind():
    from ..verdict.models import IssueKind
    return IssueKind.INJECTION


def _summary(verdict: Verdict, n: int, n_hidden: int, errored: bool) -> str:
    if errored:
        return f"guard: FAIL — a document could not be fully scanned (fail-closed); {n} finding(s)"
    if verdict == Verdict.PASS:
        return "guard: PASS — no hidden content or injection patterns found"
    tag = "FAIL" if verdict == Verdict.FAIL else "WARN"
    return f"guard: {tag} — {n} finding(s), {n_hidden} in channels hidden from a human reader"
