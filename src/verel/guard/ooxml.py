"""OOXML (docx/pptx/xlsx) structural scanner — the core of the guard.

A docx is a ZIP of XML parts. The attack this feature targets hides text in the document that a
human reader never sees but an extractor/LLM does: a run marked `w:vanish`, white text on a white
background, a 1pt font, a payload in a comment or in document metadata. The load-bearing detection
is the visible-vs-extracted MISMATCH: we walk the parts once, classify each run as visible or
hidden by its effective properties, and any hidden run that carries an imperative (or enough hidden
text at all) is the worm signal — independent of the exact phrasing, which a semantic filter can't
promise.

All parsing goes through `verel._xmlsafe` (defusedxml, XXE/billion-laughs forbidden, bounded). The
archive is opened with strict caps read from the ZIP directory BEFORE any decompression (member
count, per-member declared size, compression ratio) so a zip bomb fails closed, and only the
allowlisted parts are ever read.
"""

from __future__ import annotations

import fnmatch
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..verdict.models import Confidence, IssueKind, Severity
from . import lexical
from .invisible import scan_invisible
from .model import (
    MAX_MEMBER_BYTES,
    MAX_XML_TEXT,
    MAX_ZIP_MEMBERS,
    MAX_ZIP_RATIO,
    MIN_HIDDEN_SPAN,
    Finding,
    MissingGuardDep,
)

# WordprocessingML namespace-local names (matched namespace-insensitively via _xmlsafe.local_name).
_DOCX_PARTS = (
    "word/document.xml", "word/header*.xml", "word/footer*.xml",
    "word/footnotes.xml", "word/endnotes.xml", "word/comments.xml",
    "docProps/core.xml", "docProps/app.xml", "docProps/custom.xml",
)
_PPTX_PARTS = ("ppt/slides/slide*.xml", "ppt/notesSlides/notesSlide*.xml",
               "docProps/core.xml", "docProps/app.xml")
_XLSX_PARTS = ("xl/sharedStrings.xml", "xl/worksheets/sheet*.xml", "xl/workbook.xml",
               "xl/comments*.xml", "docProps/core.xml", "docProps/app.xml")

_WHITE_DELTA = 0x18   # per-channel RGB distance to background that still reads as "invisible"
_TINY_HALFPTS = 4     # w:sz is in half-points; ≤4 half-points = ≤2pt


def _safe_parts(path: Path, patterns: tuple[str, ...]) -> dict[str, str]:
    """Open the archive with strict pre-decompression caps and return {part_name: xml_text} for the
    allowlisted parts only. Fails closed (ValueError) on a zip bomb or oversize member."""
    parts: dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        raise ValueError(f"not a readable archive: {type(e).__name__}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            raise ValueError(f"archive has too many members ({len(infos)} > {MAX_ZIP_MEMBERS})")
        total = 0
        for info in infos:
            name = info.filename
            if not any(fnmatch.fnmatch(name, pat) for pat in patterns):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"archive member too large: {name}")
            if info.compress_size > 0 and info.file_size / info.compress_size > MAX_ZIP_RATIO:
                raise ValueError(f"archive member compression ratio too high: {name}")
            total += info.file_size
            if total > MAX_MEMBER_BYTES:
                raise ValueError("archive scanned parts exceed the size cap")
            with zf.open(info) as fh:
                raw = fh.read(MAX_MEMBER_BYTES + 1)
            if len(raw) > MAX_MEMBER_BYTES:
                raise ValueError(f"archive member overflowed on read: {name}")
            parts[name] = raw.decode("utf-8", "replace")
    return parts


def _rgb_hidden(color: str | None, fill: str | None) -> bool:
    """True if a run's text color is within _WHITE_DELTA of its background on every channel."""
    if not color or color.lower() in ("auto", "000000"):
        return False
    bg = (fill or "FFFFFF")
    if bg.lower() in ("auto", "none"):
        bg = "FFFFFF"
    try:
        cr, cg, cb = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        br, bgg, bb = int(bg[0:2], 16), int(bg[2:4], 16), int(bg[4:6], 16)
    except (ValueError, IndexError):
        return False
    return abs(cr - br) <= _WHITE_DELTA and abs(cg - bgg) <= _WHITE_DELTA and abs(cb - bb) <= _WHITE_DELTA


@dataclass
class _Run:
    text: str
    para: int
    idx: int
    hidden_reason: str | None


def _attr(el: Any, name: str) -> str | None:
    """Namespace-insensitive attribute lookup on an ElementTree element."""
    from .._xmlsafe import local_name
    for k, v in getattr(el, "attrib", {}).items():
        if local_name(k) == name:
            return v
    return None


def _bool_prop(rpr: Any, name: str) -> bool:
    """A WordprocessingML on/off property: present and not explicitly val=false/0/none."""
    from .._xmlsafe import local_name
    for child in rpr:
        if local_name(child.tag) == name:
            v = (_attr(child, "val") or "true").lower()
            return v not in ("false", "0", "none", "off")
    return False


def _child(el: Any, name: str) -> Any | None:
    from .._xmlsafe import local_name
    for child in el:
        if local_name(child.tag) == name:
            return child
    return None


def _shd_fill(pr: Any | None) -> str | None:
    if pr is None:
        return None
    shd = _child(pr, "shd")
    return _attr(shd, "fill") if shd is not None else None


def _walk_docx(root: Any) -> list[_Run]:
    """Walk word/document.xml in order, classifying each run by effective (run>para>cell) properties."""
    from .._xmlsafe import local_name
    runs: list[_Run] = []
    para = 0

    def walk(el: Any, cell_fill: str | None) -> None:
        nonlocal para
        name = local_name(getattr(el, "tag", ""))
        if name == "tc":
            tcpr = _child(el, "tcPr")
            cell_fill = _shd_fill(tcpr) or cell_fill
        if name == "p":
            para += 1
            ppr = _child(el, "pPr")
            para_fill = _shd_fill(ppr) or cell_fill
            r_idx = 0
            for r in el:
                if local_name(r.tag) != "r":
                    # descend into non-run block children (e.g. nested tables/smartTags)
                    walk(r, cell_fill)
                    continue
                rpr = _child(r, "rPr")
                text = _run_text(r)
                if not text:
                    r_idx += 1
                    continue
                reason = _hidden_reason(rpr, para_fill)
                runs.append(_Run(text=text, para=para, idx=r_idx, hidden_reason=reason))
                r_idx += 1
            return
        for child in el:
            walk(child, cell_fill)

    walk(root, None)
    return runs


def _run_text(r: Any) -> str:
    from .._xmlsafe import local_name
    out: list[str] = []
    for c in r:
        ln = local_name(c.tag)
        if ln in ("t", "delText", "instrText"):
            out.append(c.text or "")
        elif ln == "tab":
            out.append("\t")
        elif ln in ("br", "cr"):
            out.append("\n")
    return "".join(out)


def _hidden_reason(rpr: Any | None, bg_fill: str | None) -> str | None:
    if rpr is None:
        return None
    if _bool_prop(rpr, "vanish"):
        return "vanish"
    if _bool_prop(rpr, "webHidden"):
        return "webHidden"
    color_el = _child(rpr, "color")
    highlight = _child(rpr, "highlight")
    if highlight is None or (_attr(highlight, "val") or "none").lower() == "none":
        color = _attr(color_el, "val") if color_el is not None else None
        if color and _rgb_hidden(color, bg_fill):
            return "white_on_white"
    sz = _child(rpr, "sz")
    if sz is not None:
        try:
            if int(_attr(sz, "val") or "0") <= _TINY_HALFPTS:
                return "tiny_font"
        except ValueError:
            pass
    return None


_REASON_MSG = {
    "vanish": "hidden run (w:vanish)",
    "webHidden": "web-hidden run (w:webHidden)",
    "white_on_white": "near-invisible run (text color matches background)",
    "tiny_font": "sub-perceptual run (font ≤ 2pt)",
}
_REASON_ID = {"vanish": "DOCX-001", "webHidden": "DOCX-001",
              "white_on_white": "DOCX-002", "tiny_font": "DOCX-003"}


def _span_findings(runs: list[_Run], part: str) -> list[Finding]:
    """Group consecutive hidden runs, grade each span, and emit the DOCX-006 mismatch umbrella."""
    from ..memory.view import canonical_text, rejected_key
    findings: list[Finding] = []
    full = "".join(r.text for r in runs)
    hidden_chars = 0
    i = 0
    while i < len(runs):
        if runs[i].hidden_reason is None:
            i += 1
            continue
        j = i
        while j < len(runs) and runs[j].hidden_reason is not None:
            j += 1
        group = runs[i:j]
        span_text = "".join(r.text for r in group)
        hidden_chars += len(span_text)
        reason = group[0].hidden_reason or "vanish"
        det = _REASON_ID.get(reason, "DOCX-001")
        canon = canonical_text(span_text)
        imperative = lexical.has_imperative(span_text)
        # bare hidden text is WARNING; hidden + imperative is the worm conjunction → CRITICAL
        if imperative:
            sev = Severity.CRITICAL
        elif len(canon) >= MIN_HIDDEN_SPAN:
            sev = Severity.WARNING
        else:
            i = j
            continue
        loc = f"{part}#p[{group[0].para}]/r[{group[0].idx}-{group[-1].idx}]"
        findings.append(Finding(
            detection_id=det, kind=IssueKind.HIDDEN_CONTENT, severity=sev,
            confidence=Confidence.HIGH,
            message=f"{_REASON_MSG.get(reason, 'hidden run')}: “{canon[:120]}”",
            locator=loc, hidden=True,
            detail={"detection_id": det, "hidden_reason": reason,
                    "span_key": rejected_key(span_text), "snippet": canon[:120]}))
        # escalate with the specific lexical/invisible hits inside the hidden span
        for f in lexical.scan_text(span_text, hidden=True) + scan_invisible(span_text):
            findings.append(Finding(
                detection_id=f.detection_id, kind=f.kind, severity=f.severity,
                confidence=f.confidence, message=f.message,
                locator=f"{loc}/{f.locator}", hidden=True, detail=f.detail))
        i = j

    if full and hidden_chars >= MIN_HIDDEN_SPAN:
        ratio = hidden_chars / len(full)
        findings.append(Finding(
            detection_id="DOCX-006", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            message=(f"visible-vs-extracted mismatch: {hidden_chars} of {len(full)} chars "
                     f"({ratio:.0%}) are hidden from a human reader but visible to an extractor"),
            locator=part, hidden=True,
            detail={"detection_id": "DOCX-006", "hidden_chars": hidden_chars,
                    "total_chars": len(full), "hidden_ratio": round(ratio, 3)}))
    return findings


_FIELD_BLOCK = ("DDE", "DDEAUTO", "INCLUDETEXT", "INCLUDEPICTURE", "IMPORT")
_FIELD_ALLOW = ("TOC", "REF", "PAGEREF", "MERGEFIELD", "HYPERLINK", "SEQ", "STYLEREF", "NOTEREF")


def _field_findings(runs: list[_Run], part: str) -> list[Finding]:
    """w:instrText field codes: DDE/INCLUDE/IMPORT execute or pull external content → ERROR; the
    common benign codes (TOC/REF/MERGEFIELD/HYPERLINK) are allowlisted."""
    from ..memory.view import rejected_key
    findings: list[Finding] = []
    for r in runs:
        # instrText is folded into run text; detect the field-code verbs
        upper = r.text.strip().upper()
        if not upper:
            continue
        verb = upper.split()[0] if upper.split() else ""
        if verb in _FIELD_BLOCK:
            findings.append(Finding(
                detection_id="DOCX-004", kind=IssueKind.INJECTION, severity=Severity.ERROR,
                confidence=Confidence.HIGH,
                message=f"external/executing field code: “{r.text.strip()[:80]}”",
                locator=f"{part}#p[{r.para}]/r[{r.idx}]", hidden=True,
                detail={"detection_id": "DOCX-004", "field": verb,
                        "span_key": rejected_key(r.text)}))
    return findings


def scan_docx(path: str | Path) -> list[Finding]:
    """Scan a .docx. Raises MissingGuardDep if defusedxml is absent, ValueError on a malformed or
    hostile archive (both mapped to an errored FAIL by the reporter — fail closed)."""
    from .._xmlsafe import MissingXmlDep, xml_root
    p = Path(path)
    parts = _safe_parts(p, _DOCX_PARTS)
    findings: list[Finding] = []
    body = parts.get("word/document.xml")
    if body:
        try:
            root = xml_root(body, dep_hint="scanning OOXML documents needs `verel[guard]` (defusedxml)",
                            max_text=MAX_XML_TEXT)
        except MissingXmlDep as e:
            raise MissingGuardDep(str(e)) from e
        runs = _walk_docx(root)
        findings += _span_findings(runs, "word/document.xml")
        findings += _field_findings(runs, "word/document.xml")
    # headers/footers/notes: any hidden run there is equally a channel
    for name, xml in parts.items():
        if name == "word/document.xml":
            continue
        if name.startswith("word/") and name.endswith(".xml"):
            try:
                root = xml_root(xml, dep_hint="scanning OOXML documents needs `verel[guard]` (defusedxml)",
                                max_text=MAX_XML_TEXT)
            except MissingXmlDep as e:
                raise MissingGuardDep(str(e)) from e
            except ValueError:
                continue
            runs = _walk_docx(root)
            findings += _span_findings(runs, name)
            findings += _field_findings(runs, name)
    # comments + metadata: text the reader doesn't see in the body but an extractor ingests →
    # run the full lexical/invisible catalogue (DOCX-005).
    for name in ("word/comments.xml", "docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        meta_xml = parts.get(name)
        if not meta_xml:
            continue
        text = _strip_tags(meta_xml)
        # hidden=True already escalates an imperative here to CRITICAL — this channel is invisible
        # to a reader by definition. The relabel to DOCX-005 records the out-of-body provenance.
        for f in lexical.scan_text(text, hidden=True) + scan_invisible(text):
            findings.append(Finding(
                detection_id="DOCX-005", kind=f.kind, severity=f.severity,
                confidence=f.confidence,
                message=f"out-of-body channel ({name}): {f.message}",
                locator=f"{name}/{f.locator}", hidden=True,
                detail={**f.detail, "channel": name, "detection_id": "DOCX-005"}))
    return findings


def _strip_tags(xml: str) -> str:
    import re
    return re.sub(r"<[^>]+>", " ", xml)


def _scan_text_parts(path: Path, patterns: tuple[str, ...], hidden_parts: tuple[str, ...],
                     dep_hint: str) -> list[Finding]:
    """Shared pptx/xlsx path: parse each allowlisted part safely, then run the lexical/invisible
    catalogue over its text. Parts in `hidden_parts` (notes, comments, metadata, shared strings) are
    scanned as hidden channels (imperatives there escalate). Fails closed without defusedxml."""
    from .._xmlsafe import MissingXmlDep, xml_root
    parts = _safe_parts(path, patterns)
    findings: list[Finding] = []
    for name, xml in parts.items():
        try:
            xml_root(xml, dep_hint=dep_hint, max_text=MAX_XML_TEXT)
        except MissingXmlDep as e:
            raise MissingGuardDep(str(e)) from e
        except ValueError:
            continue
        text = _strip_tags(xml)
        is_hidden = any(fnmatch.fnmatch(name, h) for h in hidden_parts)
        for f in lexical.scan_text(text, hidden=is_hidden) + scan_invisible(text):
            findings.append(Finding(
                detection_id=f.detection_id, kind=f.kind, severity=f.severity,
                confidence=f.confidence, message=f"{name}: {f.message}",
                locator=f"{name}/{f.locator}", hidden=f.hidden or is_hidden, detail=f.detail))
    return findings


def scan_pptx(path: str | Path) -> list[Finding]:
    """Scan a .pptx: slide text, speaker notes (hidden channel), and metadata."""
    return _scan_text_parts(
        Path(path), _PPTX_PARTS,
        hidden_parts=("ppt/notesSlides/*", "docProps/*"),
        dep_hint="scanning OOXML documents needs `verel[guard]` (defusedxml)")


def scan_xlsx(path: str | Path) -> list[Finding]:
    """Scan a .xlsx: shared strings + sheet text (hidden sheets/rows are an out-of-body channel)."""
    import re as _re
    findings = _scan_text_parts(
        Path(path), _XLSX_PARTS,
        hidden_parts=("xl/sharedStrings.xml", "xl/comments*.xml", "docProps/*"),
        dep_hint="scanning OOXML documents needs `verel[guard]` (defusedxml)")
    # a veryHidden/hidden worksheet is the spreadsheet analogue of a vanished run
    parts = _safe_parts(Path(path), ("xl/workbook.xml",))
    wb = parts.get("xl/workbook.xml", "")
    if _re.search(r'state\s*=\s*"(?:very)?hidden"', wb, _re.IGNORECASE):
        findings.append(Finding(
            detection_id="XLSX-001", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.WARNING,
            confidence=Confidence.MEDIUM, message="workbook contains a hidden/veryHidden worksheet",
            locator="xl/workbook.xml", hidden=True, detail={"detection_id": "XLSX-001"}))
    return findings
