"""OpenDocument (odt/ods/odp) hidden-text scanner.

ODF shares the OOXML shape: a ZIP whose `content.xml` / `meta.xml` are XML. Hidden text is
expressed through automatic styles (`style:text-properties` with `text:display="none"` or a white
`fo:color`); we don't fully resolve the style graph in v1, so we take the robust route: extract the
visible text of `content.xml`, flag any hidden-style declarations structurally, and run the whole
text (plus metadata) through the lexical/invisible catalogue. Parsing uses the same hardened
`_xmlsafe` path as OOXML (defusedxml, fail-closed without the `guard` extra).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..verdict.models import Confidence, IssueKind, Severity
from . import lexical
from .invisible import scan_invisible
from .model import (
    MAX_XML_TEXT,
    Finding,
    MissingGuardDep,
)
from .ooxml import _safe_parts, _strip_tags

_ODF_PARTS = ("content.xml", "styles.xml", "meta.xml")
_HIDDEN_STYLE = re.compile(r'text:display\s*=\s*"none"', re.IGNORECASE)
_WHITE_COLOR = re.compile(r'fo:color\s*=\s*"#(?:fff|ffffff)"', re.IGNORECASE)


def scan_odf(path: str | Path) -> list[Finding]:
    from .._xmlsafe import MissingXmlDep, xml_root
    p = Path(path)
    parts = _safe_parts(p, _ODF_PARTS)
    findings: list[Finding] = []
    content = parts.get("content.xml", "")
    if content:
        try:
            xml_root(content, dep_hint="scanning OpenDocument files needs `verel[guard]` (defusedxml)",
                     max_text=MAX_XML_TEXT)
        except MissingXmlDep as e:
            raise MissingGuardDep(str(e)) from e
        except ValueError:
            pass
        if _HIDDEN_STYLE.search(content) or _HIDDEN_STYLE.search(parts.get("styles.xml", "")):
            findings.append(Finding(
                detection_id="ODF-001", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.WARNING,
                confidence=Confidence.MEDIUM, message="ODF hidden-text style (text:display=none)",
                locator="content.xml", hidden=True, detail={"detection_id": "ODF-001"}))
        if _WHITE_COLOR.search(content) or _WHITE_COLOR.search(parts.get("styles.xml", "")):
            findings.append(Finding(
                detection_id="ODF-002", kind=IssueKind.HIDDEN_CONTENT, severity=Severity.WARNING,
                confidence=Confidence.MEDIUM, message="ODF white text style (fo:color=#ffffff)",
                locator="content.xml", hidden=True, detail={"detection_id": "ODF-002"}))
    for name in ("content.xml", "meta.xml"):
        text = _strip_tags(parts.get(name, ""))
        hidden = name == "meta.xml"
        for f in lexical.scan_text(text, hidden=hidden) + scan_invisible(text):
            findings.append(f)
    return findings
