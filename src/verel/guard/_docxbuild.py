"""Minimal in-memory OOXML builders — used by the demo and the test suite so no binary fixtures
are committed. Just enough of the package shape for the scanner's allowlisted parts to parse."""

from __future__ import annotations

import io
import zipfile

_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_CT = ('<?xml version="1.0"?><Types '
       'xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
_RELS = ('<?xml version="1.0"?><Relationships '
         'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')


def run(text: str, rpr: str = "") -> str:
    pr = f"<w:rPr>{rpr}</w:rPr>" if rpr else ""
    return f"<w:r>{pr}<w:t xml:space=\"preserve\">{text}</w:t></w:r>"


def para(*runs: str) -> str:
    return f"<w:p>{''.join(runs)}</w:p>"


def document(*paras: str) -> str:
    return (f'<?xml version="1.0"?><w:document {_NS}>'
            f'<w:body>{"".join(paras)}</w:body></w:document>')


def make_docx(document_xml: str, *, comments: str | None = None,
              core_props: str | None = None, extra: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document_xml)
        if comments is not None:
            z.writestr("word/comments.xml", comments)
        if core_props is not None:
            z.writestr("docProps/core.xml", core_props)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()
