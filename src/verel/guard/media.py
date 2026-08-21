"""Image metadata text-channel scanner (Pillow, lazy — behind the `guard-media` extra).

Images carry text an assistant may ingest as context: EXIF fields (ImageDescription, UserComment,
XPComment, Artist), XMP packets, and PNG text chunks. An instruction planted there is an out-of-body
injection channel. This is WARN-tier by default — it is a real but lower-frequency vector, and the
image PIXELS (text rendered into the image, OCR) are explicitly out of scope: that is the sight
organ's job. Pillow is lazy-imported; without it, media scanning FAILS CLOSED.
"""

from __future__ import annotations

from pathlib import Path

from ..verdict.models import Confidence
from . import lexical
from .invisible import scan_invisible
from .model import Finding, MissingGuardDep


def scan_image(path: str | Path) -> list[Finding]:
    p = Path(path)
    try:
        from PIL import Image  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:
        raise MissingGuardDep("scanning image metadata needs `verel[guard-media]` (Pillow)") from e

    findings: list[Finding] = []
    try:
        with Image.open(p) as img:
            texts: list[str] = []
            exif = img.getexif()
            for _tag_id, value in exif.items():
                if isinstance(value, (str, bytes)):
                    texts.append(value.decode("utf-8", "replace") if isinstance(value, bytes) else value)
            # PNG text chunks / generic info
            for v in getattr(img, "text", {}).values():
                texts.append(str(v))
            for v in (img.info or {}).values():
                if isinstance(v, str):
                    texts.append(v)
            xmp = img.info.get("xmp") if img.info else None
            if isinstance(xmp, (str, bytes)):
                texts.append(xmp.decode("utf-8", "replace") if isinstance(xmp, bytes) else xmp)
    except Exception as e:  # noqa: BLE001 — malformed image fails closed, never crashes
        raise ValueError(f"unreadable image: {type(e).__name__}") from e

    blob = "\n".join(t for t in texts if t)
    for f in lexical.scan_text(blob, hidden=True) + scan_invisible(blob):
        # metadata imperatives are real but lower-frequency → cap the umbrella at WARNING unless the
        # underlying lexical finding is itself gating (concealment/exfil/propagation stay as graded)
        findings.append(Finding(
            detection_id="MEDIA-001", kind=f.kind, severity=f.severity, confidence=Confidence.MEDIUM,
            message=f"image metadata channel: {f.message}", locator=f"image@meta/{f.locator}",
            hidden=True, detail={**f.detail, "detection_id": "MEDIA-001"}))
    return findings
