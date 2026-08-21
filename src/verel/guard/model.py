"""Data model and bounds for the document-ingress guard.

The guard grades untrusted documents STATICALLY, before any LLM sees them — the document is data,
never instructions. The core signal is the one this attack class cannot avoid: text present for an
extractor but invisible to a human reader. Structural hiding alone is WARNING (legitimate documents
hide text: track changes, template fields); hiding PLUS a lexical imperative is CRITICAL — the
conjunction is the attack. An imperative alone in visible text is WARNING (docs *about* prompt
injection must not gate).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..verdict.models import Confidence, IssueKind, Severity


class MissingGuardDep(RuntimeError):
    """A guard scanner needs an optional dependency that is not installed. XML-based formats
    (docx/pptx/xlsx/odf) need `verel[guard]` (defusedxml); plain text / markdown / HTML / RTF
    scanning is dependency-free. Scanning an XML format without the dep FAILS CLOSED."""


# Catalogue identity — bound into the grader's suite identity (receipt `suite_sha`) so any pattern
# change re-mints the suite: a PASS receipt from an older catalogue is distinguishable by design.
CATALOG_VERSION = "guard-catalog/1"

# Bounds — every attacker-controlled resource is capped BEFORE the expensive operation (stat before
# open, ZipInfo before decompress, char cap before regex). Violations fail closed (errored FAIL).
MAX_DOC_BYTES = int(os.environ.get("VEREL_GUARD_MAX_DOC_BYTES", str(10 * 1024 * 1024)))
MAX_ZIP_MEMBERS = 256            # a docx has ~15 parts; hundreds is not a document
MAX_MEMBER_BYTES = 20 * 1024 * 1024   # declared-uncompressed, summed across scanned parts
MAX_ZIP_RATIO = 100              # per-member file_size/compress_size (zip-bomb tell)
MAX_SCAN_CHARS = 2 * 1024 * 1024  # per-part text fed to the lexical/invisible scanners
MAX_XML_TEXT = 65536             # per-text-node bound (prose runs are longer than PM counters)
MIN_HIDDEN_SPAN = 20             # canonical chars before a bare hidden span (no imperative) fires


@dataclass(frozen=True)
class Finding:
    """One grounded detection. `span_key` in `detail` is the `rejected_key`-canonical form of the
    offending text — the same 200-char canonical prefix the memory tombstone ledger consults, so a
    FAILed document's payloads can feed `record_rejection` and the propagation check directly."""

    detection_id: str            # catalogue key: "LEX-001" … "UNI-003" … "DOCX-006"
    kind: IssueKind              # HIDDEN_CONTENT | INJECTION | EXFIL_VECTOR
    severity: Severity
    confidence: Confidence
    message: str                 # human summary; any embedded snippet is canonicalized/defanged
    locator: str                 # part/element/offset grounding (file prefix added by the reporter)
    hidden: bool = False         # True when the flagged text is invisible to a human reader
    detail: dict[str, object] = field(default_factory=dict)
