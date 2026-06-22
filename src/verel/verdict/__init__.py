"""Verel Verdict bus — the unified eval contract (§7).

Every agent action is a hypothesis; no hypothesis is "done" until a grader returns a
verdict. AgentVision proved this for vision; Verel generalizes it to all senses.
"""

from __future__ import annotations

from .constants import (
    ADVISORY_CEIL,
    ADVISORY_GRADERS,
    GATING_SEVERITY,
    PRECISE_GRADERS,
    SEV_ORDER,
    W,
)
from .fingerprint import assign, canonicalize, fingerprint, issue_signature
from .gate import (
    clamp_ceiling,
    coverage_satisfied,
    gate,
    gating_failures,
    progressed,
    sign_receipt,
    verify_receipt,
    verify_signature,
)
from .keys import MissingAttestationDep, attest_self
from .models import (
    Confidence,
    GateResult,
    GraderKind,
    Issue,
    IssueKind,
    Observation,
    Percept,
    ReceiptVerification,
    Report,
    RunReceipt,
    Severity,
    Verdict,
)

__all__ = [
    "ADVISORY_CEIL",
    "ADVISORY_GRADERS",
    "GATING_SEVERITY",
    "PRECISE_GRADERS",
    "SEV_ORDER",
    "W",
    "assign",
    "canonicalize",
    "clamp_ceiling",
    "coverage_satisfied",
    "fingerprint",
    "gate",
    "gating_failures",
    "issue_signature",
    "progressed",
    "sign_receipt",
    "verify_receipt",
    "verify_signature",
    "attest_self",
    "MissingAttestationDep",
    "Confidence",
    "GateResult",
    "GraderKind",
    "Issue",
    "IssueKind",
    "Observation",
    "Percept",
    "ReceiptVerification",
    "Report",
    "RunReceipt",
    "Severity",
    "Verdict",
]
