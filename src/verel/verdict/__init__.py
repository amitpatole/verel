"""Verel Verdict bus — the unified eval contract (§7).

Every agent action is a hypothesis; no hypothesis is "done" until a grader returns a
verdict. AgentVision proved this for vision; Verel generalizes it to all senses.
"""

from __future__ import annotations

from .attest import (
    attest_fact,
    build_gate_receipt,
    fact_commitment,
    mint_report_receipt,
    verify_fact_attestation,
    verify_gate_receipt,
)
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
    GateReceipt,
    GateReceiptVerification,
    GateResult,
    GraderAttestation,
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
    "build_gate_receipt",
    "mint_report_receipt",
    "verify_gate_receipt",
    "attest_fact",
    "fact_commitment",
    "verify_fact_attestation",
    "MissingAttestationDep",
    "Confidence",
    "GateReceipt",
    "GateReceiptVerification",
    "GateResult",
    "GraderAttestation",
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
