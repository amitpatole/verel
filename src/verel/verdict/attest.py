"""Gate-level attestation (§4) — wrap the per-grader RunReceipts a stage produced into ONE
verifiable GateReceipt, and verify it.

This is the artifact the `gate` MCP tool hands back to an agent (and that `verel verify` can check):
the receipt every other party uses to confirm the verdict was real. Integrity comes from two places —
a `fingerprint` that recomputes from the graded outcome (tamper-evident), and the per-grader
RunReceipt signatures (which can be ed25519, i.e. publicly verifiable, when `verel[attest]` is on).
"""

from __future__ import annotations

import hashlib

from .constants import ADVISORY_GRADERS, GATING_SEVERITY, PRECISE_GRADERS, SEV_ORDER
from .gate import verify_receipt
from .models import (
    Confidence,
    GateReceipt,
    GateReceiptVerification,
    GraderAttestation,
    Report,
    Verdict,
)


def _was_clamped(report: Report) -> bool:
    """Did an advisory/low-confidence finding that WOULD have gated get held back to the ceiling?
    Mirrors the gate's clamp so the receipt can honestly say 'an opinion was kept from gating'."""
    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    advisory = report.grader in ADVISORY_GRADERS
    return any(
        (advisory or i.confidence == Confidence.LOW) and SEV_ORDER.index(i.severity) >= gate_idx
        for i in report.issues
    )


def _fingerprint(verdict: Verdict, graders: list[GraderAttestation]) -> str:
    """Tamper-evident digest over the verdict + each grader's outcome AND its receipt signature, so
    neither a flipped verdict nor a swapped/stripped grader line survives recomputation."""
    parts = sorted(
        f"{a.kind.value}\x1f{a.verdict.value}\x1f{int(a.precise)}\x1f"
        f"{a.run_receipt.result_digest if a.run_receipt else ''}\x1f"
        f"{a.run_receipt.signature if a.run_receipt else ''}"
        for a in graders
    )
    blob = f"{verdict.value}\x1e" + "\x1e".join(parts)
    return hashlib.blake2s(blob.encode()).hexdigest()[:16]


def build_gate_receipt(verdict: Verdict, reports: list[Report], *,
                       issued_by: str | None = None) -> GateReceipt:
    """Assemble the gate-level receipt from a stage's reports (each carrying its signed RunReceipt)."""
    if issued_by is None:
        from .. import __version__
        issued_by = f"verel@{__version__}"
    graders = [
        GraderAttestation(kind=r.grader, verdict=r.verdict, precise=r.grader in PRECISE_GRADERS,
                          run_receipt=r.run_receipt)
        for r in reports
    ]
    clamped = any(_was_clamped(r) for r in reports)
    return GateReceipt(issued_by=issued_by, verdict=verdict, fingerprint=_fingerprint(verdict, graders),
                       graders=graders, ceiling_clamped=clamped)


def verify_gate_receipt(receipt: GateReceipt, *,
                        allowed_algs: set[str] | None = None) -> GateReceiptVerification:
    """Verify a gate-level receipt with NO trust in its producer. Fails closed: the fingerprint must
    recompute, and EVERY precise grader must carry a RunReceipt whose signature verifies. Advisory
    graders need not carry one (they never gate). `public_verifiable` is True only when there is at
    least one precise grader and ALL precise receipts verified as ed25519 against trusted keys."""
    if _fingerprint(receipt.verdict, receipt.graders) != receipt.fingerprint:
        return GateReceiptVerification(valid=False, verdict=receipt.verdict,
                                       reason="fingerprint mismatch (tampered)")
    checked = 0
    public = True
    for a in receipt.graders:
        if not a.precise:
            continue
        if a.run_receipt is None:
            return GateReceiptVerification(valid=False, verdict=receipt.verdict,
                                           reason=f"{a.kind.value}: precise grader missing receipt")
        v = verify_receipt(a.run_receipt, allowed_algs=allowed_algs)
        if not v.valid:
            return GateReceiptVerification(valid=False, verdict=receipt.verdict,
                                           reason=f"{a.kind.value}: {v.reason}")
        checked += 1
        public = public and v.public_verifiable
    return GateReceiptVerification(valid=True, verdict=receipt.verdict, graders_checked=checked,
                                   public_verifiable=checked > 0 and public,
                                   reason=f"{checked} precise grader(s) attested")
