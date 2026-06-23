"""Gate-level attestation (§4) — wrap the per-grader RunReceipts a stage produced into ONE
verifiable GateReceipt, and verify it.

This is the artifact the `gate` MCP tool hands back to an agent (and that `verel verify` can check):
the receipt every other party uses to confirm the verdict was real. Integrity comes from two places —
a `fingerprint` that recomputes from the graded outcome (tamper-evident), and the per-grader
RunReceipt signatures (which can be ed25519, i.e. publicly verifiable, when `verel[attest]` is on).
"""

from __future__ import annotations

import hashlib

from .._sign import canonical_payload
from . import keys
from .constants import ADVISORY_GRADERS, GATING_SEVERITY, PRECISE_GRADERS, SEV_ORDER
from .gate import sign_receipt, verify_receipt
from .models import (
    Confidence,
    GateReceipt,
    GateReceiptVerification,
    GraderAttestation,
    Report,
    RunReceipt,
    Verdict,
    report_result_digest,
)


def mint_report_receipt(report: Report, *, suite_sha: str, inputs_digest: str,
                        coverage_assertion: str, attest: str = "hmac",
                        runner_identity: str = "sight-runner") -> RunReceipt:
    """Attach a signed RunReceipt to `report`, binding its graded outcome. Used by senses (e.g. sight)
    that produce Reports outside the CI grader path but still need attestation (§4). `attest`: "hmac"
    or "ed25519" (publicly verifiable)."""
    rr = RunReceipt(suite_sha=suite_sha, inputs_digest=inputs_digest,
                    coverage_assertion=coverage_assertion, runner_identity=runner_identity,
                    result_digest=report_result_digest(report), signature="")
    if attest == "ed25519":
        keys.attest_self(rr)
    else:
        rr.signature = sign_receipt(rr)
    report.run_receipt = rr
    return rr


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


def build_gate_receipt(verdict: Verdict, reports: list[Report], *, issued_by: str | None = None,
                       attest: str = "hmac", subject: str = "") -> GateReceipt:
    """Assemble the gate-level receipt from a stage's reports (each carrying its signed RunReceipt)
    and SIGN the envelope (`attest`: "hmac" in-domain, or "ed25519" publicly verifiable). The
    envelope signature binds the aggregate verdict + the grader set — the grader receipts alone
    don't (a real grader receipt could otherwise be paired with a flipped gate verdict). `subject`
    binds extra attested context (e.g. a sight percept's image_ref + matches_intent)."""
    if issued_by is None:
        from .. import __version__
        issued_by = f"verel@{__version__}"
    graders = [
        GraderAttestation(kind=r.grader, verdict=r.verdict, precise=r.grader in PRECISE_GRADERS,
                          run_receipt=r.run_receipt)
        for r in reports
    ]
    clamped = any(_was_clamped(r) for r in reports)
    gr = GateReceipt(issued_by=issued_by, verdict=verdict, fingerprint=_fingerprint(verdict, graders),
                     graders=graders, ceiling_clamped=clamped, subject=subject)
    if attest == "ed25519":
        keys.attest_self(gr)                  # duck-typed: stamps ed25519 identity + signs the envelope
    else:
        gr.alg = "hmac-sha256"
        gr.runner_identity = "ci-runner"
        gr.signature = sign_receipt(gr)
    return gr


def fact_commitment(subject: str, predicate: str, text: str) -> str:
    """A deterministic commitment to a claim's CONTENT (subject|predicate|text — not its scope, which
    is only where it's filed). This is what a fact attestation binds into its signed `subject`, so a
    receipt proves it attests THIS exact claim — closing the trust-laundering gap (an unrelated valid
    receipt can't promote a different fact). Producer and importer compute it identically.

    Uses the FULL 256-bit blake2s digest (not the [:16] dedup truncation): this is a security binding
    where an attacker would benefit from a second-preimage, so the collision margin must be infeasible
    (2^128), not the ~2^64 a 64-bit truncation would allow. `factclaim` domain-tagged + length-prefixed
    (injective), so no field-boundary collision between subject/predicate/text."""
    return "fact:" + hashlib.blake2s(
        canonical_payload("factclaim", subject, predicate, text).encode()).hexdigest()


def attest_fact(verdict: Verdict, reports: list[Report], *, subject: str, predicate: str, text: str,
                attest: str = "ed25519", issued_by: str | None = None) -> GateReceipt:
    """Mint a PORTABLE fact attestation — a signed GateReceipt whose `subject` commits to the claim, so
    a DIFFERENT principal can accept it as proof this fact passed a trusted grader. `reports` are the
    eval/grader reports the verdict rests on (each carrying its signed RunReceipt)."""
    return build_gate_receipt(verdict, reports, attest=attest, issued_by=issued_by,
                              subject=fact_commitment(subject, predicate, text))


def verify_fact_attestation(receipt: GateReceipt | dict, subject: str, predicate: str, text: str, *,
                            allowed_algs: set[str] | None = None) -> bool:
    """True iff `receipt` is a GateReceipt that VERIFIES, attests a PASS verdict, and is bound to THIS
    exact fact (its signed `subject` == the fact commitment). The basis for a cross-principal `verified`
    tier: trust travels only via a trusted grader's signature over this specific claim — never the
    caller's say-so, and never an unrelated receipt. Pass allowed_algs={"ed25519"} to require public
    verifiability (no shared secret), as a cross-principal importer must."""
    try:
        gr = receipt if isinstance(receipt, GateReceipt) else GateReceipt.model_validate(receipt)
    except (ValueError, TypeError):
        return False
    res = verify_gate_receipt(gr, allowed_algs=allowed_algs)
    return (res.valid and gr.verdict == Verdict.PASS
            and gr.subject == fact_commitment(subject, predicate, text))


def verify_gate_receipt(receipt: GateReceipt, *,
                        allowed_algs: set[str] | None = None) -> GateReceiptVerification:
    """Verify a gate-level receipt with NO trust in its producer. Fails closed in layers:
      1. the ENVELOPE signature must verify (binds verdict + fingerprint + identity) — this is what
         makes the aggregate verdict unforgeable;
      2. the fingerprint must recompute from the grader lines;
      3. every PRECISE grader (precise determined by KIND, never the receipt's self-declared flag —
         else an attacker relabels a grader advisory to skip its check) must carry a RunReceipt whose
         signature verifies.
    `public_verifiable` is True only when the envelope AND all precise receipts verified as ed25519."""
    env = verify_receipt(receipt, allowed_algs=allowed_algs)  # duck-typed: GateReceipt shares the shape
    if not env.valid:
        return GateReceiptVerification(valid=False, verdict=receipt.verdict,
                                       reason=f"envelope signature: {env.reason}")
    if _fingerprint(receipt.verdict, receipt.graders) != receipt.fingerprint:
        return GateReceiptVerification(valid=False, verdict=receipt.verdict,
                                       reason="fingerprint mismatch (tampered)")
    checked = 0
    public = env.public_verifiable
    for a in receipt.graders:
        if a.kind not in PRECISE_GRADERS:     # authoritative, NOT a.precise (attacker-controlled)
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
                                   public_verifiable=public, subject=receipt.subject,
                                   reason=f"{checked} precise grader(s) attested")
