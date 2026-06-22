"""The Gate — a typed reducer with an explicit CEILING clamp + grader attestation (§7.1),
plus generalized stuck/progressed detection (§7.2).

This is the single most load-bearing safety surface in Verel. Every rule here is the
direct output of the design's critic loop; do not "simplify" the clamp to a min-by-key.
"""

from __future__ import annotations

import hashlib
import hmac

from .._secrets import load_secret
from . import keys
from .constants import ADVISORY_CEIL, ADVISORY_GRADERS, GATING_SEVERITY, SEV_ORDER
from .models import (
    Confidence,
    GateResult,
    GraderKind,
    ReceiptVerification,
    Report,
    Severity,
    SignableReceipt,
    Verdict,
    report_result_digest,
)

HMAC = "hmac-sha256"

# Per-runner signing key. Set VEREL_RUNNER_SECRET to share it across a trust domain (e.g. a CI
# runner that signs and a separate gate that verifies); otherwise a persistent per-installation
# random key is used (no public default — see _secrets.load_secret).
_RUNNER_SECRET = load_secret("VEREL_RUNNER_SECRET", "runner_secret")


# ---------------------------------------------------------------------------
# Severity clamp — EXPLICIT CEILING, not min-by-key (§7.1).
# ---------------------------------------------------------------------------
def clamp_ceiling(sev: Severity, ceil: Severity) -> Severity:
    return sev if SEV_ORDER.index(sev) <= SEV_ORDER.index(ceil) else ceil


# ---------------------------------------------------------------------------
# Run-receipt attestation helpers.
# ---------------------------------------------------------------------------
def _hmac_sig(receipt: SignableReceipt, secret: bytes) -> str:
    return hmac.new(secret, receipt.signing_payload().encode(), hashlib.sha256).hexdigest()


def sign_receipt(receipt: SignableReceipt, secret: bytes = _RUNNER_SECRET) -> str:
    """Sign per `receipt.alg`. ed25519 signs with the local runner's key (the caller must have
    stamped `runner_identity`/`public_key` first — see `keys.attest_self`); hmac-sha256 (default)
    keys off the shared trust-domain secret."""
    if receipt.alg == keys.ED25519:
        return keys.ed25519_sign(receipt.signing_payload())
    return _hmac_sig(receipt, secret)


def verify_signature(
    receipt: SignableReceipt, secret: bytes = _RUNNER_SECRET, *, allowed_algs: set[str] | None = None
) -> bool:
    """True iff the receipt's signature is valid under its `alg`. Fails CLOSED on: empty signature,
    an alg outside `allowed_algs` (when a policy is given), an unknown alg, ed25519 with an untrusted
    key, or PyNaCl absent. ed25519 needs only a trusted PUBLIC key (no shared secret)."""
    if not receipt.signature:
        return False
    alg = receipt.alg
    if allowed_algs is not None and alg not in allowed_algs:
        return False  # policy: this verifier does not accept this scheme (e.g. require public-verifiable)
    if alg == keys.ED25519:
        try:
            return keys.ed25519_verify(receipt)
        except keys.MissingAttestationDep:
            return False  # no PyNaCl → cannot verify → fail closed (never silent green)
    if alg == HMAC:
        return hmac.compare_digest(receipt.signature, _hmac_sig(receipt, secret))
    return False  # unknown alg → fail closed


def verify_receipt(
    receipt: SignableReceipt, *, secret: bytes = _RUNNER_SECRET, allowed_algs: set[str] | None = None
) -> ReceiptVerification:
    """The public `verify` verb (§11): check a receipt and explain the result — including whether it
    was **publicly** verifiable (ed25519 against a trusted public key) or shared-secret (HMAC)."""
    alg = receipt.alg
    ident = receipt.runner_identity
    if allowed_algs is not None and alg not in allowed_algs:
        return ReceiptVerification(valid=False, alg=alg, runner_identity=ident,
                                   public_verifiable=False, reason=f"alg {alg!r} not permitted by policy")
    if not receipt.signature:
        return ReceiptVerification(valid=False, alg=alg, runner_identity=ident,
                                   public_verifiable=False, reason="empty signature")
    if alg == keys.ED25519:
        try:
            ok = keys.ed25519_verify(receipt)
        except keys.MissingAttestationDep as e:
            return ReceiptVerification(valid=False, alg=alg, runner_identity=ident,
                                       public_verifiable=False, reason=str(e))
        return ReceiptVerification(
            valid=ok, alg=alg, runner_identity=ident, public_verifiable=ok,
            reason="ed25519 verified against a trusted public key" if ok
            else "ed25519 signature invalid or key_id not trusted")
    if alg == HMAC:
        ok = hmac.compare_digest(receipt.signature, _hmac_sig(receipt, secret))
        return ReceiptVerification(valid=ok, alg=alg, runner_identity=ident, public_verifiable=False,
                                   reason="hmac verified (shared-secret, single trust domain)" if ok
                                   else "hmac signature mismatch")
    return ReceiptVerification(valid=False, alg=alg, runner_identity=ident,
                               public_verifiable=False, reason=f"unknown alg {alg!r}")


def coverage_satisfied(coverage_assertion: str, diff_files: set[str]) -> bool:
    """The grader must prove it scanned at least one changed file.

    `coverage_assertion` is of the form "scanned files: a.py,b.py". An empty diff set is
    treated as satisfied (nothing changed to cover).
    """
    if not diff_files:
        return True
    _, _, rhs = coverage_assertion.partition(":")
    scanned = {f.strip() for f in rhs.split(",") if f.strip()}
    return bool(scanned & diff_files)


# ---------------------------------------------------------------------------
# The Gate.
# ---------------------------------------------------------------------------
def gate(
    reports: list[Report],
    required: set[GraderKind] | None = None,
    frozen_suites: dict[GraderKind, str] | None = None,
    diff_files: set[str] | None = None,
    inputs_digests: dict[GraderKind, str] | None = None,
    allowed_algs: set[str] | None = None,
) -> GateResult:
    # `allowed_algs` is the verifier's signing policy: None accepts any supported scheme (HMAC within
    # the trust domain, ed25519 if the key is trusted); pass {"ed25519"} to REQUIRE public verifiability.
    required = required or set()
    frozen_suites = frozen_suites or {}
    diff_files = diff_files or set()

    # (a) DEAD-GATE: required grader absent OR errored => FAIL.
    present = {r.grader for r in reports if not r.errored}
    missing = required - present
    if missing:
        names = ", ".join(sorted(g.value for g in missing))
        return GateResult(verdict=Verdict.FAIL, reason=f"required grader(s) absent/errored: {names}")

    # (a') HOLLOW-GATE: required grader must ATTEST it ran the frozen suite AND covered the diff.
    for r in reports:
        if r.grader in required:
            rr = r.run_receipt
            if rr is None or not verify_signature(rr, allowed_algs=allowed_algs):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: missing/forged receipt")
            if rr.suite_sha != frozen_suites.get(r.grader):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: stale/wrong suite_sha")
            # INPUT BINDING: the receipt must match the bytes actually in front of us now, so a PASS
            # receipt can't be replayed onto different code with the same filenames.
            if inputs_digests is not None and rr.inputs_digest != inputs_digests.get(r.grader):
                return GateResult(verdict=Verdict.FAIL,
                                  reason=f"{r.grader.value}: receipt input mismatch (replayed/stale)")
            if not coverage_satisfied(rr.coverage_assertion, diff_files):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: grader did not cover diff")
            # RESULT BINDING: the receipt must commit to the report's graded outcome, so an
            # attacker can't pair a valid receipt with a tampered Report (e.g. issues stripped → PASS).
            if rr.result_digest != report_result_digest(r):
                return GateResult(verdict=Verdict.FAIL,
                                  reason=f"{r.grader.value}: receipt does not match graded result (tampered)")

    # (b) advisory + low-confidence clamp via EXPLICIT CEILING.
    gating: list[tuple[Severity, object]] = []
    attributions: dict[str, GraderKind] = {}
    for r in reports:
        for i in r.issues:
            sev = i.severity
            if r.grader in ADVISORY_GRADERS or i.confidence == Confidence.LOW:
                sev = clamp_ceiling(sev, ADVISORY_CEIL)
            gating.append((sev, i))
            if i.fingerprint:
                attributions[i.fingerprint] = r.grader

    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    if any(SEV_ORDER.index(s) >= gate_idx for s, _ in gating):
        verdict = Verdict.FAIL
    elif any(s == Severity.WARNING for s, _ in gating):
        verdict = Verdict.WARN
    else:
        verdict = Verdict.PASS
    return GateResult(verdict=verdict, attributions=attributions)


# ---------------------------------------------------------------------------
# Generalized stuck vs progressed (§7.2).
# ---------------------------------------------------------------------------
def gating_failures(report: Report) -> frozenset[str]:
    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    return frozenset(
        i.fingerprint for i in report.issues if SEV_ORDER.index(i.severity) >= gate_idx
    )


def progressed(curr: Report, prev: Report) -> bool:
    """STRICT subset shrinkage of the gating-failure set. Equal-cardinality swaps and
    growth are NOT progress (a decoy that adds a new gating issue is a regression)."""
    return gating_failures(curr) < gating_failures(prev)
