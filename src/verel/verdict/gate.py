"""The Gate — a typed reducer with an explicit CEILING clamp + grader attestation (§7.1),
plus generalized stuck/progressed detection (§7.2).

This is the single most load-bearing safety surface in Verel. Every rule here is the
direct output of the design's critic loop; do not "simplify" the clamp to a min-by-key.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from .constants import ADVISORY_CEIL, ADVISORY_GRADERS, GATING_SEVERITY, SEV_ORDER
from .models import (
    Confidence,
    GateResult,
    GraderKind,
    Report,
    RunReceipt,
    Severity,
    Verdict,
)

# Dev default; production injects a real per-runner key from the separate trust domain.
_RUNNER_SECRET = os.environ.get("VEREL_RUNNER_SECRET", "verel-dev-runner-secret").encode()


# ---------------------------------------------------------------------------
# Severity clamp — EXPLICIT CEILING, not min-by-key (§7.1).
# ---------------------------------------------------------------------------
def clamp_ceiling(sev: Severity, ceil: Severity) -> Severity:
    return sev if SEV_ORDER.index(sev) <= SEV_ORDER.index(ceil) else ceil


# ---------------------------------------------------------------------------
# Run-receipt attestation helpers.
# ---------------------------------------------------------------------------
def sign_receipt(receipt: RunReceipt, secret: bytes = _RUNNER_SECRET) -> str:
    return hmac.new(secret, receipt.signing_payload().encode(), hashlib.sha256).hexdigest()


def verify_signature(receipt: RunReceipt, secret: bytes = _RUNNER_SECRET) -> bool:
    if not receipt.signature:
        return False
    return hmac.compare_digest(receipt.signature, sign_receipt(receipt, secret))


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
) -> GateResult:
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
            if rr is None or not verify_signature(rr):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: missing/forged receipt")
            if rr.suite_sha != frozen_suites.get(r.grader):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: stale/wrong suite_sha")
            if not coverage_satisfied(rr.coverage_assertion, diff_files):
                return GateResult(verdict=Verdict.FAIL, reason=f"{r.grader.value}: grader did not cover diff")

    # (b) advisory + low-confidence clamp via EXPLICIT CEILING.
    gating: list[tuple[Severity, object]] = []
    attributions: dict[str, GraderKind] = {}
    for r in reports:
        for i in r.issues:
            sev = i.severity
            if r.grader in ADVISORY_GRADERS:
                sev = clamp_ceiling(sev, ADVISORY_CEIL)
            elif i.confidence == Confidence.LOW:
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
