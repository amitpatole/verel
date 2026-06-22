"""The Verdict-bus data model — the unified Report/Percept contract.

This is an *extension* of AgentVision's `Report` reached through the sight adapter
(`verel.senses.sight`), NOT a copy. Fields marked COMPUTED are produced by Verel:
`Issue.fingerprint` (§7.2), `Report.cost_usd`, `Report.errored`, `Report.run_receipt`.

Faithful to docs/VEREL_DESIGN.md §7.1.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum

from pydantic import BaseModel, Field

from .._sign import canonical_payload


class Verdict(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueKind(str, Enum):
    # Mirrors agentvision.models.report.IssueKind so the sight adapter is a pure mapping.
    LAYOUT = "layout"
    OVERFLOW = "overflow"
    CLIPPED = "clipped"
    CONTRAST = "contrast"
    MISSING_ELEMENT = "missing_element"
    BROKEN_IMAGE = "broken_image"
    OVERLAP = "overlap"
    BLANK = "blank"
    ERROR_TEXT = "error_text"
    TYPO = "typo"
    INTENT_MISMATCH = "intent_mismatch"
    OTHER = "other"


class GraderKind(str, Enum):
    # Perception / structural sources (mirror AgentVision Issue.source).
    VISION = "vision"
    DOM = "dom"
    OCR = "ocr"
    CV = "cv"
    # Functional / semantic graders.
    TEST = "test"
    TYPECHECK = "typecheck"
    LINT = "lint"
    LLM_JUDGE = "llm_judge"
    PERF = "perf"
    SECURITY = "security"
    CONTRACT = "contract"
    COST = "cost"
    OTHER = "other"


class RunReceipt(BaseModel):
    """Grader-execution attestation (§7.1). Required for graders in the `required` set.

    Two-tier signing (§11): `alg="hmac-sha256"` (default) is fast and shared within a trust domain;
    `alg="ed25519"` is publicly verifiable across domains — `runner_identity` carries `ed25519:<key_id>`
    and `verify` needs only the producer's PUBLIC key, no shared secret."""

    suite_sha: str  # which frozen suite actually ran
    inputs_digest: str  # digest of the artifact/diff the grader saw
    coverage_assertion: str  # e.g. "scanned files: src/a.py,src/b.py" — must intersect the diff
    runner_identity: str  # separate-trust-domain runner's identity ("ed25519:<key_id>" for ed25519)
    result_digest: str = ""  # digest of the graded OUTCOME (verdict + issues) — binds the receipt
    #                          to the Report it graded; a stripped/tampered Report fails the gate
    alg: str = "hmac-sha256"  # "hmac-sha256" | "ed25519" — BOUND INTO signing_payload (anti-downgrade)
    # ed25519: inline urlsafe-b64 pubkey, PINNED (must hash to key_id); never trust-granting
    public_key: str = ""
    # signature over signing_payload(): (alg, suite_sha, inputs_digest, coverage, identity, result_digest)
    signature: str

    def signing_payload(self) -> str:
        # `alg` is bound FIRST so a signature minted under one scheme can never be replayed as another
        # (algorithm-confusion / downgrade): the bytes a verifier checks differ the moment `alg` differs.
        # Canonical (injective, length-prefixed) encoding — a bare "|".join was non-injective and let a
        # delimiter inside a field shift the binding's partition (red-team round 2). See verel._sign.
        return canonical_payload(self.alg, self.suite_sha, self.inputs_digest,
                                 self.coverage_assertion, self.runner_identity, self.result_digest)


class Issue(BaseModel):
    kind: IssueKind
    severity: Severity
    message: str
    locator: str | None = None
    locator_precise: bool = False
    confidence: Confidence = Confidence.MEDIUM
    source: GraderKind = GraderKind.TEST
    fingerprint: str = ""  # NIRVANA-COMPUTED, REQUIRED once through fingerprint.assign() (§7.2)
    detail_json: str = "{}"

    @property
    def detail(self) -> dict:
        try:
            return json.loads(self.detail_json)
        except (json.JSONDecodeError, TypeError):
            return {}


class Report(BaseModel):
    """EXTENSION of AgentVision's Report via the §8.3 adapter."""

    verdict: Verdict
    summary: str
    issues: list[Issue] = Field(default_factory=list)
    capabilities: list[IssueKind] = Field(default_factory=list)
    grader: GraderKind = GraderKind.OTHER
    model: str | None = None
    cost_usd: float = 0.0
    elapsed_ms: int = 0
    errored: bool = False  # ran-and-failed vs did-not-run
    run_receipt: RunReceipt | None = None  # required for graders in `required` set
    artifacts: dict[str, str] = Field(default_factory=dict)
    schema_version: str = "2.0"


def report_result_digest(report: Report) -> str:
    """Digest of a report's graded OUTCOME — bind EVERY field the gate trusts so a Report tampered
    after signing is rejected (§7.1). That means not just verdict + issue (kind, severity, message)
    but also `confidence` and `source` (the gate clamps severity by these) and `errored` (the
    dead-gate path) — otherwise an attacker flips confidence HIGH→LOW to clamp a CRITICAL to WARNING
    while the receipt still matches."""
    parts = sorted(
        f"{i.kind.value}\x1f{i.severity.value}\x1f{i.confidence.value}\x1f{i.source.value}"
        f"\x1f{i.fingerprint}\x1f{i.message}"
        for i in report.issues)
    blob = f"{report.verdict.value}\x1e{int(report.errored)}\x1e" + "\x1e".join(parts)
    return hashlib.blake2s(blob.encode()).hexdigest()[:16]


class Observation(BaseModel):
    """One percept observation — the per-issue payload of a Percept."""

    kind: IssueKind
    severity: Severity
    message: str
    locator: str | None = None
    locator_precise: bool = False
    confidence: Confidence = Confidence.MEDIUM
    source: GraderKind = GraderKind.OTHER
    fingerprint: str = ""


class Percept(BaseModel):
    """The senses/perception-bus envelope (§8.3). Sight is one sense among many."""

    sense: str  # "sight" | "logs" | "tests" | "metrics" | "types"
    verdict: Verdict
    summary: str
    observations: list[Observation] = Field(default_factory=list)
    signature: list[list[str]] = Field(default_factory=list)  # serialized issue_signature
    ts: str = ""
    agent_id: str = ""
    artifact_id: str = ""
    raw_ref: str | None = None
    trace_ctx: str | None = None
    # populated for sense == "sight"
    viewport: str | None = None
    device_scale: float | None = None
    image_path: str | None = None
    # intent conformance (populated when the eyes graded against a brief; None otherwise).
    # Lets the brain record "did the artifact match what we set out to build" over iterations.
    matches_intent: bool | None = None
    intent_satisfied: int | None = None
    intent_total: int | None = None
    # temporal signal (populated by a `watch` capture; None for a single-frame glance).
    # Lets the brain gate on / compound "playback actually worked" over iterations.
    playing: bool | None = None
    live: bool | None = None
    stabilized: bool | None = None


class GateResult(BaseModel):
    verdict: Verdict
    reason: str = ""
    attributions: dict[str, GraderKind] = Field(default_factory=dict)  # fingerprint -> grader


class ReceiptVerification(BaseModel):
    """Result of the public `verify` verb (§11) — did a receipt check out, and could a stranger?"""

    valid: bool
    alg: str
    runner_identity: str = ""
    public_verifiable: bool = False  # True only for ed25519 verified against a trusted public key
    reason: str = ""


class GraderAttestation(BaseModel):
    """One grader's line in a gate-level receipt (§4): its verdict + the signed RunReceipt that
    attests it actually ran. Advisory graders (vision/llm) inform but never gate, so they may omit
    a receipt; a `precise` grader in the gate's required set must carry a verifiable one."""

    kind: GraderKind
    verdict: Verdict
    precise: bool
    run_receipt: RunReceipt | None = None


class GateReceipt(BaseModel):
    """The gate-level receipt (§4) — the headline wedge surfaced over MCP. Wraps the per-grader
    RunReceipts so a SECOND party can confirm an agent's verdict was real: the `fingerprint`
    recomputes from the graded outcome and each precise grader's signature verifies the runner."""

    issued_by: str  # e.g. "verel@0.29.2"
    verdict: Verdict
    fingerprint: str  # recomputes from (verdict + per-grader outcome/receipt); tamper-evident
    graders: list[GraderAttestation] = Field(default_factory=list)
    ceiling_clamped: bool = False  # an advisory finding was held back from gating a destructive act


class GateReceiptVerification(BaseModel):
    """Result of verifying a gate-level receipt: did the fingerprint recompute and every precise
    grader's signature check out — and was the whole thing publicly verifiable (ed25519)?"""

    valid: bool
    verdict: Verdict | None = None
    graders_checked: int = 0
    public_verifiable: bool = False
    reason: str = ""
