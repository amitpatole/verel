"""The hearing sense — Audel adapter (the ears, mirror of :mod:`verel.senses.sight`).

Faithful rules enforced here (identical discipline to sight):
- Grader identity & precise-vs-advisory key off **Issue.source** (closed dsp/asr/acoustic/audio_llm),
  NEVER off `Report.backend` (an open provenance string). DSP/ASR are precise grounding; ACOUSTIC
  (CLAP) and AUDIO_LLM (transcript/audio-native critique) are advisory and clamp to WARN.
- One Audel Report is split into one Verel `Report` per source-grader, so the Gate's report-level
  advisory clamp (§7.1) is exactly right (an audio_llm report clamps to WARN; a dsp report does not).
  A single combined `Percept` is emitted for the episodic log.
- Audio issues are **time-grounded**: the `locator` carries a `{start_ms,end_ms,…}` span, not a bbox.
- `Issue.fingerprint`, `errored`, and the synthetic-fallback filter are COMPUTED here.

Audel is an OPTIONAL dependency: import it lazily so the verdict-bus core has no heavy deps.
Install with `pip install "verel[hearing]"`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..verdict.fingerprint import fingerprint as compute_fp
from ..verdict.models import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    Observation,
    Percept,
    Report,
    Verdict,
)

# Audel Issue.source -> Verel GraderKind. Closed 4-value mapping (mirror of sight's _SOURCE_TO_GRADER).
_SOURCE_TO_GRADER = {
    "dsp": GraderKind.DSP,
    "asr": GraderKind.ASR,
    "acoustic": GraderKind.ACOUSTIC,
    "audio_llm": GraderKind.AUDIO_LLM,
}

# Kinds that say "audio did not play through" — used to derive the temporal liveness signal.
_DEAD_AIR = {IssueKind.MISSING_AUDIO, IssueKind.SILENCE}
_INTERRUPTION = {IssueKind.DROPOUT, IssueKind.DESYNC, IssueKind.TRUNCATION}


@dataclass
class AudioResult:
    """What the hearing sense produces for one listen (one analyze/watch call)."""

    reports: list[Report]  # one per source-grader — fed to gate()
    percept: Percept  # combined envelope — fed to the episodic log
    raw: object = field(default=None, repr=False)  # the original Audel Report


def _conf(c: str) -> Confidence:
    return {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}.get(
        str(c), Confidence.MEDIUM
    )


def _verdict(v: str) -> Verdict:
    return {"pass": Verdict.PASS, "warn": Verdict.WARN, "fail": Verdict.FAIL}[str(v)]


def _sev(au_sev):
    from ..verdict.models import Severity

    return Severity(str(getattr(au_sev, "value", au_sev)))


def _is_synthetic_fallback(au_issue) -> bool:
    # Audel may inject a synthetic OTHER issue on backend fallback; filter it before consolidation
    # but keep it visible in the percept (detail.fallback == true). Mirrors the sight filter.
    try:
        return bool(json.loads(getattr(au_issue, "detail_json", "{}") or "{}").get("fallback"))
    except (json.JSONDecodeError, TypeError, AttributeError):
        return False


def _locator(au_issue) -> str | None:
    """Time-grounding: serialize the issue's span to a compact JSON locator (None if not grounded)."""
    span = getattr(au_issue, "span", None)
    if span is None:
        return None
    if hasattr(span, "model_dump"):
        return json.dumps(span.model_dump(), default=str)
    if hasattr(span, "__dict__"):
        return json.dumps(vars(span), default=str)
    return None


def _report_verdict(issues: list[Issue]) -> Verdict:
    from ..verdict.constants import GATING_SEVERITY, SEV_ORDER
    from ..verdict.models import Severity

    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    if any(SEV_ORDER.index(i.severity) >= gate_idx for i in issues):
        return Verdict.FAIL
    if any(i.severity == Severity.WARNING for i in issues):
        return Verdict.WARN
    return Verdict.PASS


def _temporal(au_report, *, temporal: bool) -> tuple[bool | None, bool | None, bool | None]:
    """Derive (playing, live, stabilized) for a `watch` listen; all None for a single glance.

    `playing`/`live`: audio actually carried sound through (no dead-air finding). `stabilized`: no
    interruption (dropout / desync / truncation). These let the brain compound "playback verified".
    """
    if not temporal:
        return None, None, None
    kinds = {IssueKind(str(getattr(i.kind, "value", i.kind))) for i in getattr(au_report, "issues", [])}
    played = not (kinds & _DEAD_AIR)
    return played, played, not (kinds & _INTERRUPTION)


def from_audel(au_report, *, sense: str = "hearing", agent_id: str = "", artifact_id: str = "",
               cost_usd: float = 0.0, temporal: bool = False) -> AudioResult:
    """Map a real `audel.models.Report` into the Verel verdict-bus contract.

    Pure function over the Audel object — no decoding, no I/O. ``temporal=True`` marks a `watch`
    result so the percept carries the liveness signal.
    """
    verel_issues_by_grader: dict[GraderKind, list[Issue]] = {}
    observations: list[Observation] = []

    for au in au_report.issues:
        source = _SOURCE_TO_GRADER.get(str(getattr(au.source, "value", au.source)), GraderKind.DSP)
        locator = _locator(au)
        issue = Issue(
            kind=IssueKind(str(getattr(au.kind, "value", au.kind))),
            severity=_sev(au.severity),
            message=au.message,
            locator=locator,
            locator_precise=bool(locator) and source in (GraderKind.DSP, GraderKind.ASR),
            confidence=_conf(getattr(au.confidence, "value", au.confidence)),
            source=source,
            detail_json=getattr(au, "detail_json", "{}") or "{}",
        )
        issue.fingerprint = compute_fp(issue)

        observations.append(Observation(
            kind=issue.kind, severity=issue.severity, message=issue.message,
            locator=issue.locator, locator_precise=issue.locator_precise,
            confidence=issue.confidence, source=issue.source, fingerprint=issue.fingerprint,
        ))
        if _is_synthetic_fallback(au):
            continue  # visible in the percept, not gated into a report
        verel_issues_by_grader.setdefault(source, []).append(issue)

    caps = [IssueKind(str(getattr(k, "value", k))) for k in getattr(au_report, "capabilities", [])]
    backend = getattr(au_report, "backend", "unknown")
    model = getattr(au_report, "model", None)
    elapsed = int(getattr(au_report, "elapsed_ms", 0))

    reports: list[Report] = []
    for grader, issues in verel_issues_by_grader.items():
        reports.append(Report(
            verdict=_report_verdict(issues), summary=au_report.summary, issues=issues,
            capabilities=caps, grader=grader,
            model=model or backend,  # provenance only — NEVER an input to trust
            cost_usd=cost_usd if grader == GraderKind.AUDIO_LLM else 0.0,
            elapsed_ms=elapsed, errored=False,
        ))
    if not reports:
        # Sense ran with no gating issues: emit a clean DSP report so the gate sees a present,
        # non-errored hearing grader (absence-of-issue != absence-of-grader).
        reports.append(Report(
            verdict=Verdict.PASS, summary=au_report.summary, capabilities=caps,
            grader=GraderKind.DSP, model=model or backend, elapsed_ms=elapsed,
        ))

    matches_intent, intent_satisfied, intent_total = _conformance(au_report)
    playing, live, stabilized = _temporal(au_report, temporal=temporal)
    percept = Percept(
        sense=sense,
        verdict=_verdict(getattr(au_report.verdict, "value", au_report.verdict)),
        summary=au_report.summary,
        observations=observations,
        signature=[[o.kind.value, o.fingerprint] for o in observations],
        agent_id=agent_id,
        artifact_id=artifact_id or (getattr(au_report, "audio_path", None) or ""),
        matches_intent=matches_intent,
        intent_satisfied=intent_satisfied,
        intent_total=intent_total,
        playing=playing,
        live=live,
        stabilized=stabilized,
    )
    return AudioResult(reports=reports, percept=percept, raw=au_report)


def _conformance(au_report) -> tuple[bool | None, int | None, int | None]:
    """Extract intent-conformance facts from an Audel Report (None when no brief was graded)."""
    conf = getattr(au_report, "conformance", None)
    if conf is None or not getattr(conf, "claims", None):
        return None, None, None
    try:
        return bool(conf.matches_intent()), int(conf.satisfied), int(conf.total)
    except (AttributeError, TypeError, ValueError):
        return None, None, None


async def perceive(source: str, *, backend: str = "local", agent_id: str = "",
                   allow_local: bool = False, settings_overrides: dict | None = None,
                   **analyze_kwargs) -> AudioResult:
    """Grade `source` through Audel (`analyze`), return the Verel AudioResult.

    Thin wrapper over `audel.analyze(...)`. Requires `verel[hearing]`.

    SSRF: Audel's `block_private_networks` guard is left ON by default — `source` is
    attacker/agent-controlled, so localhost/LAN/metadata endpoints are refused on any URL path.
    `allow_local=True` is an EXPLICIT opt-in (e.g. an agent verifying its own dev server) that
    relaxes the guard — fail-closed by default, exactly like the sight sense.
    """
    from audel import analyze, load_settings

    overrides = dict(settings_overrides or {})
    if allow_local:
        overrides["block_private_networks"] = False  # explicit opt-in only — default fails closed
    settings = load_settings(audio_backend=backend, **overrides)
    au_report = await analyze(source, settings=settings, **analyze_kwargs)
    return from_audel(au_report, agent_id=agent_id, artifact_id=source)


async def watch(source: str, *, backend: str = "local", agent_id: str = "",
                allow_local: bool = False, settings_overrides: dict | None = None,
                **watch_kwargs) -> AudioResult:
    """Temporal perception — listen to `source` OVER TIME (does the audio play THROUGH?).

    Thin wrapper over `audel.watch(...)`; returns the same Verel AudioResult so the verdict bus and
    brain consume it like any other sense. Dead air (silent-though-it-"plays") and interruptions
    (dropout / desync) gate; the percept carries `playing`/`live`/`stabilized` so the brain can
    compound "playback actually worked". Same fail-closed SSRF stance as `perceive`. Requires
    `verel[hearing]`.
    """
    from audel import load_settings
    from audel import watch as au_watch

    overrides = dict(settings_overrides or {})
    if allow_local:
        overrides["block_private_networks"] = False
    settings = load_settings(audio_backend=backend, **overrides)
    au_report = await au_watch(source, settings=settings, **watch_kwargs)
    return from_audel(au_report, agent_id=agent_id, artifact_id=source, temporal=True)
