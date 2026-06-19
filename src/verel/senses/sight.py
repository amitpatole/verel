"""The sight sense — AgentVision adapter (§8.2, §8.3).

Faithful rules enforced here:
- Grader identity & precise-vs-advisory key off **Issue.source** (closed dom/ocr/cv/vision),
  NEVER off `Report.backend` (an open provenance string).
- The "reachable without a vision backend" capability set is **imported from
  `agentvision.core.checks.CLASSIC_CAPABILITIES`**, not hand-transcribed (drift-proof).
- One AgentVision Report is split into one Verel `Report` per source-grader, so the Gate's
  report-level advisory clamp (§7.1) is exactly correct (a vision report clamps to WARN; a
  dom report does not). A single combined `Percept` is emitted for the episodic log.
- `Issue.fingerprint`, `errored`, and the synthetic-fallback filter are COMPUTED here.

AgentVision is an OPTIONAL dependency: import it lazily so the verdict-bus core has no
heavy deps. Install with `pip install "verel[sight]"`.
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

# AgentVision Issue.source -> Verel GraderKind. Closed 4-value mapping.
_SOURCE_TO_GRADER = {
    "dom": GraderKind.DOM,
    "ocr": GraderKind.OCR,
    "cv": GraderKind.CV,
    "vision": GraderKind.VISION,
}


def classic_capabilities() -> set[str]:
    """The kinds the no-LLM (`local`/`checks`) path can emit, imported from source so it
    cannot silently drift from AgentVision."""
    from agentvision.core.checks import CLASSIC_CAPABILITIES

    return set(CLASSIC_CAPABILITIES)


@dataclass
class SightResult:
    """What the sight sense produces for one saccade (one analyze call)."""

    reports: list[Report]  # one per source-grader — fed to gate()
    percept: Percept  # combined envelope — fed to the episodic log
    raw: object = field(default=None, repr=False)  # the original AgentVision Report


def _conf(c: str) -> Confidence:
    return {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}.get(
        str(c), Confidence.MEDIUM
    )


def _verdict(v: str) -> Verdict:
    return {"pass": Verdict.PASS, "warn": Verdict.WARN, "fail": Verdict.FAIL}[str(v)]


def _is_synthetic_fallback(av_issue) -> bool:
    # core/analyze.py injects a synthetic OTHER/CV issue on backend fallback; filter it
    # before consolidation but keep it visible in the percept (detail.fallback==true).
    try:
        return bool(json.loads(av_issue.detail_json).get("fallback"))
    except (json.JSONDecodeError, TypeError, AttributeError):
        return False


def from_agentvision(av_report, *, sense: str = "sight", agent_id: str = "", artifact_id: str = "",
                     cost_usd: float = 0.0) -> SightResult:
    """Map a real `agentvision.models.report.Report` into the Verel verdict-bus contract.

    Pure function over the AgentVision object — no rendering, no I/O.
    """
    locator_of = {}
    verel_issues_by_grader: dict[GraderKind, list[Issue]] = {}
    observations: list[Observation] = []

    for av in av_report.issues:
        source = _SOURCE_TO_GRADER.get(str(getattr(av.source, "value", av.source)), GraderKind.CV)
        bbox = getattr(av, "bbox", None)
        locator = None
        if bbox is not None:
            if hasattr(bbox, "model_dump"):
                locator = json.dumps(bbox.model_dump(), default=str)
            elif hasattr(bbox, "__dict__"):
                locator = json.dumps(vars(bbox), default=str)
        issue = Issue(
            kind=IssueKind(str(getattr(av.kind, "value", av.kind))),
            severity=_sev(av.severity),
            message=av.message,
            locator=locator,
            locator_precise=bool(getattr(av, "bbox_precise", False)),
            confidence=_conf(getattr(av.confidence, "value", av.confidence)),
            source=source,
            detail_json=getattr(av, "detail_json", "{}"),
        )
        issue.fingerprint = compute_fp(issue)
        locator_of[issue.fingerprint] = locator

        observations.append(
            Observation(
                kind=issue.kind,
                severity=issue.severity,
                message=issue.message,
                locator=issue.locator,
                locator_precise=issue.locator_precise,
                confidence=issue.confidence,
                source=issue.source,
                fingerprint=issue.fingerprint,
            )
        )
        # synthetic-fallback issue is kept in the percept but not gated into a report.
        if _is_synthetic_fallback(av):
            continue
        verel_issues_by_grader.setdefault(source, []).append(issue)

    caps = [IssueKind(str(getattr(k, "value", k))) for k in getattr(av_report, "capabilities", [])]
    backend = getattr(av_report, "backend", "unknown")
    model = getattr(av_report, "model", None)
    elapsed = int(getattr(av_report, "elapsed_ms", 0))

    reports: list[Report] = []
    for grader, issues in verel_issues_by_grader.items():
        reports.append(
            Report(
                verdict=_report_verdict(issues),
                summary=av_report.summary,
                issues=issues,
                capabilities=caps,
                grader=grader,
                model=model or backend,  # provenance only — NEVER an input to trust
                cost_usd=cost_usd if grader == GraderKind.VISION else 0.0,
                elapsed_ms=elapsed,
                errored=False,
            )
        )
    if not reports:
        # No gating issues but the sense still ran: emit a clean DOM report so the gate sees
        # a present, non-errored perception grader (absence-of-issue != absence-of-grader).
        reports.append(
            Report(verdict=Verdict.PASS, summary=av_report.summary, capabilities=caps,
                   grader=GraderKind.DOM, model=model or backend, elapsed_ms=elapsed)
        )

    vp = getattr(av_report, "viewport", None)
    matches_intent, intent_satisfied, intent_total = _conformance(av_report)
    playing, live, stabilized = _temporal(av_report)
    percept = Percept(
        sense=sense,
        verdict=_verdict(getattr(av_report.verdict, "value", av_report.verdict)),
        summary=av_report.summary,
        observations=observations,
        signature=[[o.kind.value, o.fingerprint] for o in observations],
        agent_id=agent_id,
        artifact_id=artifact_id,
        image_path=getattr(av_report, "image_path", None),
        device_scale=getattr(av_report, "device_scale", None),
        viewport=str(vp) if vp is not None else None,
        matches_intent=matches_intent,
        intent_satisfied=intent_satisfied,
        intent_total=intent_total,
        playing=playing,
        live=live,
        stabilized=stabilized,
    )
    return SightResult(reports=reports, percept=percept, raw=av_report)


def _temporal(av_report) -> tuple[bool | None, bool | None, bool | None]:
    """Extract the temporal signal a `watch` capture rides on an issue's detail; else Nones."""
    for av in getattr(av_report, "issues", []):
        try:
            t = json.loads(getattr(av, "detail_json", "{}") or "{}").get("temporal")
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
        if isinstance(t, dict):
            vids = t.get("videos") or []
            playing = any(v.get("playing") for v in vids) if vids else None
            return playing, bool(t.get("moving")), bool(t.get("stabilized"))
    return None, None, None


def _conformance(av_report) -> tuple[bool | None, int | None, int | None]:
    """Extract intent-conformance facts from an AgentVision Report (None when no brief)."""
    conf = getattr(av_report, "conformance", None)
    if conf is None or not getattr(conf, "claims", None):
        return None, None, None
    try:
        matches = bool(conf.matches_intent())
        return matches, int(conf.satisfied), int(conf.total)
    except (AttributeError, TypeError, ValueError):
        return None, None, None


def _sev(av_sev):
    from ..verdict.models import Severity

    return Severity(str(getattr(av_sev, "value", av_sev)))


def _report_verdict(issues: list[Issue]) -> Verdict:
    from ..verdict.constants import GATING_SEVERITY, SEV_ORDER
    from ..verdict.models import Severity

    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    if any(SEV_ORDER.index(i.severity) >= gate_idx for i in issues):
        return Verdict.FAIL
    if any(i.severity == Severity.WARNING for i in issues):
        return Verdict.WARN
    return Verdict.PASS


async def perceive(source: str, *, backend: str = "local", agent_id: str = "",
                   full_page: bool = True, **analyze_kwargs) -> SightResult:
    """Render + analyze `source` through AgentVision, return the Verel SightResult.

    Thin wrapper over `agentvision.analyze(...)`. Requires `verel[sight]`.
    """
    from agentvision import analyze, load_settings

    settings = load_settings(vision_backend=backend)
    av_report = await analyze(source, settings=settings, full_page=full_page, **analyze_kwargs)
    return from_agentvision(av_report, agent_id=agent_id, artifact_id=source)


async def watch(source: str, *, backend: str = "local", agent_id: str = "",
                **watch_kwargs) -> SightResult:
    """Temporal perception — watch `source` OVER TIME (playback / loading / liveness).

    Thin wrapper over `agentvision.watch(...)`; returns the same Verel SightResult so the
    verdict bus and brain consume it like any other sense. A deterministic stall (video not
    advancing) gates to FAIL; the temporal vision findings are advisory/clamped. The percept
    carries `playing`/`live`/`stabilized` so the brain can compound "playback verified".
    Requires `verel[sight]`.
    """
    from agentvision import load_settings
    from agentvision.core import watch as av_watch

    settings = load_settings(vision_backend=backend)
    av_report = await av_watch(source, settings=settings, **watch_kwargs)
    return from_agentvision(av_report, agent_id=agent_id, artifact_id=source)
