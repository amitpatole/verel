"""Sight adapter (§8.3): grader identity keys off Issue.source (not Report.backend),
fingerprints are computed, advisory vision issues clamp at the gate, the synthetic-fallback
issue is kept in the percept but excluded from gating reports."""

import json
from types import SimpleNamespace

from verel.senses.sight import from_agentvision
from verel.verdict import GraderKind, Verdict, gate


def _av_issue(kind, severity, source, *, message="m", confidence="medium", bbox_precise=False,
              detail=None):
    return SimpleNamespace(
        kind=kind, severity=severity, source=source, message=message, confidence=confidence,
        bbox=None, bbox_precise=bbox_precise, detail_json=json.dumps(detail or {}),
    )


def _av_report(issues, *, verdict="fail", backend="anthropic", capabilities=None):
    return SimpleNamespace(
        verdict=verdict, summary="s", issues=issues, capabilities=capabilities or [],
        backend=backend, model="claude-haiku-4-5", viewport=SimpleNamespace(width=1280, height=800),
        device_scale=1.0, image_path="/tmp/x.png", elapsed_ms=42,
    )


def test_grader_keys_off_source_not_backend():
    # backend is "anthropic" but the issue source is dom -> grader must be DOM (precise), not vision.
    av = _av_report([_av_issue("overflow", "error", "dom")], backend="anthropic")
    res = from_agentvision(av)
    graders = {r.grader for r in res.reports}
    assert GraderKind.DOM in graders
    assert GraderKind.VISION not in graders
    # a DOM ERROR must gate to FAIL (precise source is NOT clamped despite anthropic backend)
    assert gate(res.reports).verdict == Verdict.FAIL


def test_vision_source_is_advisory_and_clamped():
    av = _av_report([_av_issue("layout", "critical", "vision")], backend="anthropic")
    res = from_agentvision(av)
    assert gate(res.reports).verdict == Verdict.WARN  # vision CRITICAL cannot exceed WARN


def test_fingerprints_are_computed_on_every_observation():
    av = _av_report([_av_issue("overflow", "error", "dom"),
                     _av_issue("contrast", "warning", "dom")])
    res = from_agentvision(av)
    assert all(o.fingerprint for o in res.percept.observations)
    assert res.percept.sense == "sight"


def test_synthetic_fallback_issue_excluded_from_gating_reports():
    av = _av_report([_av_issue("other", "warning", "cv", detail={"fallback": True})])
    res = from_agentvision(av)
    # kept in the percept for provenance...
    assert any(o.kind.value == "other" for o in res.percept.observations)
    # ...but not gated: the synthetic issue does not appear in any report's issues
    gated = [i for r in res.reports for i in r.issues]
    assert all(i.detail.get("fallback") is not True for i in gated)


def test_mixed_sources_split_into_separate_reports():
    av = _av_report([
        _av_issue("overflow", "error", "dom"),
        _av_issue("layout", "critical", "vision"),
        _av_issue("typo", "warning", "ocr"),
    ])
    res = from_agentvision(av)
    graders = {r.grader for r in res.reports}
    assert {GraderKind.DOM, GraderKind.VISION, GraderKind.OCR} <= graders
    # net verdict: DOM error gates to FAIL even though vision is clamped
    assert gate(res.reports).verdict == Verdict.FAIL
