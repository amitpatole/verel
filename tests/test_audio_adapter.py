"""Hearing adapter (§8.3): grader identity keys off Issue.source (not Report.backend), fingerprints
are computed, advisory acoustic/audio_llm issues clamp at the gate, time-grounding survives, the
synthetic-fallback issue is kept in the percept but excluded from gating reports, and a `watch`
result carries the liveness signal. Mirror of test_sight_adapter.py for the ears."""

import json
from types import SimpleNamespace

from verel.senses.audio import _SOURCE_TO_GRADER, from_audel
from verel.verdict import GraderKind, IssueKind, Verdict, gate

# The full audel.models.IssueKind / IssueSource wire values (kept in lockstep with the ears package).
# A drift guard: every kind the adapter might construct must exist in Verel's IssueKind, else
# from_audel() would raise ValueError mid-map. CLIPPING ("clipping") is distinct from vision CLIPPED.
_AUDEL_ISSUE_KINDS = [
    "silence", "clipping", "loudness", "truncation", "dropout", "decode_error", "missing_audio",
    "desync", "transcript_mismatch", "wrong_language", "noise", "channel_issue", "duration",
    "intent_mismatch", "other",
]
_AUDEL_ISSUE_SOURCES = ["dsp", "asr", "acoustic", "audio_llm"]


def _span(start_ms=0, end_ms=500):
    return SimpleNamespace(start_ms=start_ms, end_ms=end_ms, duration_ms=end_ms - start_ms)


def _au_issue(kind, severity, source, *, message="m", confidence="high", span=None, detail=None):
    return SimpleNamespace(
        kind=kind, severity=severity, source=source, message=message, confidence=confidence,
        span=span if span is not None else _span(), detail_json=json.dumps(detail or {}),
    )


def _au_report(issues, *, verdict="fail", backend="ollama", capabilities=None):
    return SimpleNamespace(
        verdict=verdict, summary="s", issues=issues, capabilities=capabilities or [],
        backend=backend, model="gemma4:31b", elapsed_ms=42, audio_path="/tmp/x.wav",
    )


def test_grader_keys_off_source_not_backend():
    # backend is "ollama" but the issue source is dsp -> grader must be DSP (precise), not audio_llm.
    au = _au_report([_au_issue("clipping", "error", "dsp")], backend="ollama")
    res = from_audel(au)
    graders = {r.grader for r in res.reports}
    assert GraderKind.DSP in graders and GraderKind.AUDIO_LLM not in graders
    # a DSP ERROR must gate to FAIL (precise source is NOT clamped despite the ollama backend)
    assert gate(res.reports).verdict == Verdict.FAIL


def test_audio_llm_source_is_advisory_and_clamped():
    au = _au_report([_au_issue("noise", "critical", "audio_llm")], backend="ollama")
    res = from_audel(au)
    assert gate(res.reports).verdict == Verdict.WARN  # audio_llm CRITICAL cannot exceed WARN


def test_acoustic_source_is_advisory_and_clamped():
    au = _au_report([_au_issue("other", "critical", "acoustic")])
    res = from_audel(au)
    assert gate(res.reports).verdict == Verdict.WARN  # CLAP zero-shot is advisory


def test_asr_source_is_precise_and_gates():
    # a wrong-language finding from ASR is deterministic grounding -> gates to FAIL.
    au = _au_report([_au_issue("wrong_language", "error", "asr",
                               message="expected en, heard fr")])
    res = from_audel(au)
    assert GraderKind.ASR in {r.grader for r in res.reports}
    assert gate(res.reports).verdict == Verdict.FAIL


def test_fingerprints_are_computed_and_sense_is_hearing():
    au = _au_report([_au_issue("clipping", "error", "dsp"),
                     _au_issue("loudness", "warning", "dsp")])
    res = from_audel(au)
    assert all(o.fingerprint for o in res.percept.observations)
    assert res.percept.sense == "hearing"


def test_issue_is_time_grounded_not_pixel_grounded():
    au = _au_report([_au_issue("silence", "critical", "dsp", span=_span(1000, 2500))])
    res = from_audel(au)
    issue = next(i for r in res.reports for i in r.issues)
    assert issue.locator_precise  # dsp + span -> precise grounding
    loc = json.loads(issue.locator)
    assert loc["start_ms"] == 1000 and loc["end_ms"] == 2500


def test_synthetic_fallback_issue_excluded_from_gating_reports():
    au = _au_report([_au_issue("other", "warning", "audio_llm", detail={"fallback": True})])
    res = from_audel(au)
    assert any(o.kind.value == "other" for o in res.percept.observations)  # kept for provenance
    gated = [i for r in res.reports for i in r.issues]
    assert all(i.detail.get("fallback") is not True for i in gated)


def test_intent_mismatch_flows_through_without_breaking():
    au = _au_report([_au_issue("intent_mismatch", "error", "audio_llm",
                               message="[#1] the VO never says the product name")])
    res = from_audel(au)
    assert any(o.kind.value == "intent_mismatch" for o in res.percept.observations)
    assert gate(res.reports).verdict == Verdict.WARN  # audio_llm-sourced -> advisory


def test_conformance_facts_captured_in_percept():
    conf = SimpleNamespace(claims=[1, 2, 3], matches_intent=lambda: False, satisfied=2, total=3)
    au = _au_report([_au_issue("transcript_mismatch", "error", "asr",
                               message="[#3] required phrase not spoken")])
    au.conformance = conf
    res = from_audel(au)
    assert res.percept.matches_intent is False
    assert res.percept.intent_satisfied == 2 and res.percept.intent_total == 3


def test_no_brief_means_no_conformance_facts():
    au = _au_report([_au_issue("clipping", "error", "dsp")])
    res = from_audel(au)  # no `conformance` attribute on the report
    assert res.percept.matches_intent is None and res.percept.intent_total is None


def test_watch_liveness_signal_reaches_the_percept():
    # a clean watch() result (no dead air, no interruption) -> playback verified.
    au = _au_report([], verdict="pass")
    res = from_audel(au, temporal=True)
    assert res.percept.playing is True and res.percept.live is True
    assert res.percept.stabilized is True


def test_dead_air_clears_playing_flag():
    au = _au_report([_au_issue("silence", "critical", "dsp",
                               message="audio is silent for the whole playback")])
    res = from_audel(au, temporal=True)
    assert res.percept.playing is False and res.percept.stabilized is True  # silent, not interrupted
    # dsp critical -> gates to FAIL (silent-though-it-"plays")
    assert gate(res.reports).verdict == Verdict.FAIL


def test_dropout_clears_stabilized_flag():
    au = _au_report([_au_issue("dropout", "error", "dsp", span=_span(800, 1000))])
    res = from_audel(au, temporal=True)
    assert res.percept.playing is True and res.percept.stabilized is False


def test_perceive_glance_has_no_temporal_signal():
    au = _au_report([_au_issue("clipping", "error", "dsp")])
    res = from_audel(au)  # temporal defaults False (a single analyze glance)
    assert res.percept.playing is None and res.percept.stabilized is None


def test_every_audel_issue_kind_maps_to_a_verel_issue_kind():
    # Round 2 drift guard: from_audel does IssueKind(value); an unmirrored kind would crash the map.
    for value in _AUDEL_ISSUE_KINDS:
        assert IssueKind(value).value == value
    assert IssueKind("clipping") is not IssueKind("clipped")  # audio overload != off-canvas


def test_every_audel_source_maps_to_a_grader():
    for value in _AUDEL_ISSUE_SOURCES:
        assert value in _SOURCE_TO_GRADER
    # the two untrusted (model-judged) sources are advisory; the two deterministic ones are precise.
    from verel.verdict.constants import ADVISORY_GRADERS, PRECISE_GRADERS
    assert _SOURCE_TO_GRADER["acoustic"] in ADVISORY_GRADERS
    assert _SOURCE_TO_GRADER["audio_llm"] in ADVISORY_GRADERS
    assert _SOURCE_TO_GRADER["dsp"] in PRECISE_GRADERS
    assert _SOURCE_TO_GRADER["asr"] in PRECISE_GRADERS


def test_adapter_never_forges_an_attestation_receipt():
    # Round 3: the pure adapter must NOT mint a RunReceipt — that would let an UNSIGNED hearing
    # grader satisfy Verel's `required` set. Receipts are minted by the runner/gate, never here.
    au = _au_report([_au_issue("clipping", "error", "dsp")])
    res = from_audel(au)
    assert all(r.run_receipt is None for r in res.reports)


def test_mixed_sources_split_into_separate_reports():
    au = _au_report([
        _au_issue("clipping", "error", "dsp"),
        _au_issue("noise", "critical", "audio_llm"),
        _au_issue("wrong_language", "warning", "asr"),
    ])
    res = from_audel(au)
    graders = {r.grader for r in res.reports}
    assert {GraderKind.DSP, GraderKind.AUDIO_LLM, GraderKind.ASR} <= graders
    # net verdict: DSP error gates to FAIL even though audio_llm is clamped
    assert gate(res.reports).verdict == Verdict.FAIL
