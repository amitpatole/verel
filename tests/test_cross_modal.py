"""Cross-modal acceptance (Phase 5): the brain ingests EYES (AgentVision) and EARS (Audel) into one
verdict. Both senses are pure adapters, so this runs without the optional sibling packages installed:
we build a sight result and a hearing result and feed BOTH report sets into a single `gate()` call —
the same reducer the loop uses — and assert the combined verdict gates "done" correctly.
"""

import json
from types import SimpleNamespace

from verel.senses.audio import from_audel
from verel.senses.sight import from_agentvision
from verel.verdict import Verdict, gate

# --- minimal mocks of the two sibling Reports (mirror each adapter's test doubles) ---

def _av_issue(kind, severity, source, **kw):
    return SimpleNamespace(kind=kind, severity=severity, source=source, message=kw.get("message", "m"),
                           confidence=kw.get("confidence", "high"), bbox=None,
                           bbox_precise=kw.get("bbox_precise", False),
                           detail_json=json.dumps(kw.get("detail", {})))


def _av_report(issues, verdict="pass"):
    return SimpleNamespace(verdict=verdict, summary="render", issues=issues, capabilities=[],
                           backend="local", model="local", viewport=SimpleNamespace(width=1280, height=800),
                           device_scale=1.0, image_path="/tmp/x.png", elapsed_ms=10)


def _au_issue(kind, severity, source, **kw):
    return SimpleNamespace(kind=kind, severity=severity, source=source, message=kw.get("message", "m"),
                           confidence=kw.get("confidence", "high"),
                           span=SimpleNamespace(start_ms=0, end_ms=500, duration_ms=500),
                           detail_json=json.dumps(kw.get("detail", {})))


def _au_report(issues, verdict="pass"):
    return SimpleNamespace(verdict=verdict, summary="audio", issues=issues, capabilities=[],
                           backend="dsp", model="dsp", elapsed_ms=10, audio_path="/tmp/x.wav")


def _combined(av_report, au_report, *, temporal=False):
    sight = from_agentvision(av_report)
    hearing = from_audel(au_report, temporal=temporal)
    return gate(sight.reports + hearing.reports), sight, hearing


def test_both_senses_clean_gate_to_done():
    # video renders (no vision issues) AND audio plays through (no dsp issues) -> combined PASS.
    g, sight, hearing = _combined(_av_report([]), _au_report([]))
    assert g.verdict == Verdict.PASS
    assert sight.percept.sense == "sight" and hearing.percept.sense == "hearing"


def test_silent_audio_fails_even_when_video_renders():
    # the headline case: the page LOOKS right but the audio is dead -> the brain must NOT say done.
    au = _au_report([_au_issue("silence", "critical", "dsp",
                               message="audio is silent for the whole playback")], verdict="fail")
    g, _, hearing = _combined(_av_report([]), au, temporal=True)
    assert g.verdict == Verdict.FAIL
    assert hearing.percept.playing is False  # ears report: it did not play through


def test_broken_layout_fails_even_when_audio_plays():
    # symmetric: audio is fine but the eyes see a precise DOM error -> combined FAIL.
    av = _av_report([_av_issue("overflow", "error", "dom")], verdict="fail")
    g, _, _ = _combined(av, _au_report([]))
    assert g.verdict == Verdict.FAIL


def test_advisory_audio_critique_cannot_override_a_clean_render():
    # a (possibly prompt-injected) audio_llm CRITICAL is advisory: it clamps to WARN, never FAIL,
    # so it cannot force a passing cross-modal result to fail outright.
    au = _au_report([_au_issue("noise", "critical", "audio_llm",
                               message="model claims everything is broken")], verdict="warn")
    g, _, _ = _combined(_av_report([]), au)
    assert g.verdict == Verdict.WARN  # surfaced for review, but not a hard FAIL


def test_both_senses_present_in_one_gate():
    # the gate sees graders from BOTH modalities in a single reduce.
    av = _av_report([_av_issue("overflow", "error", "dom")], verdict="fail")
    au = _au_report([_au_issue("clipping", "error", "dsp")], verdict="fail")
    _, sight, hearing = _combined(av, au)
    graders = {r.grader.value for r in sight.reports + hearing.reports}
    assert "dom" in graders and "dsp" in graders
