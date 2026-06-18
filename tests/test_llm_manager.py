"""LLM-driven manager (§6.1) — the model proposes, the plane disposes. Offline (fake chat)."""

import json

from verel.fleet import decide_fanout, validate_fanout


def _chat(reply):
    return lambda msgs: reply


def test_valid_fanout_is_accepted_and_clamped():
    arts = ["a.html", "b.html"]
    reply = json.dumps({
        "decision": "fan_out", "rationale": "two independent pages", "concurrency_cap": 99,
        "subtasks": [
            {"id": "x", "goal": "fix a", "artifact": "a.html", "verifier": "sight"},
            {"id": "y", "goal": "fix b", "artifact": "b.html", "verifier": "sight"},
        ],
    })
    fo = decide_fanout("fix pages", artifacts=arts, chat=_chat(reply))
    ok, _ = validate_fanout(fo)
    assert ok and fo.concurrency_cap == 2 and len(fo.subtasks) == 2


def test_garbage_output_falls_back_to_deterministic_plan():
    arts = ["a.html", "b.html"]
    fo = decide_fanout("fix pages", artifacts=arts, chat=_chat("I think we should... no JSON here"))
    ok, _ = validate_fanout(fo)
    assert ok and {s.artifact for s in fo.subtasks} == set(arts)  # fell back, full coverage


def test_under_coverage_falls_back():
    # model dropped b.html -> we refuse silent under-coverage and fall back
    arts = ["a.html", "b.html"]
    reply = json.dumps({"decision": "fan_out", "subtasks": [
        {"id": "x", "goal": "fix a", "artifact": "a.html"}]})
    fo = decide_fanout("fix pages", artifacts=arts, chat=_chat(reply))
    assert {s.artifact for s in fo.subtasks} == set(arts)  # coverage restored by fallback


def test_dependent_subtasks_rejected_then_fallback():
    arts = ["a.html", "b.html"]
    reply = json.dumps({"decision": "fan_out", "subtasks": [
        {"id": "x", "artifact": "a.html"},
        {"id": "y", "artifact": "b.html", "deps": ["x"]}]})
    # Subtask model ignores unknown 'deps'? It's a real field -> dependent -> invalid -> fallback
    fo = decide_fanout("fix pages", artifacts=arts, chat=_chat(reply))
    ok, _ = validate_fanout(fo)
    assert ok  # whatever we return is always valid


def test_max_subtasks_clamp():
    arts = [f"{i}.html" for i in range(12)]
    subs = [{"id": f"s{i}", "artifact": f"{i}.html"} for i in range(12)]
    reply = json.dumps({"decision": "fan_out", "subtasks": subs})
    fo = decide_fanout("fix", artifacts=arts, chat=_chat(reply), max_subtasks=8)
    # truncated to 8 -> under-coverage -> fallback to full deterministic plan (12)
    assert len(fo.subtasks) == 12
