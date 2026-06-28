"""Phase 1 of MEMORY-EXTRACTION-KICKOFF.md — the conversational fact extractor.

Acceptance: a transcript → candidate FACT records (SPO, scoped, content-addressed, deduped); the
parser FAILS CLOSED on hostile/garbage output; nothing is VERIFIED at extraction time."""

import json

from verel.memory import extract_facts, parse_extracted_facts
from verel.memory.view import MemoryKind, Trust, make_key


def _chat(payload):
    """A fake injected ChatFn that returns a canned JSON array (no API key, deterministic)."""
    return lambda _messages: json.dumps(payload)


def test_extracts_candidate_facts_from_transcript():
    transcript = [
        {"role": "user", "content": "I'm Dana, I lead the platform team and I prefer dark mode."},
        {"role": "assistant", "content": "Got it, Dana."},
    ]
    payload = [
        {"subject": "Dana", "predicate": "role", "object": "platform team lead"},
        {"subject": "Dana", "predicate": "prefers", "object": "dark mode"},
    ]
    recs = extract_facts(transcript, scope="user:dana", chat=_chat(payload), now=100.0)
    assert len(recs) == 2
    r = {x.predicate: x for x in recs}
    assert r["prefers"].text == "dark mode"
    # every extracted fact is a CANDIDATE FACT scoped + content-addressed — never trusted yet
    for x in recs:
        assert x.kind == MemoryKind.FACT
        assert x.trust == Trust.CANDIDATE
        assert x.scope == "user:dana"
        assert x.source == "extraction"
        assert x.subj_pred_key == make_key(x.subject, x.predicate, "user:dana")
        assert x.id  # content-addressed
        assert x.created_ts == 100.0


def test_string_transcript_also_works():
    recs = extract_facts("we standardized on Postgres for the prod DB", scope="repo:app",
                         chat=_chat([{"subject": "prod DB", "predicate": "engine", "object": "Postgres"}]))
    assert len(recs) == 1 and recs[0].text == "Postgres"


def test_dedup_by_subj_pred_key_last_wins():
    # the same (subject,predicate,scope) collapses to one identity; an in-conversation CORRECTION
    # supersedes (last statement wins) rather than being dropped.
    payload = [
        {"subject": "Dana", "predicate": "prefers", "object": "dark mode"},
        {"subject": "dana", "predicate": "Prefers", "object": "light mode"},  # same key, a correction
    ]
    recs = parse_extracted_facts(json.dumps(payload), scope="user:dana")
    assert len(recs) == 1 and recs[0].text == "light mode"  # the correction wins


def test_salience_hint_kept_but_does_not_move_belief():
    payload = [{"subject": "x", "predicate": "y", "object": "z", "confidence": 0.97}]
    recs = parse_extracted_facts(json.dumps(payload), scope="s")
    # the LLM's self-reported confidence is a hint in detail, NOT epistemic belief
    assert json.loads(recs[0].detail_json)["salience_hint"] == 0.97
    assert recs[0].epistemic_confidence == 0.5  # the prior — unmoved


def test_parser_fails_closed_on_hostile_input():
    # non-JSON, non-array, wrong element shapes, missing fields → [] (no crash, no partial write)
    for bad in ("not json", "{}", '"a string"', "123", "null",
                json.dumps(["x", 1, None, {}]),
                json.dumps([{"subject": "only"}, {"predicate": "p", "object": "o"}])):
        assert parse_extracted_facts(bad, scope="s") == []


def test_extractor_tolerates_a_failing_chat():
    def boom(_messages):
        raise RuntimeError("LLM unavailable")
    assert extract_facts("hello", scope="s", chat=boom) == []


def test_max_facts_cap():
    payload = [{"subject": f"s{i}", "predicate": "p", "object": "o"} for i in range(500)]
    recs = parse_extracted_facts(json.dumps(payload), scope="s")
    assert len(recs) <= 200  # DoS guard: a single conversation can't mint unbounded memories
