"""The NEW bi-temporal surface (the core valid_from/valid_to + recall_as_of engine is pinned in
test_memory_bitemporal.py): valid-time CAPTURE at extraction, the set-valued `members_as_of` query,
the `source_prior` belief prior — the "who was admin THEN vs who is owner NOW" work — plus the
security cadence around them (untrusted content must not plant a hostile interval, launder a rejected
value through time travel, or move belief it has no authority over)."""

from __future__ import annotations

import json

from memory_contract import make_fact

from verel.memory import (
    LocalMemory,
    members_as_of,
    parse_extracted_facts,
    parse_when,
    recall_as_of,
    remember_conversation,
)
from verel.memory.view import Trust

T0, T1, T2 = 1_000_000.0, 2_000_000.0, 3_000_000.0  # epoch anchors inside parse_when's window


def _chat(facts):
    def chat(_messages):
        return json.dumps(facts)
    return chat


# --- parse_when: the fail-safe ingest-side time parser ----------------------------

def test_parse_when_iso_and_epoch():
    assert parse_when("2024-01-03") == parse_when("2024-01-03T00:00:00Z")
    assert parse_when(1_700_000_000) == 1_700_000_000.0
    assert parse_when("2024-06-01T12:30:00+00:00") is not None


def test_parse_when_rejects_hostile_bounds():
    for bad in (float("inf"), float("-inf"), float("nan"), -1, 10**12, "9999-99-99",
                "not-a-date", "", "x" * 100, True, None, {"a": 1}):
        assert parse_when(bad) is None, f"{bad!r} must not parse to an instant"


# --- Phase 1: valid-time CAPTURE at extraction ------------------------------------

def test_extraction_captures_stated_valid_time():
    recs = parse_extracted_facts(json.dumps([
        {"subject": "alice", "predicate": "role", "object": "admin",
         "valid_from": "2024-01-03", "valid_to": "2024-06-01"}]), scope="repo:x")
    assert len(recs) == 1
    r = recs[0]
    assert r.valid_from == parse_when("2024-01-03")
    assert r.valid_to == parse_when("2024-06-01") > r.valid_from


def test_extraction_omits_valid_time_when_unstated():
    recs = parse_extracted_facts(json.dumps([
        {"subject": "x", "predicate": "likes", "object": "tea"}]), scope="repo:x")
    assert recs and recs[0].valid_from == 0.0 and recs[0].valid_to == 0.0  # → defaults to created_ts


def test_recall_as_of_then_vs_now_end_to_end():
    m = LocalMemory(":memory:")
    m.write(make_fact(text="us-east", subject="svc", predicate="region"), ts=T0)
    m.write(make_fact(text="us-west", subject="svc", predicate="region"), ts=T1)
    then = recall_as_of(m, "svc region", as_of=(T0 + T1) / 2, scope="repo:x")
    now = recall_as_of(m, "svc region", as_of=T2, scope="repo:x")
    assert then and then[0].text == "us-east"   # what was true THEN
    assert now and now[0].text == "us-west"      # what is true NOW


# --- Phase 2: set-membership as-of (who was admin THEN) ----------------------------

def _seed_roles(m: LocalMemory) -> None:
    m.write(make_fact(text="admin", subject="alice", predicate="role"), ts=T0)    # admin from T0
    m.write(make_fact(text="member", subject="alice", predicate="role"), ts=T1)   # demoted at T1
    m.write(make_fact(text="owner", subject="bob", predicate="role"), ts=T0)  # owner throughout


def test_members_as_of_distinguishes_then_from_now():
    m = LocalMemory(":memory:")
    _seed_roles(m)
    admins_then = members_as_of(m, predicate="role", value="admin", as_of=(T0 + T1) / 2, scope="repo:x")
    admins_now = members_as_of(m, predicate="role", value="admin", as_of=T2, scope="repo:x")
    assert [r.subject for r in admins_then] == ["alice"]     # alice WAS admin then
    assert admins_now == []                                   # nobody is admin now
    owners_now = members_as_of(m, predicate="role", value="owner", as_of=T2, scope="repo:x")
    assert [r.subject for r in owners_now] == ["bob"]     # .bob is the current owner


def test_members_as_of_without_value_lists_all_holders():
    m = LocalMemory(":memory:")
    _seed_roles(m)
    now = members_as_of(m, predicate="role", as_of=T2, scope="repo:x")
    assert {(r.subject, r.text) for r in now} == {("alice", "member"), ("bob", "owner")}


def test_members_as_of_scope_isolation():
    m = LocalMemory(":memory:")
    m.write(make_fact(text="admin", subject="a", predicate="role", scope="repo:x"), ts=T0)
    m.write(make_fact(text="admin", subject="b", predicate="role", scope="repo:y"), ts=T0)
    only_x = members_as_of(m, predicate="role", value="admin", as_of=T1, scope="repo:x")
    assert [r.subject for r in only_x] == ["a"]  # a scoped query does not leak another scope


# --- Phase 3: source-typed confidence prior ---------------------------------------

def test_source_prior_seeds_initial_confidence():
    item = [{"subject": "s", "predicate": "p", "object": "o"}]
    hi = parse_extracted_facts(json.dumps(item), scope="repo:x", source_prior=0.9)
    lo = parse_extracted_facts(json.dumps(item), scope="repo:x", source_prior=0.1)
    assert hi[0].epistemic_confidence == 0.9
    assert lo[0].epistemic_confidence == 0.1


def test_source_prior_clamped_and_default():
    item = [{"subject": "s", "predicate": "p", "object": "o"}]
    over = parse_extracted_facts(json.dumps(item), scope="repo:x", source_prior=9.0)
    dflt = parse_extracted_facts(json.dumps(item), scope="repo:x")
    assert over[0].epistemic_confidence == 1.0        # clamped into [0,1]
    assert dflt[0].epistemic_confidence == 0.5        # None = the unchanged 0.5 prior


def test_source_prior_does_not_grant_trust_tier():
    m = LocalMemory(":memory:")
    res = remember_conversation(m, "t", scope="repo:x",
                                chat=_chat([{"subject": "s", "predicate": "p", "object": "o"}]),
                                source_prior=1.0)   # max prior, but no attest / no authenticator
    assert res.candidate and not res.promoted        # a high prior is NOT verification
    assert res.candidate[0].trust == Trust.CANDIDATE


# --- Security cadence: adversarial pins over the NEW surface -----------------------

def test_sec_hostile_valid_time_in_content_is_dropped():
    """R1: a transcript that plants valid_from=+inf / valid_to='forever' / a pre-epoch bound must not
    reach the store — parse_when refuses it, so the field falls back to the safe default (0.0)."""
    recs = parse_extracted_facts(json.dumps([
        {"subject": "x", "predicate": "y", "object": "z",
         "valid_from": "inf", "valid_to": 9e18}]), scope="repo:x")
    assert recs and recs[0].valid_from == 0.0 and recs[0].valid_to == 0.0


def test_sec_inverted_interval_drops_valid_to():
    """R1b: valid_to <= valid_from is an inverted/empty interval, not a supersession signal — the
    end bound is discarded (treated as open) rather than stored as a hostile zero/negative window."""
    recs = parse_extracted_facts(json.dumps([
        {"subject": "x", "predicate": "y", "object": "z",
         "valid_from": "2024-06-01", "valid_to": "2024-01-01"}]), scope="repo:x")
    assert recs and recs[0].valid_to == 0.0 and recs[0].valid_from == parse_when("2024-06-01")


def test_sec_members_as_of_is_ledger_aware():
    """R2: a role value graded false (REJECTED) must never be resurfaced by a membership query, even
    for a historical as_of — the same anti-laundering property recall_as_of has."""
    m = LocalMemory(":memory:")
    r = m.write(make_fact(text="admin", subject="mallory", predicate="role"), ts=T0)
    for _ in range(6):
        m.contradict(r.id)
    assert m.get(r.id).trust == Trust.REJECTED
    assert members_as_of(m, predicate="role", value="admin", as_of=T2, scope="repo:x") == []


def test_sec_members_as_of_no_launder_after_supersede():
    """R2b (the round-15/F1 analog for set-membership): a role value graded false then SUPERSEDED by a
    benign correction must not be resurfaced by a historical membership query — members_as_of is
    ledger-aware on the reconstructed snapshot, not just the current record's trust."""
    m = LocalMemory(":memory:")
    r = m.write(make_fact(text="superadmin", subject="mallory", predicate="role"), ts=T0)
    for _ in range(6):
        m.contradict(r.id)
    m.write(make_fact(text="guest", subject="mallory", predicate="role"), ts=T1)  # benign correction
    assert m.get(r.id).trust == Trust.CANDIDATE  # current value is a benign candidate
    # querying at the instant the LIE was "valid" must still find nobody
    assert members_as_of(m, predicate="role", value="superadmin",
                         as_of=(T0 + T1) / 2, scope="repo:x") == []


def test_sec_valid_time_does_not_move_belief():
    """R3: valid-time is a positioning hint, never a trust signal. A stated interval must not raise
    epistemic_confidence off its prior, and the item's self-reported 'confidence' must stay a hint
    (salience), never become belief."""
    recs = parse_extracted_facts(json.dumps([
        {"subject": "x", "predicate": "y", "object": "z", "confidence": 0.99,
         "valid_from": "2024-01-01", "valid_to": "2024-12-31"}]), scope="repo:x")
    r = recs[0]
    assert r.epistemic_confidence == 0.5                       # unmoved by content
    assert r.detail.get("salience_hint") == 0.99              # kept as a hint only
