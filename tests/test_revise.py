"""Contradiction-driven schema revision (§5.5) — weaken, split, reject. Offline (stub chat)."""

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    Trust,
    contradicts,
    revise_with_counterexample,
)
from verel.memory.view import make_key

SPLIT = ('{"narrowed":{"condition":"fixed width on a static card","action":"use max-width:100%",'
         '"applies_to":"static cards"},'
         '"exception":{"subject":"flex cards","condition":"fixed width in a flex row",'
         '"action":"use min-width:0","applies_to":"flex layouts"}}')


def _rule(subj="cards", kind="overflow", ec=0.7, scope="repo:x"):
    return MemoryRecord(
        kind=MemoryKind.DESIGN_RULE, subject=subj, predicate="design_rule",
        text="fixed width → use max-width", scope=scope, epistemic_confidence=ec,
        trust=Trust.CANDIDATE, subj_pred_key=make_key(subj, "design_rule", scope),
    ).with_detail(covers_kind=kind, condition="fixed width", action="use max-width", applies_to="all")


def _fail(text, kind, scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FAILURE, subject=text[:8], predicate="f", text=text,
                        scope=scope, subj_pred_key=make_key(text, "f", scope)).with_detail(kind=kind)


# ---- contradicts ----
def test_contradicts_matches_domain_only():
    r = _rule()
    assert contradicts(r, _fail("new overflow", "overflow"))
    assert not contradicts(r, _fail("contrast", "contrast"))
    assert not contradicts(r, MemoryRecord(kind=MemoryKind.FAILURE, text="no kind"))


# ---- annotate (no corroboration) ----
def test_annotate_does_not_change_confidence():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.6))
    mem.annotate(r.id, counterexamples=[{"id": "x", "text": "t"}])
    got = mem.get(r.id)
    assert got.epistemic_confidence == 0.6 and got.detail["counterexamples"] == [{"id": "x", "text": "t"}]


# ---- weaken / split / reject ----
def test_first_counterexample_weakens_without_split():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.7))
    rev = revise_with_counterexample(mem, mem.get(r.id), _fail("o1", "overflow"),
                                     chat=lambda _m: SPLIT, contradiction_delta=0.2, split_after=2)
    assert rev.action == "weakened" and rev.confidence < 0.7 and rev.narrowed is None


def test_split_narrows_original_and_adds_exception():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.7))
    revise_with_counterexample(mem, mem.get(r.id), _fail("o1", "overflow"), chat=lambda _m: SPLIT, split_after=2)
    rev = revise_with_counterexample(mem, mem.get(r.id), _fail("o2", "overflow"), chat=lambda _m: SPLIT, split_after=2)
    assert rev.action == "split"
    # narrowed SUPERSEDES the original (same id) and carries a correction chain
    assert rev.narrowed.id == r.id and rev.narrowed.detail["applies_to"] == "static cards"
    assert rev.narrowed.detail["revision"] == "narrowed" and rev.narrowed.detail["corrections"]
    # exception is a NEW candidate rule with its own key
    assert rev.exception.id != r.id and rev.exception.detail["exception_of"] == r.id
    assert rev.narrowed.trust == Trust.CANDIDATE and rev.exception.trust == Trust.CANDIDATE


def test_collapsing_confidence_rejects_the_rule():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.25))  # already weak
    rev = revise_with_counterexample(mem, mem.get(r.id), _fail("o1", "overflow"),
                                     chat=lambda _m: SPLIT, contradiction_delta=0.2, split_after=99)
    assert rev.action == "rejected" and rev.trust == Trust.REJECTED.value
    assert mem.get(r.id).trust == Trust.REJECTED


def test_unparseable_split_falls_back_to_weakened():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.9))
    revise_with_counterexample(mem, mem.get(r.id), _fail("o1", "overflow"), chat=lambda _m: "junk", split_after=2)
    rev = revise_with_counterexample(mem, mem.get(r.id), _fail("o2", "overflow"), chat=lambda _m: "still junk", split_after=2)
    assert rev.action == "weakened" and rev.narrowed is None  # no split written on bad LLM output
