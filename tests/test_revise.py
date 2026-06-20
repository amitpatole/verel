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


# ---- schema-split propagation up the hierarchy ----
def _schema(subj, text, order, subsumes, scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.SCHEMA, subject=subj, predicate="schema", text=text,
                        scope=scope, trust=Trust.CANDIDATE, epistemic_confidence=0.6,
                        subj_pred_key=make_key(subj, "schema", scope)).with_detail(
        grounding="schema", order=order, subsumes=subsumes)


def _both_chat(messages):
    if "NARROWED" in messages[0]["content"]:
        return SPLIT
    u = messages[1]["content"]
    return ('{"subject":"x","principle":"REVISED meta-principle"}' if "layout-principle" in u
            else '{"subject":"x","principle":"REVISED principle"}')


def test_split_propagates_and_rederives_subsuming_schemas():
    mem = LocalMemory()
    r = mem.write(_rule(ec=0.7))
    s2 = mem.write(_schema("layout-principle", "all cards fit any viewport", 2, [r.id]))
    s3 = mem.write(_schema("ui-meta", "the ui is perceivable", 3, [s2.id]))
    revise_with_counterexample(mem, mem.get(r.id), _fail("o1", "overflow"), chat=_both_chat, split_after=2)
    rev = revise_with_counterexample(mem, mem.get(r.id), _fail("o2", "overflow"), chat=_both_chat, split_after=2)
    assert rev.action == "split" and len(rev.propagated) == 2  # both levels re-derived
    # order-2 schema re-derived from the NARROWED rule, reset to candidate, flagged
    g2 = mem.get(s2.id)
    assert g2.text == "REVISED principle" and g2.detail["revised"] and g2.detail["revised_due_to"] == r.id
    assert g2.epistemic_confidence == 0.5 and g2.trust == Trust.CANDIDATE
    # order-3 meta-schema re-derived too (propagation climbed the hierarchy)
    assert mem.get(s3.id).text == "REVISED meta-principle" and mem.get(s3.id).detail["revised"]


def test_propagation_is_a_noop_without_subsuming_schemas():
    from verel.memory import propagate_revision
    mem = LocalMemory()
    r = mem.write(_rule())
    assert propagate_revision(mem, r.id, chat=_both_chat) == []


def test_propagation_contradicts_a_schema_it_cannot_rederive():
    from verel.memory import propagate_revision
    mem = LocalMemory()
    r = mem.write(_rule())
    s2 = mem.write(_schema("p", "principle", 2, [r.id]))
    before = mem.get(s2.id).epistemic_confidence
    propagate_revision(mem, r.id, chat=lambda _m: "garbage")  # can't re-derive
    assert mem.get(s2.id).epistemic_confidence < before  # weakened instead of left over-claiming


def test_propagation_leaves_unrelated_schemas_untouched():
    from verel.memory import propagate_revision
    mem = LocalMemory()
    r = mem.write(_rule())
    other = mem.write(_schema("unrelated", "something else", 2, ["some-other-id"]))
    propagate_revision(mem, r.id, chat=_both_chat)
    assert mem.get(other.id).text == "something else" and not mem.get(other.id).detail.get("revised")
