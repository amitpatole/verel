"""MemoryView trust layer + failure ledger + consolidation (§5, §7.5) — all offline."""

from verel.memory import (
    FailureLedger,
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    Trust,
    consolidate_failures,
    regression_report,
    should_prune,
)
from verel.memory.view import rank
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign


def _fact(subject="card", predicate="max-width", text="use max-width:100%", scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate=predicate, text=text, scope=scope)


# ---- the two orthogonal quantities -----------------------------------------
def test_corroborate_raises_confidence_not_strength_semantics():
    m = LocalMemory()
    r = m.write(_fact())
    assert r.epistemic_confidence == 0.5
    r2 = m.corroborate(r.id)
    assert r2.epistemic_confidence > 0.5 and r2.support_count == 2


def test_contradict_lowers_and_eventually_rejects():
    m = LocalMemory()
    r = m.write(_fact())
    for _ in range(4):
        r = m.contradict(r.id)
    assert r.trust == Trust.REJECTED


def test_recall_reinforces_strength_but_not_confidence():
    m = LocalMemory()
    r = m.write(_fact())
    r.retrieval_strength = 0.3
    m._upsert(r)
    before_conf = r.epistemic_confidence
    hits = m.recall("max-width card", scope="repo:x")
    assert hits and hits[0].retrieval_strength > 0.3  # recall = testing effect
    assert hits[0].epistemic_confidence == before_conf  # truth untouched by retrieval


def test_interference_supersede_same_subject_predicate():
    m = LocalMemory()
    a = m.write(_fact(text="use width:100%"))
    b = m.write(_fact(text="use max-width:100%"))  # same subject+predicate+scope
    assert a.id == b.id  # same key
    assert m.get(a.id).text == "use max-width:100%"
    assert m.get(a.id).detail.get("superseded") == "use width:100%"


def test_prune_rule_is_exact_conjunction():
    weak = MemoryRecord(kind=MemoryKind.FACT, text="x", retrieval_strength=0.1,
                        epistemic_confidence=0.3, support_count=1, trust=Trust.CANDIDATE)
    assert should_prune(weak)
    verified = weak.model_copy(update={"trust": Trust.VERIFIED})
    assert not should_prune(verified)  # verified is never pruned
    supported = weak.model_copy(update={"support_count": 2})
    assert not should_prune(supported)  # support_count >= 2 saves it


def test_rank_combines_relevance_strength_confidence():
    r = _fact()
    r.retrieval_strength, r.epistemic_confidence = 1.0, 1.0
    assert rank(r, relevance=1.0) > rank(r, relevance=0.0)


# ---- failure ledger / regression guard -------------------------------------
def _overflow_report():
    r = Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.DOM,
               issues=[Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR,
                             message="panel overflows by 320px", locator=".panel",
                             source=GraderKind.DOM)])
    return assign(r)


def test_ledger_records_marks_fixed_and_catches_regression():
    m = LocalMemory()
    led = FailureLedger(m, scope="repo:x")
    rep = _overflow_report()

    fps = led.record(rep)
    assert fps and m.all(kind=MemoryKind.FAILURE)
    assert not led.check_regressions(rep)  # still open, not yet fixed -> not a regression

    led.mark_fixed(fps)
    rec = m.get(led.mem_id(fps[0]))
    assert rec.detail["status"] == "fixed" and rec.trust == Trust.VERIFIED

    # same failure reappears later -> regression guard fires from memory alone
    regs = led.check_regressions(_overflow_report())
    assert len(regs) == 1
    rr = regression_report(regs)
    assert rr.verdict == Verdict.FAIL and "Reintroduced" in rr.issues[0].message


# ---- consolidation (offline fake chat) -------------------------------------
def test_consolidation_writes_candidate_design_rule():
    m = LocalMemory()
    led = FailureLedger(m, scope="repo:x")
    for px in ("320px", "880px"):  # two distinct overflow failures, same kind
        r = Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.DOM,
                   issues=[Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR,
                                 message=f"card overflows by {px}", locator=f".c{px}",
                                 source=GraderKind.DOM)])
        led.record(assign(r))

    fake = lambda msgs: '{"subject": "fixed-width cards", "rule": "use max-width:100% not fixed px"}'
    rules = consolidate_failures(m, scope="repo:x", min_cluster=2, chat=fake)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.kind == MemoryKind.DESIGN_RULE
    assert rule.trust == Trust.CANDIDATE  # NEVER auto-verified
    assert "max-width" in rule.text and rule.support_count == 2
