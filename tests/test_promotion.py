"""Held-out, attested promotion gate (§5.7, §7.7) — offline/deterministic."""

from verel.memory import (
    EvalCase,
    HeldOutCorpus,
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    PromotionGate,
    Trust,
    evaluate_rule,
)


def _rule(keywords, covers_kind="overflow", scope="repo:x"):
    return MemoryRecord(
        kind=MemoryKind.DESIGN_RULE, subject="fixed-width cards", predicate="design_rule",
        text="use max-width:100% not fixed px widths", scope=scope, trust=Trust.CANDIDATE,
    ).with_detail(grounding="inferred", covers_kind=covers_kind, keywords=keywords)


def _corpus():
    return HeldOutCorpus(cases=[
        EvalCase("card uses fixed width 1600px and overflows", "overflow", "prevent"),
        EvalCase("panel width 2400px causes horizontal scroll", "overflow", "prevent"),
        EvalCase("text contrast ratio too low on caption", "contrast", "allow"),
        EvalCase("button width is fine", "overflow", "allow"),
    ])


def test_good_rule_promotes_to_verified():
    mem = LocalMemory()
    rule = mem.write(_rule(keywords=["max-width", "width", "fixed", "px"]))
    assert rule.trust == Trust.CANDIDATE
    gate = PromotionGate(mem, _corpus())
    res = gate.consider(rule)
    assert res.promoted and res.f1 >= 0.8
    assert mem.get(rule.id).trust == Trust.VERIFIED
    assert mem.get(rule.id).detail.get("grounding") == "verified"


def test_weak_rule_stays_candidate():
    mem = LocalMemory()
    # keywords that never match the prevent-cases -> low recall -> not promoted
    rule = mem.write(_rule(keywords=["unrelated", "tokens"]))
    res = PromotionGate(mem, _corpus()).consider(rule)
    assert not res.promoted
    assert mem.get(rule.id).trust == Trust.CANDIDATE


def test_leakage_canary_blocks_promotion():
    mem = LocalMemory()
    corpus = _corpus()
    rule = mem.write(_rule(keywords=["max-width", "width", "px"]))
    # the held-out canary token leaked into agent-accessible memory -> corpus compromised
    mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="leak", predicate="x",
                           text=f"oops {corpus.canary_token} stored", scope="repo:x"))
    res = PromotionGate(mem, corpus).consider(rule)
    assert not res.promoted and "canary" in res.reason
    assert mem.get(rule.id).trust == Trust.CANDIDATE


def test_evaluate_rule_precision_recall():
    f1, stats = evaluate_rule(_rule(keywords=["width", "px"]), _corpus())
    assert stats["n"] == 4 and 0.0 <= f1 <= 1.0
    assert stats["tp"] >= 1
