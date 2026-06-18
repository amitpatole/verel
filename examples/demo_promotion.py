"""Promotion demo — only verified work compounds (design §5.5, §5.7, §7.7).

Episodic failures → (Ollama Cloud) a CANDIDATE, `inferred` DesignRule → a held-out, attested,
agent-inaccessible eval → promotion to `verified`. Then we show the leakage canary blocking a
promotion when the held-out corpus is contaminated. The verdict — never the rubric — is all
the agent ever sees.

Run:  python examples/demo_promotion.py     (needs ~/.config/ollama/key for consolidation)
"""

from __future__ import annotations

from verel.agents.llm import have_key
from verel.memory import (
    EvalCase,
    FailureLedger,
    HeldOutCorpus,
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    PromotionGate,
    Trust,
    consolidate_failures,
)
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign


def _overflow(px, locator):
    return assign(Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.DOM,
                         issues=[Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR,
                                       message=f"element overflows the viewport by {px}px",
                                       locator=locator, source=GraderKind.DOM)]))


# Held-out cases phrased in the phenomenon's own vocabulary (overflow/viewport/width), so a
# rule that genuinely generalizes the overflow failure will match the positives. The allow
# cases discriminate: a different kind (contrast) excluded by `covers_kind`, and an overflow
# case that is actually fine and avoids the failure vocabulary.
HELD_OUT = HeldOutCorpus(cases=[
    EvalCase("a fixed-width container overflows the viewport on narrow screens", "overflow", "prevent"),
    EvalCase("the panel width exceeds the viewport and overflows horizontally", "overflow", "prevent"),
    EvalCase("element width is not responsive so it overflows the viewport", "overflow", "prevent"),
    EvalCase("caption contrast ratio is too low for AA", "contrast", "allow"),
    EvalCase("the footer renders correctly at every breakpoint", "overflow", "allow"),
])


def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    for px, loc in ((320, ".card"), (880, ".panel"), (1240, ".hero")):
        led.record(_overflow(px, loc))

    print("── Consolidate (Ollama Cloud): 3 overflow episodes → 1 candidate rule ──")
    rules = consolidate_failures(mem, scope="repo:x", min_cluster=2)
    if not rules:
        print("  (no rule induced)"); return 1
    rule = rules[0]
    print(f"  [{rule.trust.value}/{rule.detail.get('grounding')}] {rule.subject} → {rule.text}")
    print(f"  induced keywords (the gate's matcher): {rule.detail.get('keywords')}")

    print("\n── Promotion gate: held-out, attested, agent-inaccessible eval ──")
    res = PromotionGate(mem, HELD_OUT).consider(rule)
    print(f"  F1={res.f1:.2f}  verdict={res.verdict.value}  promoted={res.promoted}")
    print(f"  now: trust={mem.get(rule.id).trust.value} grounding={mem.get(rule.id).detail.get('grounding')}")

    print("\n── Leakage canary: contaminate the corpus, retry ──")
    mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="leak", predicate="x",
                           text=f"someone stored {HELD_OUT.canary_token}", scope="repo:x"))
    res2 = PromotionGate(mem, HELD_OUT).consider(rule)
    print(f"  promoted={res2.promoted}  reason={res2.reason}")

    ok = res.promoted and mem.get(rule.id).trust == Trust.VERIFIED and not res2.promoted
    print("\nResult:", "PASS — candidate earned `verified` only via the held-out gate; "
          "canary blocked the contaminated run" if ok else "NOT MET")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
