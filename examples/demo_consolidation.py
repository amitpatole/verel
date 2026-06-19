"""Deepened consolidation (§5.5) — episodic failures → structured rules → a schema, offline.

Shows the three layers and the adaptive decay: recurring failures cluster (by kind here; pass an
embedder + semantic=True for meaning-based sub-clustering), each cluster induces a STRUCTURED
DesignRule (condition/action/applies_to), and the rules themselves induce a 2nd-order SCHEMA.
Everything enters as `candidate` — it earns `verified` only through the held-out gate.

The LLM is stubbed here so it runs with no key; in production it's Ollama Cloud (OpenAI fallback).
Run:  python examples/demo_consolidation.py
"""

from __future__ import annotations

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    consolidate_failures,
    induce_schemas,
)
from verel.memory.view import apply_decay, effective_half_life, make_key


def _failure(text: str, kind: str) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FAILURE, subject=text[:14], predicate="f", text=text,
                        scope="repo:app", subj_pred_key=make_key(text[:14], "f", "repo:app")).with_detail(kind=kind)


def _rule_chat(messages: list[dict]) -> str:
    if "contrast" in messages[-1]["content"]:
        return ('{"subject":"buttons","condition":"text contrast is below WCAG AA",'
                '"action":"ensure a >= 4.5:1 contrast ratio","applies_to":"all interactive text"}')
    return ('{"subject":"cards","condition":"a card uses a fixed px width",'
            '"action":"use max-width:100% with a flexible container","applies_to":"narrow viewports"}')


def _schema_chat(messages: list[dict]) -> str:
    return ('{"subject":"perceivable UI","principle":'
            '"every element must stay legible and within its container across all viewports"}')


def main() -> None:
    mem = LocalMemory()
    for text, kind in [
        ("product card overflows the viewport on a 320px screen", "overflow"),
        ("pricing panel runs off-screen on mobile widths", "overflow"),
        ("CTA button label fails contrast against the gradient", "contrast"),
        ("secondary button text is too light to read", "contrast"),
    ]:
        mem.write(_failure(text, kind))

    print("Layer 1+2 — cluster failures → structured DesignRules:")
    rules = consolidate_failures(mem, scope="repo:app", min_cluster=2, chat=_rule_chat)
    for r in rules:
        d = r.detail
        print(f"  [{d['covers_kind']:8}] WHEN {d['condition']}  →  DO {d['action']}")
        print(f"             applies_to={d['applies_to']!r}  trust={r.trust.value}  grounding={d['grounding']}")

    print("\nLayer 3 — induce a 2nd-order SCHEMA over the rules:")
    for s in induce_schemas(mem, scope="repo:app", min_rules=2, chat=_schema_chat):
        print(f"  «{s.subject}» {s.text}  (subsumes {len(s.detail['subsumes'])} rules, {s.kind.value})")

    print("\nAdaptive decay — a corroborated rule outlives a one-off (reachability only):")
    base = 7 * 24 * 3600.0
    one_off = MemoryRecord(kind=MemoryKind.DESIGN_RULE, text="seen once", support_count=1,
                           epistemic_confidence=0.5, retrieval_strength=1.0, created_ts=0.0)
    corroborated = MemoryRecord(kind=MemoryKind.DESIGN_RULE, text="seen often", support_count=8,
                                epistemic_confidence=0.9, retrieval_strength=1.0, created_ts=0.0)
    print(f"  half-life: one-off={effective_half_life(one_off, base) / 86400:.0f}d  "
          f"corroborated={effective_half_life(corroborated, base) / 86400:.0f}d")
    for r in (one_off, corroborated):
        apply_decay(r, now=base, half_life_s=base, stale_after_s=1e12, volatile_ttl_s=1e12)
    print(f"  after 1 base half-life idle: one-off strength={one_off.retrieval_strength:.2f}  "
          f"corroborated={corroborated.retrieval_strength:.2f}")


if __name__ == "__main__":
    main()
