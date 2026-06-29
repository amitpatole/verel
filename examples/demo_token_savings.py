#!/usr/bin/env python3
"""Token cost — what graded, budgeted recall saves vs replaying the whole brain into every prompt.

The naive pattern is "stuff all the memories (or the raw chat history) into the context each turn."
Verel's `recall_budgeted` instead returns only the highest-value memories that fit a token budget,
**graded-first** — so under pressure a VERIFIED fact beats an equally-relevant CANDIDATE and a poisoned
candidate can't crowd out a verified one. You spend the budget on what matters, not the first N rows.

Runs offline (no API key). Uses `tiktoken` for exact counts if it's installed, else a ~4-chars/token
estimate — the numbers print which.

    python examples/demo_token_savings.py
"""
from __future__ import annotations

from verel.memory import LocalMemory, recall_budgeted
from verel.memory.view import MemoryKind, MemoryRecord, Trust, make_id, make_key

try:
    import tiktoken
    _enc = tiktoken.get_encoding("cl100k_base")
    tok = lambda s: len(_enc.encode(s))          # noqa: E731
    COUNTER = "tiktoken cl100k_base (exact)"
except Exception:                                 # noqa: BLE001
    tok = lambda s: max(1, round(len(s) / 4))     # noqa: E731
    COUNTER = "~4 chars/token estimate (pip install tiktoken for exact)"

PRICE_PER_1M = 2.50     # $/1M input tokens, a GPT-4o-class rate (adjust to your model)
TURNS = 1000            # amortize over a realistic number of agent turns


def _fact(mem, subject, predicate, text, trust=Trust.VERIFIED):
    k = make_key(subject, predicate, "user:dana")
    mem.write(MemoryRecord(id=make_id(k), kind=MemoryKind.FACT, subject=subject, predicate=predicate,
                           text=text, scope="user:dana", subj_pred_key=k, trust=trust))


def main() -> None:
    mem = LocalMemory()
    # A realistic user brain accumulated over many sessions: 40 durable facts...
    facts = [("user", f"pref_{i}", f"value setting number {i} for the dashboard and workflow")
             for i in range(40)]
    for s, p, o in facts:
        _fact(mem, s, p, o)
    # ...plus one HALLUCINATED candidate the agent should NOT spend budget trusting:
    _fact(mem, "user", "is", "a billing superadmin", trust=Trust.CANDIDATE)

    naive = "\n".join(f"- {s} {p}: {o}" for s, p, o in facts)
    naive_tok = tok(naive)
    print(f"== token cost per turn — counts via {COUNTER} ==")
    print(f"   naive (replay the whole brain): {naive_tok} tokens\n")

    print(f"== verel recall_budgeted (graded-first) — ${PRICE_PER_1M}/1M tokens over {TURNS} turns ==")
    for budget in (100, 200, 400):
        br = recall_budgeted(mem, "dashboard workflow setting", scope="user:dana",
                             token_budget=budget, token_count=tok)
        used = tok(br.text)
        saved = naive_tok - used
        naive_cost = naive_tok * TURNS * PRICE_PER_1M / 1e6
        verel_cost = used * TURNS * PRICE_PER_1M / 1e6
        leaked = any("superadmin" in r.text for r in br.records)
        print(f"   budget={budget:4}: {used:3} tokens  (saved {saved}, {100 * saved // naive_tok}%)  "
              f"kept {len(br.records)}, dropped {br.dropped}  |  ${naive_cost:.2f} → ${verel_cost:.2f}  "
              f"|  hallucination included: {leaked}")

    print("\n   It's not truncation: the budget is spent on the most-relevant VERIFIED facts; the\n"
          "   hallucinated CANDIDATE never makes it in, so you don't pay tokens to mislead the model.")


if __name__ == "__main__":
    main()
