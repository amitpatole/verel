# Verel memory vs Mem0 / Engram / Zep

Honest positioning, because the agent-memory space is crowded and the right answer is often *"not
Verel."* Verel isn't primarily a memory library — it's a **verification framework** where memory is one
organ. So its memory makes a different bet than the others.

## The one-line difference

Most memory systems **extract-and-believe**: they pull facts from a conversation and store them as
truth. Verel **extracts-then-verifies**: a fact enters as `CANDIDATE` and only becomes `VERIFIED` when
it's **attested** (a signed receipt) or corroborated by **≥2 authenticated sources**. A one-off, a
hallucination, or an attacker repeating a lie never silently becomes "what the agent knows."

## Cost: what graded, budgeted recall saves

The naive memory pattern — *"stuff every fact (or the whole chat history) into the prompt each turn"* —
grows your input token bill linearly with how much the agent remembers. Verel's `recall_budgeted`
returns only the highest-value memories that fit a **token budget**, **graded-first**, so you spend the
budget on the facts that matter — not the first N rows, and not a hallucinated `CANDIDATE`.

Measured by `examples/demo_token_savings.py` (offline, real `tiktoken cl100k_base` counts) — a 40-fact
user brain, naive context = **679 tokens/turn**:

| Per-turn budget | Tokens used | Saved | Cost over 1,000 turns @ $2.50/1M |
|---|---|---|---|
| naive (replay all) | 679 | — | $1.70 |
| `token_budget=400` | 458 | **32%** | $1.70 → **$1.15** |
| `token_budget=200` | 237 | **65%** | $1.70 → **$0.59** |
| `token_budget=100` | 135 | **80%** | $1.70 → **$0.34** |

At each budget the hallucinated candidate is **excluded** (`graded-first`, not truncation), so you also
don't pay tokens to mislead the model. Four mechanisms compound the saving:

- **Budgeted recall** (`recall_budgeted`) — a hard token cap, filled best-first; injectable exact
  tokenizer (`token_count=tiktoken…`) so the budget is precise.
- **Facts, not transcripts** — `extract_facts` stores compact SPO facts ("Dana prefers dark mode"), not
  raw conversation turns.
- **Supersede, not append** — a changed value replaces the old one (one fact per key), so recall never
  pays for stale duplicates.
- **Decay + prune** — unused memories fade and are pruned, so the budget isn't spent on junk.

Run it: `python examples/demo_token_savings.py` (`pip install tiktoken` for exact counts).

## When to use which

| Your situation | Best fit |
|---|---|
| Single agent, you just want a memory layer, a human curates | **Mem0** (or **Engram** for small, clean, local). Simpler; Verel is heavier than you need. |
| Keep memory **small and clean** (reconcile/forget), local dev workflow | **Engram** — compact, FTS-oriented, great at staying tidy. |
| You need **temporal** reasoning — *what was true when*, facts changing over time | **Zep** — built around a temporal knowledge graph. |
| Memory as part of the **agent runtime** (working vs archival, explicit control) | **Letta**. |
| Multi-user **product** memory — APIs, user profiles, connectors | **Supermemory** / **Honcho**. |
| **A fleet of agents shares one brain and a wrong fact is expensive** — you can't have a hallucination (or one bad actor) become trusted memory | **Verel** — graded trust, rejected-value tombstones, fenced recall. |

**Verel is not a Mem0 replacement** — it's a different philosophy. Reach for it when *correctness of
memory under multiple, partly-untrusted writers* matters more than minimal setup.

## Third-party comparison

An independent comparative report (by the author of [RainBox](https://github.com/neoneye/RainBox),
who also analyzes their own system) puts Verel in its own **"verification-first memory"** category and
rates its trust/correction model highest in the set — with the honest tradeoff that it's "more complex
than most systems need for an MVP." Verbatim: *"Verel treats memory as a trust problem … separates
confidence, retrieval strength, and verification state; carries rejected values forward; fences recalled
memory as untrusted data … best correctness model in set."*
See [`memory-systems/overview.md`](https://github.com/neoneye/RainBox/blob/main/source/docs/memory-systems/overview.md).

## Coming from Mem0

The shapes map closely — the difference is the grade gate between write and trust:

| Mem0 | Verel | Note |
|---|---|---|
| `m.add(messages, user_id="dana")` | `remember_conversation(mem, messages, scope="user:dana", chat=llm)` | Verel facts enter `CANDIDATE`; pass `authenticate=`/`attest=` to let them graduate to `VERIFIED`. |
| `m.search(query, user_id="dana")` | `recall_budgeted(mem, query, scope="user:dana", token_budget=N)` | Returns a token-budgeted, graded-first, fenced block; verified beats candidate. |
| `m.get_all(user_id=…)` | `mem.all(scope="user:dana")` | Same idea; records carry `trust`, `provenance`, `epistemic_confidence`. |
| Vector store + history | `LocalMemory` (SQLite + **FTS5 BM25**, optional embedder) | Zero-config, dependency-free default; Postgres/Redis/LanceDB/hosted behind the same `MemoryView`. |
| Managed platform features | the verdict bus, fleets, eyes | Verel's "platform" is the rest of the organism — opt in only if you need it. |

Practical migration: keep Mem0 if a human reviews memory and a single agent writes it. Move to Verel
(or run it alongside, gating what Mem0 stores) when **multiple agents** write and a wrong fact would
propagate. Start with the **[Memory quickstart](memory-quickstart.md)** — it's 20 lines, offline, no key.

## What Verel deliberately does NOT do

To keep the verification focus sharp, Verel **cedes**: a temporal knowledge graph (use Zep), a
connector ecosystem / hosted multi-tenant ranking (Supermemory), and a verbatim-evidence raw store
(MemPalace). Its provenance + queryable correction chains cover auditability; the rest would dilute the
moat.
