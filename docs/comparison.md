# Verel memory vs Mem0 / Engram / Zep

Honest positioning, because the agent-memory space is crowded and the right answer is often *"not
Verel."* Verel isn't primarily a memory library — it's a **verification framework** where memory is one
organ. So its memory makes a different bet than the others.

## The one-line difference

Most memory systems **extract-and-believe**: they pull facts from a conversation and store them as
truth. Verel **extracts-then-verifies**: a fact enters as `CANDIDATE` and only becomes `VERIFIED` when
it's **attested** (a signed receipt) or corroborated by **≥2 authenticated sources**. A one-off, a
hallucination, or an attacker repeating a lie never silently becomes "what the agent knows."

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
