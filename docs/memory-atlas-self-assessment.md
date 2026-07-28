# Memory self-assessment (agent-memory-atlas method)

The [agent-memory-atlas](https://neoneye.github.io/agent-memory-atlas/) grades agent-memory systems on
**seven binary dimensions** by inspecting code at a pinned commit and *tracing* behaviour — capture →
storage → retrieval → correction → deletion. It scored an early snapshot of Verel **3/7**. Rather than
argue, we internalised the atlas's own method: `verel/memory/rubric.py` re-implements each dimension as
a **live behavioural probe** against `LocalMemory(":memory:")`, so a mark is *earned by demonstrated
behaviour*, not claimed — and a regression flips the mark to a dash (it is a pinned test,
`tests/test_memory_rubric.py`).

Run it yourself:

```bash
verel memory rubric          # or:  python -m verel.memory.rubric
```

> The atlas is explicit this is **not a maturity score**: "A system with six marks is not better than
> one with two; it is differently shaped." We report the shape, with evidence, and pin nothing we can't
> demonstrate.

## Scorecard — 7 / 7

| # | Dimension (atlas criterion) | Mark | Our evidence | What the probe demonstrates |
|---|---|---|---|---|
| 1 | **Rejected-value Tombstone** — durable record of a rejected *value*, keyed on the value, so later extraction can't silently re-assert it | ✓ | `view.record_rejection` / `is_launder_blocked`; ledger keyed on `rejected_key(text)`, carried across supersession | reject a value → it's in `rejected_values` keyed by value; supersede + re-assert → still un-promotable |
| 2 | **Explicit Trust State** — a discrete status *field* (not a float) with at least one state that withholds a memory | ✓ | `view.Trust` enum `CANDIDATE / VERIFIED / REJECTED` | a REJECTED record is withheld from recall on every backend |
| 3 | **Bi-temporal Validity** — when a fact was *true* tracked separately from when it was recorded | ✓ | `MemoryRecord.valid_from/valid_to` vs `created_ts`; `value_as_of` / `recall_as_of` | `region` changes us-east→us-west; as-of March returns us-east, as-of today us-west |
| 4 | **Scope Enforced in Retrieval** — a stored scope key applied as a *filter on the read path* | ✓ | `local.recall` SQL `m.scope = ? OR 'global'`; every backend filters | `recall(scope=repo:a)` omits a `repo:b` record |
| 5 | **Append-only Mutation Audit** — a named append-only event record of *mutations* in the system's own store | ✓ | `memory.audit.MemoryAudit` / `AuditedMemory` (hash-chained JSONL) | write + promote are logged; the chain verifies and detects tampering |
| 6 | **Human Review Surface** — a place a person inspects, approves, or *adjudicates* memory | ✓ | `memory.review.approve/reject/pending`; `verel memory` CLI (CLI-only) | a candidate is queued, approved → verified + recorded, rejected → durable |
| 7 | **Negative Retrieval Assertion** — *committed* eval cases assert particular material must **not** be retrieved | ✓ | `tests/test_memory_negative_eval.py` + `memory_contract` negative checks | a rejected value is absent from budgeted recall; committed cases exist in-tree |

## Method, applied to ourselves (the atlas per-repo sections, condensed)

**1. Executive summary.** Verel is a *verification-first* agent framework; memory is one organ. A fact
becomes a belief only when **graded** (attested, or corroborated by ≥2 authenticated principals, or
approved by a human) — never by raw repetition. It stops being one via `contradict` → `REJECTED`, a
durable tombstone.

**2. Mental model — how a thing becomes a belief and stops being one.** Trust is a discrete field
(`CANDIDATE → VERIFIED`, or `→ REJECTED`), orthogonal to two never-collapsed quantities:
`epistemic_confidence` (belief, moved only by corroborate/contradict) and `retrieval_strength`
(reachability, power-law decay). Promotion is gated in the **primitive** `promote()` via
`is_launder_blocked`, so no caller can launder a once-rejected value.

**3. Architecture.** `MemoryView` Protocol with five interchangeable backends (SQLite default,
Postgres, LanceDB, Redis, mem0) + a hosted HTTP brain; the trust layer is Verel's, the storage is
rentable. Secrets under `~/.config`, never in the repo.

**4–5. Data model & write mechanics.** `view.MemoryRecord` — content-addressed id, `subj_pred_key`
interference key (same key supersedes, keeping a bounded correction chain), the `rejected_values`
ledger, and bi-temporal `valid_from/valid_to`. Writes are synchronous; supersession stamps validity
intervals.

**6. Retrieval mechanics.** FTS5 BM25 lexical (default) or cosine (with an embedder), re-ranked
trust-aware so a VERIFIED fact beats an equally-relevant CANDIDATE; `recall_budgeted` fences results as
untrusted DATA; `recall_as_of` reconstructs historical values.

**9. Reliability, safety, trust.** Receipts (HMAC/ed25519, fail-closed); the memory trust layer was
hardened over **five adversarial red-team rounds** (terminal-clean) closing laundering and
terminal-injection vectors; residual risk is dependencies/kernel and the documented replication trust
boundary (the cluster credential).

**10. Tests & evals.** The negative-eval suite asserts what recall must *not* surface, across every
backend and recall path; this self-assessment is itself a pinned regression test.

**"For your own build" — Steal / Avoid / Fit.** *Steal:* put the anti-laundering guard in the write
primitive, not each caller. *Avoid:* a bounded rejection ledger that silently evicts — pair it with a
saturation fail-safe. *Fit:* Verel suits agents that must not compound unverified work; it is heavier
than an extract-and-believe store and deliberately so.

## Honest residuals

- The atlas notes marks are *shape, not rank* — 7/7 means "covers these seven concerns," not "best."
- `recall_as_of` is an O(n) analytical scan, not a hot path; it returns raw records to be fenced by the
  caller, exactly like `recall`.
- The mutation audit is a **local integrity** log (in-place tamper + torn-write detection), not a signed
  WORM chain — use `ReceiptStore` for the signed variant.
