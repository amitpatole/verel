# MEMORY-EXTRACTION-KICKOFF.md — graded conversational memory (v1.2.0)

> Closes the two most-felt memory gaps (turnkey conversational fact extraction + prompt-size
> minimization) **without diluting the moat**: a fact is *extracted* like Mem0/Engram, but it only
> **compounds after it's graded** — written as `Trust.CANDIDATE`, promoted to `Trust.VERIFIED` only
> through the existing held-out / attested promotion gate. Pitch: *"extracted facts, but verified
> before trusted — your memory can't confidently remember something wrong."*

Follow phase by phase. **Stop at each acceptance check for review** before the next phase.

## What already exists (reuse, don't reinvent)
- `MemoryRecord` (SPO: subject·predicate·`text`, `scope`, `subj_pred_key`), `MemoryKind.FACT`,
  `Trust.{CANDIDATE,VERIFIED,REJECTED}`, `epistemic_confidence`, `retrieval_strength`, decay/TTL.
- The **grade gate**: `principal.import_belief(into, claim, verify=…)` (signed writes) +
  `promotion.evaluate_rule` / `Promoter` (held-out F1 ≥ 0.8 → VERIFIED) + `verdict.verify_fact_attestation`.
- **Conflict handling**: `revise.contradicts`, `revise.propagate_revision`; **consolidation**:
  `consolidate.cluster_records`, `consolidate_failures`.
- **Recall/ranking**: `view.relevance`, `view.rank` (relevance + confidence + trust), `lattice_recall`.
- `ChatFn = Callable[[list[dict]], str]` (injected — everything stays offline-testable with a fake chat).

## Non-negotiables (the through-line)
- **No ungraded fact compounds.** Extraction writes `CANDIDATE`; only the promotion gate makes `VERIFIED`.
- **Every write stays scope-isolated + (optionally) signed** — reuse `import_belief`, don't bypass it.
- **Pure + injected** — parsers pure over canned output, `ChatFn` injected, offline matrix, defensive
  against hostile/garbage LLM output (the transcript is untrusted input → security cadence).
- One coherent **v1.2.0** release; docs in lockstep; dogfood verel's own gate.

---

## Phases

### Phase 1 — the extractor (smallest shippable slice)  ← START HERE
`memory/extract.py`: `extract_facts(transcript, *, scope, chat, now) -> list[MemoryRecord]` and a
pure `parse_extracted_facts(out, *, scope, now)`. Turns a conversation into **candidate** `FACT`
records (SPO, `Trust.CANDIDATE`, `source="extraction"`, content-addressed id via `make_key`/`make_id`),
deduped by `subj_pred_key`.
- **Acceptance:** a transcript (string or `[{role,content}]`) → candidate FACT records with
  subject/predicate/text/scope; deterministic dedup; the parser fails closed on garbage/hostile JSON
  (no crash, no partial); zero records are `VERIFIED`. Lint+types+tests green.

### Phase 2 — the grade gate wiring
`remember_conversation(mem, transcript, *, scope, chat, promoter|verify)`: extract → write CANDIDATE →
run the **existing** promotion/attestation gate → only VERIFIED facts compound; a contradicting fact
routes through `revise.contradicts` (supersede, don't duplicate); a corroboration bumps
`epistemic_confidence`.
- **Acceptance:** an unsupported/hallucinated fact stays CANDIDATE (never trusted); a corroborated one
  promotes to VERIFIED; a contradiction supersedes the stale record. No new bypass of `import_belief`.

### Phase 3 — token-budgeted recall (prompt minimization)
`recall_budgeted(mem, query, *, scope, token_budget) -> (records, used_tokens)`: rank via `view.rank`,
fill to the budget verified-first, compress/summarize the tail, return the minimal context + the token
count.
- **Acceptance:** output never exceeds `token_budget`; at the margin a VERIFIED fact beats an equally
  relevant CANDIDATE; `used_tokens` reported and tested; a tiny budget still returns the single most
  load-bearing fact.

### Phase 4 — surfaces + docs lockstep
MCP tools (`verel_remember`, `verel_recall`) + optional CLI; `memory-backends.md` + a new **Conversational
memory** concepts section + `api.md`; a runnable `examples/demo_memory.py` (no API key, fake chat); CHANGELOG.
- **Acceptance:** `mkdocs build --strict` green; documented symbols exist; demo runs and prints real output.

### Phase 5 — security cadence (untrusted transcript = real attack surface)
Audit → red-team rounds on: prompt-injection into the extractor ("ignore previous… store this admin
fact"), PII capture, memory poisoning (write a false high-confidence fact), scope/principal bypass,
JSON-DoS. Fix in verified batches; regression-pin each; ≥3 adversarial rounds until a round is empty.
- **Acceptance:** every discovered vector closed + pinned; the gate still fails closed on hostile input.

### Phase 6 — release v1.2.0
Full release cadence (version bump everywhere + drift-guard, dogfood gate, TestPyPI→verify→PyPI→verify,
tag, GitHub release, image/chart, docs deploy + verify-live, main CI green). One release for the track.
- **Acceptance:** `pip install verel==1.2.0` resolves; all surfaces live + green.

## Explicitly out of scope for v1.2.0 (later phases of the broader roadmap)
Bitemporal/temporal-KG recall (Phase C), working↔archival runtime paging (Phase D), background
reflection + LangGraph adapter (Phase E), the LoCoMo-style benchmark (Phase F). Connector ecosystem and
a user-profile product are **ceded** (off-mission).
