Ground truth confirmed: `CLASSIC_CAPABILITIES = ["contrast", "overflow", "broken_image", "error_text", "typo", "blank", "other"]` — exactly as the converged design states. The document is internally consistent with source. Returning the definitive final document.

# Verel — Definitive Architecture & Build Plan

> **Document status & how to read it.** This is the final lead-architect design, converged after three adversarial critic rounds (record in §13). Every major subsection carries a **phase tag** in its header — `[v1 thin-vertical]`, `[v2]`, `[v3+/research]`, or `[non-goal/kill-list]` — so the team builds the moat in the *vertical*, not the buzzword surface area. The body is the *target architecture*; only the `[v1]` sections are the program of work. Where a critic was right, the text is fixed and the fix is called out. Where a critic was wrong, the text pushes back briefly rather than silently complying. AgentVision source claims were re-verified against `/home/amitpatole/Eyes_For_AI_Agents/src/agentvision/` (`models/report.py`, `core/analyze.py`, `core/checks/__init__.py`, `adapters/mcp_server.py`); `CLASSIC_CAPABILITIES = ["contrast","overflow","broken_image","error_text","typo","blank","other"]` is confirmed verbatim at `core/checks/__init__.py:25`.

> **Headline strategic conclusion, stated up front.** **Verel has NO durable technical moat at v1. It has a WEDGE — grounded perception (AgentVision) + verdict-gating — and a BET on a data flywheel (a verified eval+skill corpus) that only becomes a moat if two falsifiable conditions BOTH hold: (1) adoption reaches a threshold (H1), and (2) verified skills transfer across tenants/repos at a non-trivial rate (H2).** Both are *hypotheses under test*, treated with the same discipline as the cost model (§8.5). If cross-repo skill transfer is <20% (§8.7 experiment), the GLOBAL tier and public registry are dead and the moat collapses to per-tenant lock-in (weaker, but still real). We say this in §1 and §8, not in a footnote.

---

## 1. One-line positioning & executive summary  `[v1 thin-vertical]`

**One line:**

> *Verel is the agent framework where nothing is "done" until a grader returns a verdict — checked by real senses including eyes (AgentVision) — and only verified work compounds.*

**Executive summary.** Verel is an agent framework built on the Claude Agent SDK with one banner promise: **nothing ships until it is verified by real senses — including eyes — and only verified work is allowed to compound into the fleet's shared memory.** The external pitch leads on **verification + perception** — the two axes that are real, lacking elsewhere, and hard to dismiss as marketing. We are **cutting "real brain" from all external-facing material**: Letta and mem0 already own "memory for agents" with shipped product, so leading with "brain" picks the weakest, most-contested, most-copyable axis as the banner. The brain/memory framing is **demoted to internal architecture vocabulary** (§5) — kept for *legibility* of the memory subsystem, with the rigor of mapping every brain word to a CS mechanism — but it is not the product story. What no existing framework holds together is the buildable substance: **(1)** a universal verdict bus (§7) unifying vision, tests, types, lint, perf, security, cost, and LLM-judge into one schema and one stuck/progress signal, with a typed reducer enforcing "precise gates, advisory informs" at merge time plus grader-execution attestation so a hollow grader can't mint green; **(2)** AgentVision as a grounded perception organ (§8) feeding both the verdict bus and memory; **(3)** verdict-gated procedural memory (§5, §7) where agent-built tools/skills/facts compound into shared memory only after passing a graded eval against a held-out, agent-inaccessible corpus, and are demoted on regression. The durable asset — *if it materializes* — is the verified eval+skill corpus that compounds with usage (§8). Everything below names the concrete CS mechanism behind every analogy and flags where a metaphor breaks or where a claim is marketing rather than buildable.

---

## 2. What makes Verel unique — the moat (honest)  `[strategy]`

### 2.1 The competitive landscape — and the incumbent-response case, argued explicitly

| System | What it actually is | What Verel adds | **What stops them shipping our wedge in ONE quarter, given their distribution?** |
|---|---|---|---|
| **LangGraph** | Graph/state-machine runtime; durable checkpointer = "memory." | Verdict-gating + consolidating entailment-gated memory. | **Nothing technical.** They have distribution and a runtime. Our only edge is focus on the verification framing + corpus accrual. |
| **AutoGen / Swarm** | Multi-agent convergence / minimal handoff primitives. | Eval-gated agents-managing-agents + perception + consolidation. | Mostly nothing structural; they lack the verification framing, not the capability. |
| **CrewAI** | Roles/crews orchestration; leans on mem0 for memory. | Verdict bus + grounded perception + gated promotion. | Nothing structural; CrewAI already integrates mem0 and could add a perception adapter. |
| **Claude Agent SDK / Claude Code** | The substrate we build on (subagents, hooks, MCP, skills, background tasks). | Verdict bus + eyes + gated procedural memory above it. | N/A — it's the platform; the honest one. We build ON it. |
| **Letta (MemGPT)** | Tiered memory, virtual context paging, **sleep-time compute (their consolidation)**. | Perception organ + verdict-gating + verified corpus + cross-store consistency contract. | **Nothing technical** — Letta can mount AgentVision's open MCP server in an afternoon and add held-out evals. Edge is execution speed + owning "verified," NOT a barrier. |
| **mem0** (~47K stars) | Memory service (vector+graph+KV, **auto-extraction with provenance**). | We *use* mem0 as the v1 backend; compete on what gates/consolidates/perceives. | **Nothing technical** on storage; they could add a perception adapter. Edge is gated-promotion discipline + corpus. |
| **Generic RAG** | Top-k retrieve + stuff into context. | Closed write/consolidate/retrieve loop with entailment + trust + interference + forgetting. | Nothing — but no one's packaged it as a verification product. |

**The honest incumbent-response conclusion.** For every incumbent, the truthful answer to "what stops them?" is **"nothing technical — only that they are not focused on the verification framing."** Verel's perception organ is a thin adapter over an open MCP tool a competitor can mount in an afternoon. **Therefore the real strategy is execution speed + category-definition (owning "verified agents"), NOT a technical moat.** That is a legitimate bet, but a *different* bet than naive "we have a unique brain" framing, and we name it as such.

### 2.2 The moat — a DATA FLYWHEEL bet, with cold-start and its honest holes

> **The durable asset, IF it materializes, is a shared verified eval+skill corpus that compounds with usage. AgentVision + verdict-gating are the WEDGE that bootstraps it — not the moat themselves. At v1 there is NO durable moat; there is a wedge and a bet.**

**Flywheel mechanism:**
1. **Accrual:** every run produces (a) verified skills that passed the held-out, *attested* gate, and (b) failure-ledger entries with stable fingerprints — verified, attributable, deduped data.
2. **Distribution:** a **public Skill Registry** (content-addressed, signed, provenance-tagged); an **opt-in fleet-GLOBAL tier**; a **public held-out benchmark** turning "did your agent actually pass?" into a comparable standard.
3. **Cold-start — stated with its holes.** It is *wrong* to claim "seed the registry with UI-fix skills AgentVision already proves," twice over: **(a)** AgentVision returns *critiques, not fix-skills* — a transferable fix-skill artifact (`SKILL.md` + fix procedure) does not exist today and must be *built* from many resolved episodes via §5.5 induction, NOT emitted by `analyze()`; **(b)** a Tailwind-overflow fix is *repo/design-system-specific* (`scope:'repo:checkout-web'`), so repo-scoped skills do NOT automatically compound across tenants. The data-network-effect that is the *entire* moat **may not exist** because the asset may not be fungible across tenants. This is the single biggest feasibility risk, turned into the gating experiment in §8.7 (H2).

### 2.3 Defensibility audit — the honest table

| # | Improvisation | Time-to-clone | Verdict |
|---|---|---|---|
| 1 | Verdict Bus (one schema, all senses) | ~1 quarter | **copyable** |
| 2 | Promotion-on-eval procedural memory (held-out, attested) | ~1–2 quarters | **wedge** (durable only via corpus) |
| 3 | Memory provenance/trust + corroborated entailment gate | ~1 quarter | **copyable** |
| 4 | Cross-episode consolidation + interference model | ~1–2 quarters | **wedge** |
| 5 | Issue-set stuck-detection, fleet-wide | weeks | **copyable** |
| 6 | Bounded-context firewall + interference rule | weeks | **copyable** |
| 7 | Cost-as-a-sense | weeks | **copyable** |
| 8 | Manager eval-contracts ("done" = verdict) | ~1 quarter | **wedge** |
| — | **AgentVision (eyes)** | **2–4 weeks** | **strong FEATURE today, NOT a durable moat** |
| — | **The verified eval+skill corpus** | **cannot be cloned without users + time** | **the ONLY potentially durable asset — and only IF §8.7 transfer holds** |

**Conclusion the table forces:** 6 of 8 are copyable/wedge; only the compounding corpus is *potentially* durable, and only if cross-tenant transfer is real. **Invest in distribution + corpus accrual + the transfer experiment, not in believing any single component is the barrier.**

---

## 3. North-star principles  `[v1 thin-vertical]`

1. **No self-asserted "done."** Every agent action is a hypothesis; a grader must return `pass` before a task closes. "Done" is a verdict.
2. **Precise gates, advisory informs — enforced at merge, not just per-issue.** Grounded graders (DOM, OCR, CV, tests, typecheck, lint) can *block*; ungrounded graders (vision-LLM, LLM-judge) are *clamped to ≤ `warn`* by the Gate reducer (§7.1), via an **explicit ceiling function** (not a `min`-by-key that only works by accident).
3. **Termination correctness rests on a stable fingerprint, never on raw natural-language text.** The fleet-wide stuck/progress/dedup/failure-ledger key is a **scrubbed fingerprint** (§7.2), not `message.strip().lower()`.
4. **Memory is retrieval + assembly + stores — never neurons.** LLMs are stateless: `f(context) → tokens`. Nothing persists across calls unless we write it down and re-inject it.
5. **No continuous learning.** Verel consolidates only when a job runs. If it never runs, the agent is a goldfish with good notes.
6. **Progress = monotone shrinkage of the failing-issue set, not any set-change** (§7.2): a *strict subset* relation over gating-severity failures, with named constants `GATING_SEVERITY`, `SEV_ORDER` (§7.1).
7. **Only verified work compounds, and the gate lives in a separate trust domain** (§7.7). An agent may author tools but may **not** author the gate that judges them, **and required graders must attest they actually ran** (§7.1).
8. **Rent the commodity substrate, own the policy.** v1 rents **one** memory backend; we own consolidation policy, trust model, verdict-gating, and the **cross-store consistency contract** (§5.9). No self-hosted Neo4j / CRDT in v1.
9. **Single-writer scheduler in v1, with its OWN fencing lease.** v1 confines itself to a **single-writer per run** model (§6.7) — and because of that, **fencing tokens for workers are themselves deferred to v3** (§6.1, §12): fencing only matters under concurrent managers, which v1 does not have. The one place v1 keeps a fencing lease is the *scheduler-on-the-run* (§6.10), to prevent two schedulers resuming the same run.
10. **Every brain word maps to a store with a buildable, inspectable, writable artifact — or it gets cut.** "The agent dreams" was cut. This design also cuts **"working memory"** (no capacity-limited buffer exists — §5.2) and **"prospective memory"** (a reliable cue-matcher is a durable event queue, not human PM — §5.8), and strips the **dopamine/tagging gloss** off the salience filter (§5.5).

---

## 4. System architecture — the five organs  `[v1 = bold path only; rest v2+]`

Verel is five organs meeting at one bus: the **Fleet** acts, the **Senses** perceive, the **Brain** retains, the **Tool-smith** grows capability — and the **Verdict bus** decides what counts as progress, what closes a task, and what compounds into shared memory.

```
                                   ┌───────────────────────────────────────────────┐
                                   │            FLEET / ORCHESTRATION                │
                                   │  Control plane (Verel-owned), on Claude SDK   │
   goal ───────────────────────►  │                                                 │
                                   │  Orchestrator ─┬─ Manager ─┬─ Worker (worktree) │
                                   │   (Opus 4.8)   │ (Sonnet)  ├─ Worker            │
                                   │                │           └─ Critic/Verifier   │
                                   │                └─ Tool-smith  [v2]               │
                                   │  Supervision(retry+heartbeat) · Budget LEASE    │
                                   │  Scheduler(single-writer, self-fenced on run-id)│
                                   │  Event log = WAL + outbox · trace context        │
                                   └───────┬───────────────────────────────┬─────────┘
                                           │ delegate(goal+criteria+lease)   │ blackboard(versioned KV)
                                           ▼                                 ▼
        ┌──────────────────────────────────────────────────────────────────────────────┐
        │                    VERDICT BUS  (eval-driven core, v1)                         │
        │  one schema: Report{verdict, summary, issues[], capabilities[], grader, conf,  │
        │                     run_receipt}                                               │
        │  Gate = typed_reducer(reports): required-grader PRESENT *and ATTESTED* →        │
        │  per-kind trust CEILING clamp → attribute. progressed = STRICT-SUBSET shrink    │
        │  over scrubbed fingerprints                                                     │
        └───────┬───────────────────────────────────────────────────────┬───────────────┘
                │ percepts (uniform envelope)                            │ verdicts gate writes
                ▼                                                        ▼
   ┌────────────────────────────────┐                  ┌───────────────────────────────────┐
   │     SENSES / PERCEPTION BUS     │                  │   BRAIN / MEMORY (internal vocab;  │
   │  sight = AgentVision adapter    │                  │            NOT "a brain")          │
   │   (MCP/CLI/lib; local|anthropic)│  episodes ─────► │  Context assembly under a TOKEN    │
   │  logs · tests · metrics · types │                  │   BUDGET (this is NOT working mem) │
   │  grounded=precise, vision=advis.│  ◄──── RAG       │  Short-term: session.jsonl + BB    │
   │  + entailment gate (NOT LLM-only)│  (assembler)    │  Long-term: episodic vec · semantic│
   └────────────────────────────────┘                  │  Consolidation: per-episode EXTRACT│
                                           ▲            │   + cross-episode SCHEMA INDUCTION │
                                           │            │   + interference/inhibition        │
                                           │            └───────────────────────────────────┘
        ┌──────────────────────────────────┴───────────────────────────────────────────┐
        │                    TOOL-SMITH / TOOLING  (registry = procedural memory)        │
        │  v1: promotion-on-eval gate (attested, held-out).   v2: tool-smith             │
        └────────────────────────────────────────────────────────────────────────────────┘
```

**Data flow.** A `goal` enters the Fleet. The Orchestrator decomposes it; Managers fan out to Workers in isolated git worktrees. Each Worker action is a *hypothesis*; before it can close, the relevant **Senses** produce `Percept`s (sight from AgentVision, plus logs/tests/types/metrics/cost), which the **Verdict bus** reduces into a single gate verdict (`pass`/`warn`/`fail`) with per-issue attribution. Passing, grounded outcomes append as episodes to the **Brain**; an offline consolidation job promotes verified facts/skills into shared tiers; the **Tool-smith** authors missing tools, which enter the registry (procedural memory) only after passing an attested, held-out eval. The Brain serves context back to the Fleet by retrieval + bounded assembly. The bus is the single point through which "progress," "done," and "what compounds" are all decided.

---

## 5. The Brain — full memory architecture (internal vocabulary, not external positioning)

### 5.1 The honest frame  `[v1 conceptual]`

An LLM is a stateless function `f(context) → tokens`. "Memory" is **state stored outside the model and selectively re-injected**. The brain map exists for *legibility of the memory subsystem*, not for marketing. Every row names the mechanism and where the metaphor breaks. **Two human systems the naive draft kept as analogues — working memory and prospective memory — are demoted to honest non-analogues, because each maps to its own negation.**

### 5.2 Human memory → CS mechanism → where the analogy BREAKS  `[v1 conceptual]`

| Human system | What it does | Verel CS mechanism | Where the analogy BREAKS / verdict |
|---|---|---|---|
| **Working memory** (capacity-limited ~4 chunks, attention-gated bottleneck) | Active manipulation of a small, interference-protected set, forcing chunking/prioritization | **There is NO working-memory store.** Verel has **bounded context assembly** (§5.6): long-term reads re-injected into a prompt under a hard token budget. | **CUT as an analogue.** The residual stream is an inference-time artifact Verel cannot inspect, write, or bound — not a store. The KV cache is a recomputation cache, not WM. We state flatly: **"Verel has no working memory; it has context assembly under a token budget."** What we *do* build (§5.6) is the one buildable thing WM's *function* demands — a capacity bound + eviction policy + interference rule — without pretending it is the neural mechanism. |
| **Episodic memory** (events, autobiographical) | "What happened, when, where" | **Append-only event log** (`session.jsonl`) of episodes; indexed in a **vector store** for similarity recall | Human episodic recall is reconstructive/lossy, re-rendered each retrieval. Ours is byte-exact replay — perfect fidelity, *no* generalization at recall. Generalization is a separate offline pass (§5.5), never automatic. |
| **Semantic memory** (facts, concepts) | Decontextualized knowledge | **Fact store: vectors + typed triples in ONE backend** (§5.3); facts carry provenance + epistemic-confidence + retrieval-strength + entailment evidence | Humans bind semantics with spreading activation. Ours is explicit records, no emergent inference. Schema induction is a *separate cross-episode pass* (§5.5 step 2b) — exactly where **false memories** can enter (named failure mode). |
| **Procedural memory** (skills, "how to") | Implicit cognitive/motor skills | **Skill/Tool Registry**: versioned executable artifacts (`SKILL.md` + scripts, MCP tools, saved chains), retrieved by tool-search | Human procedural memory is implicit/non-introspectable; ours is fully explicit code/text — inspectable, diffable, rollback-able. "Skill acquisition" = authoring + eval-gating, not motor tuning. |
| **Prospective memory** (intentions, cue-dependent, *unreliable*) | "Do X when Y happens", with characteristic cue-detection FAILURE, monitoring cost, intention deactivation | **Durable cue-bound event queue** (§5.8) | **CUT as a brain analogue.** A reliable durable cue-matcher is a database trigger. The defining, *studied* property of human PM is its *unreliability* (cue-detection failure, prospective/retrospective split, monitoring cost) — exactly what we engineer away. The word loses the brain label, same treatment as "the agent dreams." *(Optional v3: §5.8 sketches re-earning the label by modeling intention-deactivation as a real failure signal.)* |
| **Consolidation** (systems vs synaptic — two distinct processes) | Hippocampal→neocortical transfer with **interleaved replay** to extract schemas/gist across many episodes (systems, CLS); tagging/capture over hours (synaptic) | **Two-stage offline job** (§5.5): (2a) per-episode EXTRACT (information extraction) AND (2b) **cross-episode SCHEMA INDUCTION** (cluster N episodes → synthesize a DesignRule whose evidence is the cluster). Only (2b) earns the words "systems consolidation / episodic→semantic." | A naive draft conflates systems and synaptic consolidation and implements neither's signature property. Fixed: (2b) is the genuine episodic→semantic step. **Analogy break stated honestly: human consolidation is offline because replay needs the hippocampus offline to avoid interfering with encoding; our job is offline for an UNRELATED reason — cost/latency batching. We do not claim the neural rationale.** |

> **Footnote — the sensory buffer is a buffer, not a memory "system."** Iconic/echoic → an in-proc ring buffer with no pre-attentive fusion. Named as the trivial buffer it is.

**The single most important honest statement: there is no continuous learning.** If the consolidation job never runs, the agent is a goldfish with good notes.

### 5.3 Build vs. rent — resolved by DELETION, not layering  `[v1 thin-vertical]`

- **v1 backend = ONE rented service: `mem0` (or Letta) behind the `MemoryView` interface.** Vector + KV + lightweight graph. We name one and **delete the rest from the v1 schema**: no self-hosted Neo4j, no LanceDB+pgvector+SQLite triple stack. The §5.4 schemas are the *interface contract* Verel enforces over whatever the backend stores.
- **Consolidation is single-writer.** One privileged job ratifies writes to shared tiers. **CRDT support-counters are CUT** (§12): single-writer already serializes the only contended field.
- **Verel owns the layer no commodity provides:** trust/provenance + entailment evidence, verdict-gated promotion, the AgentVision-grounded salience signal, the consolidation conflict/interference policy, and — critically — the **cross-store consistency contract** between the rented backend and Verel's own event log (§5.9).

### 5.4 Concrete stores & schemas  `[v1 thin-vertical]`

```
LAYER       STORE                BACKEND (v1)                    LIFETIME    WRITE PATH
──────────────────────────────────────────────────────────────────────────────────────────
Sensory     observation_queue    in-proc ring buffer             ms–1 turn   synchronous
"Working"   context window       prompt (assembled under budget) 1 call      assembler (§5.6)
            scratchpad           /run/<id>/scratch.md            1 session   agent write
Short-term  episode_buffer       session.jsonl (append) + BB     1 session   after each step
Long-term   episodic_index       mem0 vector namespace          ∞           outbox→applier (§5.9)
            semantic_facts       mem0 vector+graph namespace    ∞           outbox→applier (entailment+corroboration gated)
            design_rules         mem0 vector namespace          ∞           cross-episode induction (§5.5 step 2b)
            skill_store          git repo of SKILL.md+code       ∞           author/consolidate (eval-gated, held-out, attested)
            intention_queue      durable queue + cue-matcher     until fired transactional claim (§6.8)
```

> The `"Working"` row is in quotes deliberately: it is **context assembly under a budget**, not a working-memory store (§5.2). It is listed because it is where the budget/eviction/interference policy lives (§5.6), not because it is a memory system.

**Episode record** (short-term; one per agent step):
```json
{
  "id": "ep_01J...", "session_id": "s_…", "agent_id": "fleet/ui-fixer",
  "ts": "2026-06-18T10:02:11Z", "goal": "fix overflow on /checkout",
  "action": {"tool": "Edit", "args_digest": "sha256:…"},
  "observation": {"kind": "agentvision_report", "verdict": "warn",
                  "issue_signature": "h:4f9c…",
                  "issues": [{"kind":"overflow","severity":"warning","locator":"[.cart]","locator_precise":true,"source":"dom"}]},
  "outcome": "progressed", "salience": 0.62, "bayes_surprise": 1.8, "verdict_delta": "+warn", "tokens": 1840
}
```

**Semantic fact** (long-term, consolidated — note the SPLIT of epistemic confidence vs retrieval strength, and per-item-type decay):
```json
{
  "id": "fact_01J...",
  "text": "Tailwind `overflow-x-auto` on .cart-table fixes horizontal overflow at <=375px",
  "embedding_ref": "vec:…",
  "subj_pred_key": "css:overflow-x-auto|fixes",          // pattern-separation / interference key (§5.7)
  "entities": ["component:cart-table","css:overflow-x-auto","viewport:375"],
  "relations": [{"subj":"css:overflow-x-auto","pred":"fixes","obj":"issue:overflow"}],
  "epistemic_confidence": 0.81,                           // truth; moved ONLY by corroboration/contradiction
  "support_count": 4, "contradiction_count": 0,
  "grounding": "precise",                                 // requires a PRECISE same-episode source (§5.5)
  "item_type": "ui_fix",                                  // selects decay params (§5.5 step 7)
  "provenance": [{"episode":"ep_…","source":"agentvision/dom","entailment_score":0.94,
                  "precise_corroborator":"dom"}],
  "retrieval": {"retrieval_count": 12, "last_retrieved":"2026-06-17",
                "retrieval_strength": 0.66, "base_half_life_days":90, "beta":0.6},
  "scope": "repo:checkout-web", "trust": "corroborated"
}
```

**DesignRule** (cross-episode induced — the *only* record that may generalize beyond one episode):
```json
{
  "id":"rule_01J...","predicate":"viewport<=375 && component=='data-table' => require overflow-x-auto",
  "evidence_cluster":["ep_a","ep_b","ep_c","ep_d"],      // entailment evidence = the CLUSTER, not one episode
  "support_count":4, "held_out_eval":{"suite":"ui-overflow-v3","verdict":"pass","sha":"a1b2"},
  "grounding":"inferred",                                 // induced rules start 'inferred'; promote only via held-out eval
  "scope":"repo:checkout-web", "trust":"corroborated"
}
```

**Skill record** (procedural):
```json
{
  "id": "skill_fix_overflow", "kind":"procedure", "version":"3",
  "trigger":"AgentVision reports issue.kind == 'overflow' with source in {dom,cv}",
  "entrypoint":"skills/fix_overflow/SKILL.md", "deps":["agentvision"],
  "success_rate": 0.74, "runs": 53, "owner":"fleet", "trust":"verified",
  "last_eval":{"verdict":"pass","sha":"a1b2","held_out_suite":"ui-overflow-v3","ts":"2026-06-15",
               "run_receipt_ref":"rr_…"}
}
```

**Intention record** (durable cue-bound queue — NOT "prospective memory"):
```json
{
  "id":"int_01J...","trigger":{"type":"event-cue","predicate":"pr.merged && repo=='checkout-web'"},
  "action":{"agent":"regression-runner","prompt":"re-run AgentVision baseline on /checkout"},
  "idempotency_key":"int_…:<event_id>", "ttl":"2026-12-01","status":"armed",
  "armed_ts":"2026-06-18T...", "deactivate_on_fire":true        // (v3) intention-deactivation hook, §5.8
}
```

> **Schema-naming resolution.** Canonical field is **`locator`** (generalized `bbox`) with **`locator_precise: bool`**; identity function is **`issue_signature()`** (§7.2). Memory records carry **`grounding ∈ {precise, advisory, inferred}`**; `inferred` is a real state (failed-precise-corroboration but kept). **Epistemic confidence and retrieval strength are SEPARATE fields and never multiplied into one another** (§5.5 step 7).

### 5.5 Consolidation pipeline ("dream" pipeline) — two stages, where everyone fails, and how we don't  `[v2; the cross-episode induction, the split decay model, and the corroborated entailment gate are the novel parts]`

**Why attempts fail (SIX named modes):**
(a) consolidate everything → swamp; (b) no conflict resolution → contradictory facts poison retrieval; (c) no forgetting → unbounded growth; (d) inline on an expensive model → never runs at scale; (e) no provenance → can't audit/undo; **(f) GIST-DISTORTION / CONFABULATION** — lossy episodic→semantic summarization invents *unentailed* claims (the DRM/false-memory analogue), laundering a Haiku hallucination into `grounding: precise`.

**The tension resolved.** You cannot simultaneously claim "episodic→semantic gist-ification" AND gate out everything not entailed by a *single* episode — the entailment gate forbids exactly the inductive leap that defines semantic memory. **Resolution by SPLITTING the two claims onto two mechanisms with two evidentiary bars:**

- **Per-episode EXTRACT (step 2a)** is *information extraction*, not generalization. A fact may not assert more than one episode supports. The **per-episode entailment gate** (step 3) lives here — it correctly forbids single-episode confabulation.
- **Cross-episode SCHEMA INDUCTION (step 2b)** is where generalization is *allowed and expected*. Its evidentiary bar is **corroboration count + a held-out eval**, NOT single-episode entailment. An induced `DesignRule`'s "entailment evidence" is the *cluster* of episodes; it cannot promote past `inferred` → `corroborated` without passing a held-out graded eval. This is the genuine episodic→semantic transfer; gated by *generalization evidence*, so the contradiction is gone.

Pipeline (scheduled background task; cheap **Haiku** extract/dedup via **Batches API ~50% cost**; **Opus 4.8 / Fable 5** for hard conflict reasoning):

```
 episode_buffer (session.jsonl)
        │  TRIGGER: session-end OR N episodes OR nightly cron OR token-pressure
        │  (NB: offline for COST/LATENCY batching, NOT for the neural replay reason — §5.2)
        ▼
 [1 SALIENCE FILTER — two-stage gate; computational SURPRISE, no dopamine gloss]
        ▼
 [2a PER-EPISODE EXTRACT]   Haiku: episode → candidate facts (structured output)
 [2b CROSS-EPISODE INDUCTION] cluster N episodes by (kind, component, viewport)
                              → synthesize DesignRule (evidence = cluster)
        ▼
 [3 ENTAILMENT GATE]  per-episode facts: NLI + REQUIRED precise same-episode corroborator
        ▼
 [4 DEDUP + PATTERN-SEPARATION]  refuse/merge near-duplicates; enforce subj_pred_key uniqueness
        ▼
 [5 CONFLICT RESOLUTION + RETRIEVAL-INDUCED INHIBITION]  higher-trust suppresses contradicting lower-trust
        ▼
 [6 WRITE-BACK]   via transactional outbox (§5.9); promote sequences → skill_store (eval-gated, attested §7.7)
        ▼
 [7 DECAY/FORGET]  per-item-type power law on RETRIEVAL STRENGTH only (never on epistemic confidence)
```

**Step 1 — Salience filter, as computational SURPRISE (drops the dopamine costume).** A naive draft labels Stage A "dopaminergic novelty / synaptic-tagging-and-capture." That gloss is false rigor: a `verdict_flip` boolean is not a signed, magnitude-graded reward-prediction-error, and tagging-and-capture is protein-synthesis LATE-LTP over hours, not which log lines to keep. **We drop the neuro labels and use a real surprise signal with magnitude:**

```python
def salient(ep, run) -> bool:
    # STAGE A — HARD KEEP: high computational surprise (Bayesian surprise = KL of issue-set posterior||prior)
    surprise = kl_divergence(run.issue_set_posterior_after(ep), run.issue_set_prior_before(ep))
    if surprise >= SURPRISE_KEEP_NATS or signature_unseen(ep.issue_signature):
        ep.bayes_surprise = surprise
        return True
    # STAGE B — SOFT SCORE (all terms normalized to [0,1]; weights are UN-FIT DEFAULTS)
    goal_relevance = minmax(cosine(ep.goal_emb, run.goal_emb))
    cost           = minmax(ep.tokens, lo=run.p10_tokens, hi=run.p90_tokens)
    score = 0.6*goal_relevance + 0.4*cost
    return score >= KEEP_PERCENTILE_THRESHOLD              # tunable percentile of the batch, not a magic ratio
```

- **Bayesian surprise** (KL between issue-set distributions before/after the episode) is signed-in-effect and magnitude-graded — a real computational salience model. The cheap "verdict_flip OR signature_unseen" fallback is kept only when a posterior can't be estimated.
- The "~80% dropped" figure is **explicitly a hypothesis to measure**, not a result; we report the *measured* drop rate from the eval harness.

**Step 3 — Entailment gate, NOT an LLM alone (closes the contradiction with §10.1).** A single Haiku NLI call must not solely decide `grounding: precise` — that violates "an LLM never solely gates a consequential, compounding, money-spending action." Promotion into shared memory auto-fires skills later; it is consequential. **Fixed to the document's own corroboration rule:**
- A candidate fact may carry **`grounding: precise` ONLY IF** (i) Haiku NLI `entailment_score ≥ 0.85` **AND** (ii) the SAME episode contains a **precise source** (`dom/cv/ocr` or a deterministic test verdict) whose output is consistent with the fact's `relations`. Single-Haiku entailment with no precise corroborator **caps the fact at `grounding: inferred`** — never `precise`.
- `0.5 ≤ score < 0.85` and no corroborator → `grounding: inferred`, low starting epistemic confidence, never promotable to GLOBAL until independently corroborated and held-out-eval-passed.
- `score < 0.5` → **dropped.**
- The verbatim episode stays in cold storage as auditable ground truth, so a disputed fact is always re-checkable against source.

**Step 4 — Pattern-separation at write (interference defense, named).** At write, **refuse near-duplicate facts and MERGE** rather than append; enforce **`subj_pred_key` uniqueness within a scope** (two facts with the same subject+predicate in the same scope cannot co-exist — they reconcile, step 5). This is pattern separation; it prevents two near-duplicates both surfacing at retrieval.

**Step 5 — Conflict resolution + retrieval-induced inhibition.** Same `subj+pred`, different `obj`: do NOT silently keep both. Resolve by trust then recency; the loser is **inhibited** (marked `suppressed_by: <winner_id>`), not co-admitted, so retrieval cannot return contradictory facts simultaneously (the retrieval-induced-forgetting analogue). A hard contradiction on a `verified` fact queues human/agent review. Defended failure modes named: **proactive interference** (old fact impairing a new correction), **retroactive interference** (new fact burying a still-valid old one), **cue overload / fan effect** (one cue matching too many facts → MMR cap + scope filter, §5.6).

**Step 7 — Decay: DECOUPLE epistemic confidence from retrieval strength; per-item-type params.**

```python
# TWO orthogonal quantities, never multiplied into one stored field.
# (1) epistemic_confidence: moved ONLY by corroboration(+) / contradiction(-). Retrieval NEVER touches it.
# (2) retrieval_strength: power-law of disuse, reset+extended by recall (testing effect).

P = ITEM_TYPE_PARAMS[fact.item_type]    # per-type, NOT one global curve
half_life_eff   = P.base_half_life_days * (1 + P.K * log1p(retrieval_count))
age_days        = now - last_retrieved                       # reset on each recall
retrieval_strength = max(P.strength_floor, (1 + age_days/half_life_eff) ** (-P.beta))

# Ranking combines them by a DOCUMENTED rule; decay does not mutate truth:
rank_score = w_e * epistemic_confidence + w_r * retrieval_strength    # w_e, w_r logged & tunable
# Prune ONLY: retrieval_strength < 0.15 AND epistemic_confidence < 0.4 AND support_count < 2 AND trust != 'verified'.
```

`ITEM_TYPE_PARAMS` (un-fit placeholders, labeled as such exactly like salience):

| item_type | base_half_life | beta | strength_floor | rationale |
|---|---|---|---|---|
| `security` / `verified` | 365d | 0.3 | 0.5 | must stay accessible even when rarely retrieved |
| `api_contract` | 180d | 0.4 | 0.3 | medium durability |
| `ui_fix` | 90d | 0.6 | 0.15 | design-system churn |
| `cosmetic_tip` | 21d | 0.8 | 0.05 | short-lived |

**FIT procedure (specified, not hand-waved):** once the eval harness + retrieval logs exist, estimate `base_half_life` and `beta` per `item_type` by fitting the power law to observed *retrieval-success-vs-age* curves from the failure-ledger and retrieval logs (maximum-likelihood on recall hits). Until fitted, the table values are **un-fit placeholders**. Curve is power-law (Wixted), not exponential.

**Anti-swamp rules, concretely:** only salient episodes enter; per-episode entailment-without-precise-corroboration can't reach `precise`; dedup merges (never appends) and enforces `subj_pred_key` uniqueness; contradictions inhibit (not co-admit); decay prunes by *retrieval strength*, never by demoting truth.

*Where the analogy breaks:* this is clustering + `GROUP BY` + cosine + NLI + a precise-corroborator check + power-law decay, not a hippocampus reorganizing representations during sleep. **"The agent dreams" stays deleted.** The offline trigger is offline for cost/latency, **not** for the neural-replay reason — stated so the "sleep" word does no covert work.

### 5.6 Retrieval & context assembly — bounded assembly (NOT working memory; the context-rot firewall)  `[v1 = recency + scope + confidence-gate + budget + interference rule; the 5-weight MMR scorer is v2]`

**This section delivers WM's FUNCTION without claiming WM's mechanism.** WM's defining computational role is a small, attention-gated bottleneck protecting against interference and forcing prioritization. We build exactly that as a **policy over the assembled context**, not a neural buffer:

1. **Hard token budget per role** — `CONTEXT_BUDGET[role]` cap (e.g., working set ≤ ~40% of window). The capacity bound WM's function requires; we own it, inspect it, bound it.
2. **Explicit eviction/priority policy** — when assembly exceeds budget: keep frozen prefix (identity/invariants) → required percepts (last verdict) → highest `rank_score` facts → recent episodes; evict lowest-priority first; summarize-on-overflow via SDK compaction.
3. **Interference-avoidance rule (the WM-function fix):** **never co-admit two facts with the same `subj_pred_key`** in one assembled context (read-side pattern separation, mirroring write-side §5.5 step 4). When a higher-trust fact and a contradicting lower-trust fact both match, the lower is **inhibited, not co-admitted**.

> Stated plainly: **Verel has no working memory; it has bounded context assembly under a token budget with an eviction policy and an interference rule.** That delivers WM's *computational function* without an inference-time metaphor we can't touch.

**v2 scorer (target, not v1):**
```
score(item) = α·relevance(query ⊗ goal embedding)
            + β·recency(exp decay over episode_buffer)
            + γ·importance(w_e·epistemic_confidence + w_r·retrieval_strength + trust)   ← split fields, §5.5
            + δ·goal_conditioning(KG distance to active goal entities)
            − λ·redundancy(MMR penalty vs already-selected)
```

Assembly order respects **prompt-cache prefix stability** (frozen first, volatile last) in v1 and v2:
```
[SYSTEM: identity + invariants]   ← frozen, cached
[SKILLS: descriptions only]       ← stable, cached; full body on tool-search hit
[SEMANTIC: top-k facts]           ← scoped, rank_score-gated, subj_pred_key-unique
[EPISODIC: k recent + k similar]  ← recency + relevance
[SCRATCHPAD + last percept]       ← volatile, last → no cache thrash
```

**Anti-poisoning (v1):** rank-gate (low-rank facts never enter); advisory facts labeled in-prompt (`[src:vision conf:low advisory]`) so a low-trust fact is *visibly* distrusted; hard budget + summarize-on-overflow; scope filter first so a fleet on different repos never cross-contaminates; the `subj_pred_key` interference rule above.

### 5.7 Identity, continuity, and fleet-shared vs private memory & provenance  `[single-agent continuity = v1; TEAM/GLOBAL tiers = v2; CRDT = CUT]`

**Single-agent continuity (v1):** identity = stable `agent_id` + pinned persona + private scoped stores. A session restores by loading persona + scoped facts + last N episodes. Continuity is *reconstructed retrieval* — waking up and reading your own diary, not a resumed process.

**Fleet tiers (v2):**
```
PRIVATE   per-agent episodic + scratch          (never shared)
TEAM      per-repo/project semantic + skills     (shared within a fleet on that repo)
GLOBAL    org-wide verified skills + facts       (curated, high-trust only)
```
- **Provenance & trust tiers:** every shared record carries `provenance[]` (episode, source, entailment evidence) and a trust level: `unverified → corroborated (support_count≥3) → verified (passed a held-out, attested graded eval or human sign-off)`. Only `verified` promotes to GLOBAL.
- **Write model = SINGLE-WRITER, CRDT CUT.** The consolidation job is the **only** writer to TEAM/GLOBAL; agents *propose*, consolidation *ratifies*. With a single writer there is no concurrent-write contention, so CRDTs are dead weight (removed).
- **Anti-swamp at fleet scale:** GLOBAL admission is verified-only, entailment+precise-corroborated, MMR-deduped, capped. A bad fact stays `unverified` and scoped until it independently corroborates *and* passes a held-out eval.

### 5.8 The intention queue (durable cue-bound queue — NOT prospective memory)  `[v2; intention-deactivation = v3]`

The brain label is **cut**: this is a durable event queue, not human prospective memory (§5.2). An intention is `{cue-predicate, action, idempotency_key, ttl}`; firing correctness under restart is a distsys concern (§6.8), not a memory metaphor.

> **(v3, optional) Re-earning the label, honestly.** If we ever want the words back, we must model PM's *characteristic* property — failure. Sketch: an armed intention that never fires within `ttl` is logged as a **prospective-memory FAILURE event**, fed back into scheduling (add explicit monitoring or escalate). Modeling intention-deactivation and the monitoring cost is the only thing that would make "prospective memory" non-fraudulent. Until then it stays a queue.

### 5.9 Cross-store consistency contract — the memory dual-write fix  `[v1 — non-negotiable]`

**Closes the distributed-failure hole: the correctness story assumed mem0 is a reliable single source of truth, with no contract for "mem0 write succeeds but our event-log write fails" (or vice-versa).** Same bug class §6.2 fixed for git side-effects, fixed identically here:

- **Verel's own append-only event log is the single source of truth Verel controls.** mem0 is a **downstream projection**, not the system of record.
- Consolidation writes go through a **transactional outbox**: the fact + an `outbox` row are committed in ONE transaction to Verel's event log. A separate **idempotent applier** reads the outbox and **upserts into mem0 keyed on `fact_id`** (re-apply is a no-op).
- **On resume:** replay un-applied outbox entries. A consolidation job that wrote to the event log then crashed before mem0 was updated re-applies cleanly (idempotent upsert); a job that updated mem0 but not the outbox cannot happen, because the outbox commit is the *source*, and the applier is the only writer to mem0. No dup, no orphan.

---

## 6. The Fleet — agents managing agents, dynamic workflows, multi-repo

The orchestration layer is a **control plane** over the Claude Agent SDK's execution primitives. **The SDK runs agents; Verel decides which agents run, why, with what budget, and whether their output is trustworthy.**

> **v1 scope cut.** A full distributed-systems v1 control plane (worker fencing tokens + side-effect WAL + lease ledger + deterministic resume) is over-engineered by an order of magnitude for a greenfield small team. Resolution: **v1 is a single-process, single-writer-per-run scheduler with a file-based WAL/outbox and NO worker fencing tokens.** Fencing only matters under concurrent managers — which §6.7 defers to v3 — so worker fencing is moved to the same v3 bucket as vector clocks (§12). The hard distsys (worker fencing, the §6.2 git fencing sink, phi-accrual) is **v3**; v1 keeps the minimum for crash-safe resume of one writer. The full target architecture is documented below with phase tags so v3 has a spec.

### 6.1 Agent topology & supervision  `[v1 = roles + retry + heartbeat; worker fencing = v3]`

Five **roles**, not five processes:

| Role | Responsibility | Default model | Phase |
|---|---|---|---|
| **Orchestrator** | Top-level goal, budget, workflow graph. One per run. | Opus 4.8 | v1 |
| **Manager** | A sub-goal; fan-out vs. do-it-myself; spawns workers. | Sonnet 4.6 | v1 |
| **Worker** | Scoped task in an isolated worktree. | Sonnet 4.6 / Haiku | v1 |
| **Critic/Verifier** | Independently grades output. Never writes product code. | Haiku 4.5 | v1 |
| **Tool-smith** | Builds missing tools/MCP/skills on demand. | Sonnet 4.6 | **v2** |

OTP vocabulary is demoted to a retry-policy table + heartbeat (there is no live process to link to). v1 ships per-role `{max_restarts, backoff, on_fail: retry|quarantine|escalate}`.

**Failure detection (v1) — single-writer makes this tractable.** Because v1 is single-writer-per-run (§6.7), the scheduler is the *sole* authority that declares a worker dead and spawns a replacement — so **two managers cannot both declare the same worker dead** (the split-brain a naive fencing design fights). A worker writes a heartbeat every `H`; the scheduler marks it *suspect* after `2H`, *dead* after `T_dead = 6H` (so a slow Opus call within its wallclock budget isn't mistaken for death). A suspect worker is **paused at its next `PreToolUse` hook** and must re-confirm it still owns its worktree lease before any further mutation.

**Worker worktree lease (v1) = a local advisory lock; FENCING TOKENS = v3.** v1 gives each worker an exclusive local lease on `.nirvana/wt/<task-id>`. Because there is exactly one scheduler, a stale worker cannot race a replacement *through a second manager*. The full fencing-token + server-side fencing sink design is v3.

> **`[v3]` Fencing SINK — the enforcement point git lacks.** A `PreToolUse` hook checking a token before `git push` is pure TOCTOU: token valid at hook time, lease revoked, push lands anyway (separate syscall). git has no concept of a fencing token. The real fix is a **fencing sink at the durable ref update**: route ALL worker git mutations through a **Verel-controlled remote** (or local bare repo) whose **`pre-receive`/`update` hook** reads the current fencing token for `<task-id>` from the ledger and **rejects any push whose ref does not carry/match it**, performing the check **atomically with a ref CAS** (`git update-ref --stdin` with `old-sha`) in the same server-side hook. Token check + ref CAS in one server-side transaction is the only place fencing is real. v3 because v1 has no concurrent managers to fence against — specified now so "fencing is decorative" is honestly absent from v1, not true of the *target* architecture.

**Map to SDK primitives.** A Verel node = one SDK subagent invocation (or background task). A `PreToolUse` hook enforces budget/lease; a `Stop` hook runs the verifier gate before "done" is accepted — generalizing AgentVision's Claude Code skill to *all* verifiers.

**Fan-out decision** (manager emits structured output; the plane validates and clamps):
```jsonc
{ "decision": "fan_out" | "self", "rationale": "string",
  "subtasks": [ {"id","goal","repo","deps":["id"],"est_tokens","verifier":"name"} ],
  "concurrency_cap": 4 }
```
Fan out only when subtasks are **independent** (`deps` form an antichain), **individually verifiable**, and largest `est_tokens` < doing it inline.

### 6.2 Dynamic runtime-generated workflows + deterministic resume with a SIDE-EFFECT WAL  `[v1 WAL+verdict ordering; v3 adds the fencing sink]`

`Task`:
```jsonc
Task {
  id, role, goal, repo, worktree,
  deps: [id], barrier_policy: {kind:"all|k_of_n|optional", k?},   // §6.6: not just "all must PASS"
  verifier: "tests|agentvision|schema|none",
  budget_lease: {max_tokens, max_usd, max_wallclock_s, max_iters, max_output_tokens},   // §6.5
  retry: {max:3, backoff_s:[5,30,120], on_fail:"quarantine|escalate"},
  state: "pending|ready|running|passed|failed|quarantined|skipped",
  attempt, last_report_ref, fingerprint, pre_intent_sha, fencing_token  // fencing_token populated v3
}
```

Workflows are **runtime-generated**: managers emit `Task` DAGs as structured output during the run; the scheduler validates acyclicity and admits them. `Scheduler.patch()` mutates the live DAG (injects fix-nodes) under the guards in §6.6.

**Deterministic resume — write-ordering protocol WITH a mutate-abort recovery step.** A task's *effect* is a git mutation, not a pure function of inputs. Protocol:

```
0. RECORD pre_intent_sha  → the worktree's HEAD/ref state BEFORE any mutation, written INTO WAL-INTENT.
1. WAL-INTENT  → fsync { task_id, fingerprint, pre_intent_sha,
                          intended_effect:{git_ref, expected_sha}, fencing_token } BEFORE any mutation.
2. MUTATE      → perform the git mutation, tagged with idempotency key = changeset-id trailer.
3. CONFIRM-REF → read back the ref; require it equals expected_sha.
4. WAL-VERDICT → fsync PASS verdict ONLY AFTER step 3 confirms the ref at expected_sha.

ON RESUME, for each task with WAL-INTENT:
  CASE A — WAL-VERDICT==PASS AND durable ref == expected_sha  → memoize as passed.
  CASE B — WAL-VERDICT==PASS but ref missing/wrong            → NOT passed → re-run (idempotent via trailer).
  CASE C — WAL-INTENT present, WAL-VERDICT ABSENT             → MUTATE-ABORT/RECOVERY, then re-run:
             git rebase --abort 2>/dev/null || git merge --abort 2>/dev/null || true
             git reset --hard <pre_intent_sha>            # clean rollback REQUIRES the recorded pre_intent_sha
             git worktree prune
             # now the worktree is at a known-clean sha; re-apply the task from scratch.
```

A naive draft handles only the PASS case (A/B) and would **compound corruption** on an interrupted rebase / dirty index / detached worktree (Case C). "Idempotent via the changeset-id trailer" only holds if re-application is a pure replace — an interrupted rebase is NOT a no-op. Recording `pre_intent_sha` *into WAL-INTENT* is what makes clean rollback possible; without it, rollback is impossible. Every transition is logged-and-fsynced before externally visible and idempotent on replay.

- **Concurrency caps** = semaphore per `(run, repo, role)` + global cap.
- **Barriers** gate on verifier PASS per `barrier_policy` (§6.6), not raw completion.

### 6.3 Multi-repo orchestration with worktrees  `[v3+/research; v1 = MANUAL COORDINATION]`

Workers operate in isolated **git worktrees** (`.nirvana/wt/<task-id>`) so concurrent edits never collide in a working tree. True cross-repo atomicity without a monorepo is distributed-transactions research; a half-working compensating revert can corrupt repos. **v1 ships MANUAL coordination** (human/orchestrator lands repos in order, one PR at a time). v3+ target:

- **Isolation via merge queue / staging-branch fast-forward.** A changeset lands through a per-workspace merge queue holding a lock on each repo's default branch for the two-phase land, OR lands to staging branches and **fast-forwards all-or-nothing** — so consumers cannot build on A while it is locked/staged.
- **Bounded, quantified inconsistency window** — the fast-forward batch duration; default **max 90s**, emitting a `freeze-consumers` signal to dependent CI.
- **Compensation-of-compensation specified** — if the revert PR conflicts, escalate to a **human freeze + manual reconciliation**; never silently leave inconsistency. A git revert is **not** a guaranteed compensation, which is exactly why isolation is mandatory.

Labeled a **saga with compensations and a bounded inconsistency window** — not "atomic commits across repos."

### 6.4 Communication & shared state (the blackboard) — ONE consistency model per store  `[v1]`

1. **Directed messages** — `delegate(goal+criteria+lease)` / `report(result)`. Outcome contracts, not RPC. Child returns `TaskResult{verdict, artifacts[], issues[], spend, trace_ctx}`.
2. **Run blackboard** = **single-writer-per-key, last-writer-wins + a version vector for conflict detection (stale puts REJECTED)**. `blackboard.put(key, value, expected_version)` fails if stale, giving **read-your-writes** for coordination data fan-out correctness depends on. Not append-only, not CRDT — a versioned KV with optimistic concurrency.
3. **CRDT** — **reserved for nothing in v1.**

### 6.5 Budgets & runaway protection — a LEASE/RESERVATION ledger WITH per-call output reservation  `[v1]`

**Fixes the distributed-counter race AND the mid-call overshoot.**

- A parent **issues a signed budget lease** (`max_tokens`, `max_usd`, `expiry`) to each child. Issuance **atomically decrements** the parent's remaining via a **single-writer ledger actor**.
- A child spends **only against its own lease** — no shared-counter reads at spend time, so no race at the hot path.
- **Per-call output reservation (the overshoot fix).** An LLM call in flight cannot be pre-checked against the remaining lease, because output token count is only known *after* the call returns. So a single call can overshoot a lease by its full output. The "no race" claim was only true at **issuance** granularity. Fixed: at issuance, **reserve `max_iters × max_output_tokens × out_price` headroom**; AND the `PreToolUse` gate **refuses to START a call when `remaining_lease < worst_case_next_call`** (`worst_case_next_call = max_output_tokens × out_price + est_input_cost`). **Stated overshoot bound: at most one call's `max_output_tokens × out_price`, which is pre-reserved, so the lease invariant holds even on the last call.**
- **Unused lease returns** to the parent on task close.
- Overrun → task `failed`, not silent overspend.

### 6.6 Liveness, deadlock, barrier policy, and runaway detection  `[v1]`

- **Barrier policy is not "all must PASS" by default.** `barrier_policy ∈ {all, k_of_n, optional}`. A `k_of_n` join proceeds when `k` deps PASS; `optional` deps don't gate. A quarantined dep is a permanent non-PASS, counted against the policy — so a single quarantine no longer necessarily collapses the join; only an `all`-barrier with a quarantined required dep fails fast (by design), and the detector then re-routes via `patch()`.
- **Quarantine→patch→quarantine termination.** `Scheduler.patch()` can inject a fix-node upstream of a barrier at runtime. Guards: (1) `patch()` **must validate the DAG stays acyclic**; (2) a **HARD CAP of `P` fix-node injections per barrier** (default `P=3`), after which the join **escalates to a human** instead of patching again. This makes the patch→quarantine→patch loop **provably terminate** in ≤ `P` injections per join, *independent of the budget ceiling* — an agent cannot keep patching new failing fix-nodes until money runs out. A patched-in fix-node *can* clear a quarantine and re-arm the barrier, but only `P` times.
- **Oscillation/runaway detection.** A→B→A ring-buffer check **parameterized to cycle length ≤ k** (not just 2), **combined with a marginal-yield derivative** (§7.3) so monotonic decoy churn (A→B→C→D) can't evade both guards. Circuit breaker trips on (a) per-run **global spend-rate** ceiling AND (b) a **spawn-rate limiter** (default: ≤ 8 new agents/min/run, ≤ 32 concurrent).

### 6.7 Clock & ordering assumptions  `[v1 = single-writer-scheduler; distributed = v3+]`

Event-log ordering, fingerprint reproducibility, and "land in topological order" assume a **total order**. **v1 is explicitly per-run single-writer-scheduler** — the only model under which §6.2 resume is sound, and the reason worker fencing is unnecessary in v1 (§6.1). Lamport/vector clocks across distributed managers are **v3+/research**.

### 6.8 Intention firing — TRANSACTIONAL dedup, not "idempotent effect"  `[v2]`

Spawning an agent spends money and mutates repos — it is **NOT idempotent**, so "idempotent on the action side" is false. The dedup-check and the spawn are two operations; two concurrent fires can both pass a non-atomic check and both spawn. Fixed with a **transactional claim**:

```sql
-- Dedup is a CONDITIONAL INSERT; the spawn is gated on the insert returning a row, in one transaction.
INSERT INTO intention_fires(idempotency_key, status, claimed_at)
VALUES (:key, 'claimed', now())
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING idempotency_key;
-- if a row was returned: this fire WON the claim → spawn the agent → UPDATE status='fired'.
-- if no row:            another fire already claimed it → do nothing.
-- claimed-but-unfired rows (spawner crashed) are reclaimed after a timeout.
```

So at most one fire spawns per key. We **drop the "idempotent effect" framing for spawns** — the property we actually have is single-claimant dedup via a CAS insert.

### 6.9 Interface sketch  `[v1]`

```python
class Verel:
    def run(self, goal, workspace, budget, policy) -> RunHandle: ...
    def resume(self, run_id) -> RunHandle: ...     # replays WAL+outbox; memoizes only verdict∧ref-confirmed tasks

class Agent:                                        # one node in the supervision tree
    role; model; tools; budget_lease; memory; trace_ctx; fencing_token  # fencing_token v3
    def delegate(self, subtasks) -> list[TaskResult]: ...   # propagates trace_ctx (§6.11)
    def decide_fanout(self, goal) -> FanOutDecision: ...
    def verify(self, artifact) -> Verdict: ...      # critics only

class Scheduler:                                    # single-writer; holds a fencing lease on run_id (§6.10)
    def submit(self, spec): ...
    def patch(self, ops): ...                       # validates acyclic + caps fix-nodes per barrier (P)
    def tick(self) -> list[Task]: ...
    def on_event(self, e): ...                       # WAL+outbox append + retry policy

class BudgetLedger:                                 # single-writer
    def issue_lease(self, parent_id, child_id, lease) -> SignedLease: ...  # atomic decrement + output reservation
    def close(self, child_id) -> None: ...

class MemoryView:
    def assemble(self, role) -> Context: ...         # bounded context assembly under CONTEXT_BUDGET[role] (NOT WM)
    def episodic(self, run_id) -> list[Event]: ...
    def semantic(self, query, k=8) -> list[Fact]: ...# rank_score-gated, subj_pred_key-unique RAG
    def procedural(self) -> list[Tool]: ...
```

### 6.10 Scheduler failover — the single-writer's OWN guard  `[v1]`

"Single-writer per run" has a single point of failure with no failover story, and the resume actor is itself unguarded against split-brain. Fixed: the **scheduler holds a fencing lease on `run_id`** (a row in the ledger with a monotonic epoch + a TTL heartbeat). To start or resume a run, a scheduler process must **CAS-acquire the run lease at a strictly higher epoch**; a second scheduler starting against the same run fails the CAS and exits. If the scheduler dies, its lease TTL expires, and a supervisor (or operator) starts a new scheduler that acquires a higher epoch and replays the WAL+outbox (§6.2, §5.9). This is the *one* fencing lease v1 keeps — on the writer itself, not on workers — because it is the actual SPOF.

### 6.11 Observability & trace context — buildable, not asserted  `[v1]`

Concrete correlation model for agents-managing-agents: a **trace context** `{run_id, parent_task_id, task_id, attempt, lease_id, fencing_token?}` is **propagated through every `delegate()` and `report()`** and stamped on every WAL/outbox/event-log row and every `Report`. Debugging a deadlocked or runaway fleet is then a query: `WHERE run_id=… ORDER BY ts` reconstructs the full causal tree; `task_id → attempt → lease_id` ties spend, verdicts, and side-effects together. Without this propagation contract, "observability" is a word; with it, it is a join.

---

## 7. Eval-driven everything — the Verdict bus

### 7.1 The Verdict bus — a typed reducer with an explicit CEILING clamp, grader attestation, and named constants  `[v1]`

Core thesis: **every agent action is a hypothesis; no hypothesis is "done" until a grader returns a verdict.** AgentVision proved this for vision; Verel generalizes it.

**Honesty correction.** AgentVision's real `Report` has `backend, viewport, device_scale, image_path, schema_version='1.0'` and **no** `grader`/`cost_usd`/`artifacts`/`fingerprint`; its `issue_signature` is `frozenset((kind.value, message.strip().lower()))`; `analyze()` returns **no cost**. The Verel `Report` is an **EXTENSION reached through an adapter (§8.3)**, not a copy. `cost_usd` and per-issue `fingerprint` are **COMPUTED BY NIRVANA**.

```python
# ── NAMED CONSTANTS ──
SEV_ORDER        = [Severity.INFO, Severity.WARNING, Severity.ERROR, Severity.CRITICAL]   # index = rank
GATING_SEVERITY  = Severity.ERROR     # issues at/above this gate; used by progressed() and gating_failures()
ADVISORY_CEIL    = Severity.WARNING   # advisory graders cannot exceed this

class Verdict(str, Enum):    PASS="pass"; WARN="warn"; FAIL="fail"
class Severity(str, Enum):   INFO="info"; WARNING="warning"; ERROR="error"; CRITICAL="critical"
class Confidence(str, Enum): HIGH="high"; MEDIUM="medium"; LOW="low"

class GraderKind(str, Enum):
    VISION="vision"; DOM="dom"; OCR="ocr"; CV="cv"
    TEST="test"; TYPECHECK="typecheck"; LINT="lint"
    LLM_JUDGE="llm_judge"
    PERF="perf"; SECURITY="security"; CONTRACT="contract"; COST="cost"; OTHER="other"

PRECISE_GRADERS  = {GraderKind.TEST, GraderKind.TYPECHECK, GraderKind.LINT,
                    GraderKind.DOM, GraderKind.OCR, GraderKind.CV, GraderKind.SECURITY}
ADVISORY_GRADERS = {GraderKind.VISION, GraderKind.LLM_JUDGE}

class RunReceipt(BaseModel):           # grader-execution attestation
    suite_sha: str                     # which frozen suite actually ran
    inputs_digest: str                 # digest of the artifact/diff the grader saw
    coverage_assertion: str            # e.g. "scanned files: src/a.py,src/b.py" — must intersect the diff
    runner_identity: str               # signing identity of the separate-trust-domain runner
    signature: str                     # signature over (suite_sha, inputs_digest, coverage_assertion, runner_identity)

class Issue(BaseModel):
    kind: IssueKind; severity: Severity; message: str
    locator: str | None = None; locator_precise: bool = False
    confidence: Confidence = Confidence.MEDIUM
    source: GraderKind = GraderKind.TEST
    fingerprint: str                   # NIRVANA-COMPUTED, REQUIRED (§7.2)
    detail_json: str = "{}"

class Report(BaseModel):               # EXTENSION of AgentVision's Report via §8.3 adapter
    verdict: Verdict; summary: str
    issues: list[Issue] = []
    capabilities: list[IssueKind] = []
    grader: GraderKind = GraderKind.OTHER
    model: str | None = None
    cost_usd: float = 0.0; elapsed_ms: int = 0
    errored: bool = False              # ran-and-failed vs did-not-run
    run_receipt: RunReceipt | None = None   # required for graders in `required` set
    artifacts: dict[str, str] = {}
    schema_version: str = "2.0"
```

**The advisory clamp is an EXPLICIT CEILING, not `min`-by-key.** `min(sev, WARNING, key=SEV_ORDER.index)` returns the element with the *smallest* index and only happens to clamp correctly because WARNING sits between INFO and ERROR — it silently mis-clamps the moment ordering or the target changes. This is the single most load-bearing safety line; it must be unambiguous:

```python
def clamp_ceiling(sev: Severity, ceil: Severity) -> Severity:
    return sev if SEV_ORDER.index(sev) <= SEV_ORDER.index(ceil) else ceil

# Unit-test table SHIPPED with it:
#   clamp_ceiling(CRITICAL, WARNING) == WARNING   # advisory CRITICAL -> WARNING
#   clamp_ceiling(ERROR,    WARNING) == WARNING   # advisory ERROR    -> WARNING
#   clamp_ceiling(INFO,     WARNING) == INFO      # advisory INFO      -> INFO (not raised)
#   clamp_ceiling(CRITICAL, CRITICAL)== CRITICAL  # precise CRITICAL   -> CRITICAL (no clamp)
```

**The Gate — typed reducer with required-grader ATTESTATION.** Treating a required grader as satisfied if ANY non-errored `Report` with `grader==X` is present means an agent authoring its own CI could register a SECURITY grader returning `PASS, issues=[]` **without running any scan**. "Present-but-hollow ⇒ PASS" was the open silent-green hole. Fixed by **verifying a signed `run_receipt`**:

```python
def gate(reports, required: set[GraderKind], frozen_suites: dict[GraderKind,str], diff_files: set[str]) -> GateResult:
    # (a) DEAD-GATE: required grader absent OR errored ⇒ FAIL
    present = {r.grader for r in reports if not r.errored}
    if (missing := required - present):
        return GateResult(Verdict.FAIL, reason=f"required grader(s) absent/errored: {missing}")

    # (a') HOLLOW-GATE: required grader must ATTEST it ran the frozen suite AND covered the diff
    for r in reports:
        if r.grader in required:
            rr = r.run_receipt
            if rr is None or not verify_signature(rr):                       return FAIL("missing/forged receipt")
            if rr.suite_sha != frozen_suites[r.grader]:                      return FAIL("stale/wrong suite_sha")
            if not coverage_satisfied(rr.coverage_assertion, diff_files):    return FAIL("grader did not cover diff")

    # (b) advisory + low-confidence clamp via EXPLICIT CEILING (not min-by-key)
    gating, attributions = [], {}
    for r in reports:
        for i in r.issues:
            sev = i.severity
            if r.grader in ADVISORY_GRADERS:        sev = clamp_ceiling(sev, ADVISORY_CEIL)
            elif i.confidence == Confidence.LOW:    sev = clamp_ceiling(sev, ADVISORY_CEIL)
            gating.append((sev, i)); attributions[i.fingerprint] = r.grader
    verdict = (Verdict.FAIL if any(SEV_ORDER.index(s) >= SEV_ORDER.index(GATING_SEVERITY) for s,_ in gating)
               else Verdict.WARN if any(s == Severity.WARNING for s,_ in gating)
               else Verdict.PASS)
    return GateResult(verdict, attributions=attributions)
```

Now "a security CRITICAL gates; a vision CRITICAL cannot escalate past WARN" is enforced by code; **and a required grader must prove it ran the frozen suite (matching `suite_sha`) and actually scanned the changed files (`coverage_assertion` ∩ `diff_files ≠ ∅`)** — a hollow `PASS, issues=[]` now FAILS the gate. "Absent OR errored ⇒ FAIL" is necessary; "present-but-attested ⇒ trust" is now sufficient.

### 7.2 Generalized stuck vs. progressed — scrubbed fingerprint + named constants  `[v1; load-bearing]`

**(A) `issue_signature` uses a scrubbed `fingerprint`** (raw `message.strip().lower()` is unstable — any line number/seed/timestamp/float yields a new signature ⇒ `progressed=true` forever ⇒ **stuck never fires**):

```python
def canonicalize(msg: str) -> str:
    s = msg.strip().lower()
    s = re.sub(r'0x[0-9a-f]+', '<addr>', s)
    s = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b','<uuid>',s)
    s = re.sub(r'\b\d{4}-\d{2}-\d{2}t[\d:.]+z?\b', '<ts>', s)
    s = re.sub(r'[/\\][\w./\\-]+', '<path>', s)
    s = re.sub(r'-?\d+\.\d+', '<float>', s)
    s = re.sub(r'\b\d+\b', '<num>', s)
    return s

def fingerprint(i) -> str:                                   # per GraderKind, NIRVANA-computed
    if   i.source == GraderKind.TEST:      key = f"{i.detail['test_id']}|{canonicalize(i.message)}"
    elif i.source == GraderKind.TYPECHECK: key = f"{i.detail['rule_code']}|{i.locator}|{i.detail['symbol']}"
    elif i.source == GraderKind.LINT:      key = f"{i.detail['rule_id']}|{i.locator}"
    elif i.source == GraderKind.SECURITY:  key = f"{i.detail['cwe']}|{i.locator}|{canonicalize(i.message)}"
    else:                                  key = f"{i.kind.value}|{i.locator}|{canonicalize(i.message)}"
    return blake2s(key.encode()).hexdigest()[:16]

def issue_signature(report) -> frozenset[tuple[str,str]]:
    return frozenset((i.kind.value, i.fingerprint) for i in report.issues)
```

This **diverges from AgentVision's message-based signature, deliberately** (message normalization is too brittle to be the fleet-wide identity). A correctness invariant + test ships: *same logical failure across reruns → stable fingerprint; genuinely different failure → different fingerprint.* TEST/PERF/SECURITY graders must populate `detail`.

**(B) Progress = MONOTONE SHRINKAGE of the gating-failure set, with named `GATING_SEVERITY`:**
```python
def gating_failures(report) -> frozenset:
    return frozenset(i.fingerprint for i in report.issues
                     if SEV_ORDER.index(i.severity) >= SEV_ORDER.index(GATING_SEVERITY))   # §7.1 constant

def progressed(n, n1) -> bool:
    return gating_failures(n) < gating_failures(n1)      # STRICT SUBSET; equal-cardinality swaps = NOT progressed
```
Pure churn and growth are **not progressed**; a decoy introducing a new gating issue is **regression**. We track the failing-set cardinality curve and require it non-increasing across a window of length `W` (default `W=4`). Oscillation (§6.6) catches cycles ≤ k; strict-subset catches monotonic decoy churn.

> **Sight-sense parity, reconciled.** AgentVision's `LoopSession` (`core/loop.py`) computes `progressed/stuck` itself from `report.issue_signature()` (message-based) in an in-process dict — Verel **cannot** inject its scrubbed fingerprint there without forking the loop. **Reconciliation, stated once and bindingly: Verel does NOT rely on `LoopSession`'s in-process progressed/stuck. It persists `PerceptEvent`s (§8.2) and recomputes progressed/stuck from its OWN scrubbed fingerprints on every iteration and on resume.** The in-loop AgentVision signal is consumed only as an *advisory hint*, never the termination authority. So the *only* stuck-timing that matters is Verel's scrubbed-fingerprint one. (Trade-off acknowledged: Verel's scrubbed identity may merge two failures AgentVision's message identity would split; the invariant test guards against over-merging.)

### 7.3 The ultracode loop + the grader-ordering state machine  `[v1 loop; flaky-before-stuck ordering is v1]`

**Definition.** The *ultracode loop* is an exhaustive `find → verify → fix → re-verify` cycle that runs until the gating-failing set stops shrinking (PASS or marginal-yield collapse), driven entirely by the verdict bus — with an explicit ordering state machine that runs FLAKY detection BEFORE stuck-escalation.

**The contradiction it fixes:** §7.2's `canonicalize()` scrubs seeds/ints so a flaky test's two FAIL runs can yield IDENTICAL `issue_signature`s → the stuck detector fires → escalates haiku→sonnet→opus on a test **no model can fix because it is flaky**, burning the entire lease before FLAKY triage (which needs ≥2 runs to see a flip) ever runs. **Fixed by a stated ordering:**

```
GRADER STATE MACHINE (per loop iteration, ORDER IS BINDING):
 1. RUN PRECISE deterministic graders (tests/typecheck/lint/dom/cv/ocr/security).
 2. For each test FAILURE: run the FLAKY PROBE — N re-runs of the SAME SHA (default N=3) —
    BEFORE the stuck detector is allowed to escalate the model ladder.
 3. QUARANTINE flaky fingerprints (ERROR→WARNING) and REMOVE them from gating_failures()
    so they cannot pin the stuck signal or trigger the upgrade ladder.
 4. ONLY THEN apply stuck / model-ladder logic to the RESIDUAL deterministic-fail set.
 5. Adversarial verify ONLY advisory-sole-signal issues that would escalate past WARN.
 6. Fix one corroborated issue; re-run AFFECTED graders.
 7. Loop until PASS or the gating-failing set stops shrinking.
```

**Adversarial verification is OPT-IN (step 5), not default** — a failing unit test *is* ground truth and needs no second confirmer; doubling every grader is a money pit:

| Sole-signal grader | Independent confirmer (NOT a re-run) | Disagreement rule |
|---|---|---|
| VISION (advisory) | require corroboration by a **PRECISE** source (DOM/CV/OCR) before escalation | no precise corroboration ⇒ stays WARN |
| LLM_JUDGE (advisory) | a **second judge of a DIFFERENT model family**, blind to author reasoning, fixed rubric | judges disagree ⇒ stays WARN |
| TEST (precise) | **no second confirmer**; suspected flakiness → FLAKY probe (step 2), not a re-run | precise-vs-precise disagree ⇒ **FAIL-closed + escalate** |

General rule: **precise wins over advisory; precise-vs-precise disagreement ⇒ FAIL-closed + escalate.**

**Stop condition (numeric):** stop when (a) PASS, (b) `stuck` over the *residual* (non-flaky) gating set ⇒ escalate, or (c) **marginal-yield collapse**: `d(gating_failing_size)/d(iter) > -ε` for `M` iterations (defaults `ε=1` issue, `M=3`) while `cost_usd` accumulates. A derivative on the failing-set curve + a budget, not "the agent feels done."

### 7.4 Agent-run CI/CD with safety gates  `[v2; inner-loop + pre-commit gate are v1]`

| Stage | Location | Graders | Phase |
|---|---|---|---|
| Inner loop | local worktree | lint, typecheck, fast unit, AgentVision on changed views | **v1** |
| Pre-commit gate | local hook | unit + affected tests, fingerprint check vs failure-memory | **v1** |
| Pre-merge gate | sandbox CI runner | full suite, integration, AgentVision sheet, perf, security, regression-guard | v2 |
| Post-merge | ephemeral env | smoke/E2E, canary verdicts feeding rollback | v2 |

- **Self-healing builds (v2):** a `ci-medic` classifies each failing `Report` — infra/transient → retry; dep drift → regenerate lockfile; genuine regression → fix branch + ultracode loop. Every action re-gated.
- **Flaky triage** is wired into §7.3's state machine (FLAKY before stuck). Quarantine = ERROR→WARNING (never silently deleted), file ticket, record in failure-memory.
- **Rollback:** verdict-driven via a **deterministic policy engine** — the agent *proposes*, the engine *executes*; destructive actions never depend on an advisory grader.

### 7.5 Regression & memory of failures (failure-memory)  `[v2]`

- **Store:** every `Issue` with a stable **`fingerprint`** that reached `verdict=FAIL` enters an append-only **Failure Ledger** + vector index. Nightly clustering into named "known bugs" is v2.
- **Recall as a grader:** a `regression-guard` grader embeds the diff + new issue set, retrieves top-k past failures, emits `REGRESSION` if a resolved fingerprint reappears.
- **Synthetic-fallback exclusion.** AgentVision injects an `OTHER/WARNING/CV/low` issue and downgrades PASS→WARN when the requested vision backend is unavailable (`core/analyze.py:93-99`). The Failure Ledger and consolidation **must NOT** treat this synthetic fallback as a real failure — filtered by a `detail.fallback==true` marker the sight-adapter sets. (Note: this is the *fallback* OTHER; `other` is otherwise a legitimate classic-path kind — §8.2.)

### 7.6 Tool-smith: agent-built tooling lifecycle  `[v2]`

Loop: **detect → scaffold → test → register → reuse**. Test against a held-out eval gate — no tool enters red. Register to a versioned, signed Tool Registry with provenance; reuse via semantic index.

**Promotion gate (the flywheel).** Tools/skills/facts enter shared (TEAM/GLOBAL) memory **only after passing a verdict-graded eval against the held-out corpus (§7.7) WITH a valid `run_receipt`**, demoted on regression. Auto-registration only for read-only/idempotent side-effect classes; destructive tools require a human review verdict.

### 7.7 The gate lives in a separate trust domain — with attestation and rotation  `[v1 — non-negotiable safety]`

- **Eval definitions are signed, human-owned, agent-INACCESSIBLE.** Agents get *verdicts*, never the rubric or held-out cases.
- **Grader-execution attestation (§7.1):** the separate-trust-domain runner produces the signed `run_receipt`; `gate()` verifies it. This makes "the gate is in a separate trust domain" protect *execution integrity*, not just *definitions*.
- **Rotation cadence + leakage canary.** Held-out cases **rotate on a fixed cadence** (default: 20% of the suite retired and freshly minted **every 30 days**, or sooner if a leakage canary trips). **Leakage canary:** continuously compare an agent's pass-rate on the *current* held-out suite vs. a **freshly-minted micro-hold-out** never seen; a widening gap (current ≫ fresh) signals overfitting. **Skills `verified` against a now-retired suite are demoted to `corroborated`** until re-verified. Without this, the held-out corpus degrades into a memorized public test set — the long-horizon version of eval-gaming.
- **This is a v1 requirement, not v2.**

---

## 8. Eyes (AgentVision) — faithful integration as a sense feeding the brain

### 8.1 Ground truth (re-verified against source)  `[v1]`

`Report{verdict, summary, issues[], capabilities[], backend, model, viewport, device_scale, image_path, elapsed_ms, schema_version="1.0"}`. `Issue{kind, severity, message, bbox?, bbox_precise, confidence, source, detail_json}`, **`source ∈ {dom, ocr, cv, vision}`** (a closed 4-value set), `bbox_precise=True` only for dom/ocr/cv. `Report.issue_signature() → frozenset[(kind, message.strip().lower())]` (no fingerprint field). `verdict_from_issues` knows only Severity+Confidence. `LoopSession` (`core/loop.py`) sets `progressed`/`stuck` from signature stability in an in-process `_sessions: dict` (`adapters/mcp_server.py:22`). `analyze()` returns **no cost**. Fallback injects a synthetic `OTHER/WARNING/CV/low` issue and downgrades PASS→WARN (`core/analyze.py:93-99`). **`Report.backend` is an OPEN string** (`'checks'`,`'anthropic'`,`'ollama'`,`'gemini'`,`'openai'`); **`CLASSIC_CAPABILITIES = ['contrast','overflow','broken_image','error_text','typo','blank','other']`** (verified, `core/checks/__init__.py:25`). Verel builds *on* these; it does not reimplement perception.

### 8.2 Eyes as a sense feeding the brain — and the capability table FIXED against `CLASSIC_CAPABILITIES`  `[v1]`

- **Sensory input (retina):** an `analyze`/`analyze_artifact` call is one *saccade*; the `Report` is the raw percept. Event-driven, **not** a sensor feed — the analogy breaks immediately (a retina is always-on; AgentVision fires only on render).
- **"Working memory":** there is none (§5.2). The latest `Report` + signature history is **assembled into context under the budget** (§5.6), not held in a WM buffer.
- **Episodic memory:** each iteration appends an immutable `PerceptEvent{ts, agent_id, repo, artifact_id, viewport, image_path, report_json, signature, ssim, changed_ratio, progressed, stuck, model, backend}`.
- **Semantic memory (v2):** cross-episode induction (§5.5 step 2b) clusters recurring `(kind, message_template, viewport, component)` into `DesignRule`s. `GROUP BY` + threshold + held-out eval, not hippocampus→cortex.

**Issue-kind → memory mapping, SPLIT by what the CLASSIC (no-LLM `local`/`checks`) path can ACTUALLY emit.** Ground truth: **`CLASSIC_CAPABILITIES = {contrast, overflow, broken_image, error_text, typo, blank, other}`.** `clipped`, `overlap`, `layout`, `missing_element` are NOT in it; `other` IS.

**Kinds the CLASSIC path emits (no vision backend needed):**

| IssueKind | typical source | precise? | Memory action |
|---|---|---|---|
| contrast | dom | yes | semantic rule (component+token), high-trust |
| overflow | dom/cv | yes | episodic → DesignRule (viewport-keyed) |
| broken_image | dom | yes | episodic; escalate fast (build/data regression) |
| error_text | dom/ocr | yes | episodic; escalate fast |
| blank | dom/cv | yes | episodic; escalate fast |
| typo | ocr | yes | episodic; low consolidation value |
| other | cv (incl. synthetic fallback) | mixed | **emittable on the no-LLM path** (`analyze.py:93-99` injects OTHER/CV on fallback); consolidate only after N corroborations; the synthetic-fallback OTHER is filtered (§7.5) via `detail.fallback==true` |

**Kinds that REQUIRE a vision backend (NOT in `CLASSIC_CAPABILITIES`):**

| IssueKind | source | precise? | Memory action |
|---|---|---|---|
| layout, clipped, overlap | vision (advisory) or dom-with-vision | advisory unless dom-grounded | working context only until corroborated by a precise source; consolidate after N corroborations |
| missing_element | vision (advisory) | advisory | advisory; never auto-fix on coordinates |

**Why this matters:** a manager reads `capabilities[]` to know what a backend **cannot** see, and per our own rule *absence-of-issue is never mistaken for pass*. If the table told the manager the classic backend covers `clipped`/`overlap`/`layout`/`missing_element` (it does NOT), the manager would treat those kinds as checked when they are **unchecked** — the exact silent-green failure §7.1/§8.2 prevent.

> **Programmatic, drift-proof binding:** the "reachable without vision" set is **imported from `agentvision.core.checks.CLASSIC_CAPABILITIES`**, NOT hand-transcribed. A test asserts `nirvana.capability_map[local_backend] == set(CLASSIC_CAPABILITIES)`. If AgentVision adds a classic check, the table updates from source.

### 8.3 The sight-adapter — field-mapping table; grader-identity keys off `Issue.source`, NOT `Report.backend`  `[v1]`

| AgentVision field | Verel field | PASS-THROUGH or COMPUTED |
|---|---|---|
| `verdict` | `Report.verdict` / `Percept.verdict` | pass-through |
| `summary` | `Report.summary` | pass-through |
| `issues[]` | `issues[]` / `observations[]` | pass-through (per-issue below) |
| `capabilities[]` | `capabilities[]` | pass-through (consumed by Gate §7.1; bound to `CLASSIC_CAPABILITIES` §8.2) |
| **`Issue.source`** (closed: dom/ocr/cv/vision) | **`Report.grader` / per-issue trust** | **computed** — grader identity & precise-vs-advisory key off **`Issue.source`** |
| `Report.backend` (OPEN string) | `Report.model` provenance only | **provenance, NEVER trust** |
| `model` | `Report.model` | pass-through |
| `viewport`/`device_scale`/`image_path` | `PerceptEvent.*` / `Percept.raw_ref` | pass-through |
| `elapsed_ms` | `Report.elapsed_ms` | pass-through |
| `schema_version` "1.0" | `Report.schema_version` "2.0" | computed |
| `Issue.bbox`/`bbox_precise` | `Issue.locator`/`locator_precise` | pass-through (bbox→locator JSON) |
| — | `Issue.fingerprint` | **COMPUTED** (§7.2) |
| — | `Report.cost_usd` | **COMPUTED** (§8.5 — see measurement caveat) |
| — | `Report.errored` | **COMPUTED** |
| — | `Report.run_receipt` | **COMPUTED** (attestation, §7.1) |
| synthetic fallback issue (`detail.fallback`) | filtered before consolidation | adapter-handled (§7.5) |

> **Binding rule:** `Report.backend` is an **open string** (`checks`/`anthropic`/`ollama`/`gemini`/`openai`); `Issue.source` is a **closed 4-value enum** (dom/ocr/cv/vision). **Per-issue grounding (precise vs advisory) MUST key off `Issue.source`/`bbox_precise`. `Report.backend` is provenance only and is NEVER an input to trust.** This means the `ollama`/`gemini`/`openai` backends need no special-casing — a `vision`-source issue is advisory regardless of which backend produced it.

**Percept envelope (the senses/perception bus contract):**
```jsonc
Percept {
  sense: "sight"|"logs"|"tests"|"metrics"|"types",
  verdict, summary,
  observations: [ { kind, severity, message, locator?, locator_precise, confidence, source, fingerprint } ],
  signature, ts, agent_id, artifact_id, raw_ref, trace_ctx,
  viewport?, device_scale?, image_path?      // populated for sense=="sight"
}
```

### 8.4 Wiring surfaces — which surface used where (the FULL real MCP tool set)  `[v1]`

Complete verified set (`adapters/mcp_server.py`): `analyze_artifact`, `check_artifact`, `render_artifact`, `contact_sheet`, `visual_diff`, `ocr_artifact`, `start_loop`, `loop_iterate`, `manage_baseline`, `doctor`. `ocr_artifact` is a **precise-box source the trust model leans on**.

- **MCP server** — default in-fleet perception organ; every coding subagent gets it mounted. `contact_sheet` across `375,768,1280,1920` is the responsive-vision primitive.
- **CLI** (`analyze`/`loop`/`baseline`/`regress`) — CI gates run by agents; deterministic exit codes.
- **Library** (`LoopSession`) — tight in-process inner loops; lowest latency (but see §8.5 crash hazard).
- **`local` backend** (CV/OCR, no key/egress) — emits only `CLASSIC_CAPABILITIES`; `capabilities[]` declares what it cannot see.
- **`anthropic` backend** (default haiku-4-5) — semantic critique; boxes advisory; never fed to an auto-fix tool as coordinates.

### 8.5 Closed loop + manager escalation + the in-process-session crash hazard  `[v1]`

Per artifact: **write → render → `loop_iterate` → Report → fix → re-render.** Manager state machine:
- `progressed && !pass` → keep model, continue (cheap path).
- `stuck` (over the *residual non-flaky* gating set, §7.3) → **model-upgrade ladder** haiku → sonnet → opus.
- `stuck` after opus, or oscillating between two signatures → **human handoff** with the episodic trail. SSIM/`changed_ratio` is *explanatory*, never the decision channel.

**Crash-continuity (binding, reconciled with §7.2).** AgentVision's `LoopSession` lives in an **in-process `_sessions: dict`**; a Verel worker crash LOSES it. **Resolution: Verel persists `PerceptEvent`s itself and recomputes its scrubbed-fingerprint progressed/stuck from that log — both on resume AND every iteration.** Verel never relies on AgentVision's in-process session surviving, and never relies on `LoopSession`'s message-based progressed/stuck as the termination authority. This is the single, consistent stuck-timing source.

**Cost-measurement caveat.** `analyze()` returns **no per-call cost**, and the vision-LLM call is made **inside AgentVision** (`vision.analyze(req)`), not by Verel — so Verel cannot directly attribute the ~$0.01. **Resolution: AgentVision must expose token usage on the `Report` (a small upstream PR, since Amit owns it), OR Verel wraps the Anthropic client AgentVision uses and meters it.** Until one of those ships, `cost_usd` for the sight sense is **estimated, not measured** — stated honestly.

### 8.6 Beyond UI, and honest limits  `[v1 limits stated; broader artifacts v2]`

Helps wherever a fleet emits rendered artifacts. **Honest limits:** rasterized non-HTML WCAG is heuristic (`confidence: low`); vision-LLM bboxes are advisory; vision varies run-to-run — consolidation requires **N corroborations** before a vision-only observation becomes a `DesignRule`; CI prefers dom/cv/ocr for hard fails. **Grounding (dom/ocr/cv) is what keeps the metaphor from being marketing** — anywhere we can't point to it, the percept is advisory and the state machine discounts it.

---

## 9. What we can improvise — our claimable inventions  `[mix of phases]`

Each tagged `novel | table-stakes | wedge` + effort (S/M/L) + phase. (Defensibility rated in §2.3.)

1. **Verdict Bus** — one schema, all senses, typed reducer with ceiling-clamp + attestation. `table-stakes-but-strongest-unifying-idea · M` · **v1**
2. **Promotion-on-eval procedural memory** (held-out, attested corpus gate) — `wedge · L` · **v1 gate, v2 registry**
3. **Corroborated entailment gate** (NLI + precise same-episode corroborator; never LLM-alone) — `novel · M` · **v2**
4. **Cross-episode consolidation + interference model** (schema induction + pattern-separation + retrieval-induced inhibition) — `wedge · M` · **v2**
5. **Fleet-wide issue-set stuck-detection** (scrubbed fingerprint, strict-subset shrink) — `novel-as-generalization · S` · **v1**
6. **Bounded-context firewall + `subj_pred_key` interference rule** — `table-stakes · S` · **v1**
7. **Cost-as-a-sense** (budget grader on the verdict bus) — `novel-framing · S` · **v1**
8. **Manager eval-contracts** ("done" = verdict, enforced at the `Stop` hook) — `wedge · M` · **v1**
9. **The verified eval+skill corpus + public registry + public held-out benchmark** — `DURABLE iff §8.7 H2 holds · L` · **v2 accrual, v3 registry**

---

## 10. Honest risks & non-goals — why "not everyone succeeds," and the answers

### 10.1 Biggest failure risks and the design's answer
- **Context rot** → bounded context assembly + interference rule (§5.6); never dump full memory in.
- **Memory swamp** → trust scoring + corroborated entailment gate + per-item-type retrieval decay + two-stage surprise salience (§5.5).
- **Memory interference** → pattern-separation at write + retrieval-induced inhibition at read + `subj_pred_key` uniqueness (§5.5 steps 4–5, §5.6).
- **Eval gaming (deepest risk)** → precise gates / advisory ceiling-clamped at merge (§7.1); **gate in a separate trust domain with held-out, agent-inaccessible evals AND grader-execution attestation (§7.1, §7.7)**; progress = strict-subset shrink (§7.2); rotation + leakage canary (§7.7); *an LLM never solely gates a destructive or memory-compounding action — including the entailment gate, which now requires a precise corroborator (§5.5)*.
- **False memories / gist-distortion** → corroborated entailment gate + verbatim episode in cold storage (§5.5f).
- **Flaky-vs-stuck budget burn** → FLAKY probe runs BEFORE stuck-escalation; flaky fingerprints removed from `gating_failures()` (§7.3).
- **Runaway cost / non-termination** → budget LEASE ledger with per-call output reservation (§6.5) + failing-set stop (§7.3) + spawn/spend circuit breaker (§6.6) + bounded patch→quarantine loop (§6.6).
- **Split-brain / dual-execution** → v1: single-writer scheduler with its own run-fencing lease (§6.10); v3: worker fencing sink at the durable ref (§6.1).
- **Lost side-effects on crash** → side-effect WAL + `pre_intent_sha` MUTATE-ABORT recovery + ref-confirmation before verdict-log (§6.2); cross-store memory writes via transactional outbox (§5.9).
- **Non-determinism** → advisory verdicts as **distributions: N-of-M majority before an advisory grader may even WARN-gate**; pin model/seed where possible; log verdict provenance.
- **Over-engineering (the #1 project killer)** → ship the thin vertical (§11); kill-list (§11.2); v1 control plane cut to single-process single-writer with NO worker fencing.
- **No demand (H1) / no corpus fungibility (H2)** → both measured before scaled (§8.7); registry investment gated on the H2 experiment.

### 10.2 Non-goals
- **Not** neurons, not continuous learning, not "the agent dreams," **not "working memory," not "prospective memory"** (both cut as brain labels — §5.2). "Brain" is internal vocabulary only, cut from external positioning.
- **Not** true cross-repo atomic commits — v3 saga, bounded (≤90s) window; v1 manual coordination (§6.3).
- **Not** human visual regression (Percy/Applitools) or browser automation.
- **Not** a memory-storage product — we rent that (mem0) and compete on what gates/consolidates it.
- Advisory LLM/vision verdicts are **never** sole gates for destructive actions, merges, or memory promotion.
- We **won't** reinvent SDK primitives (subagents, hooks, MCP, skills, background tasks, structured output).

### 10.3 Naming
"Verel" oversells "enlightenment"; the honest pitch is "verified, perceiving agents." Keep "Verel" as the internal working name; before launch pick a name signaling **verification + perception**. Anchor: *the agent framework where nothing ships until it's verified by real senses — including eyes — and only verified work compounds.*

---

## 11. Phased build roadmap

### 11.0 Cost/latency feasibility — the gating economic check  `[v1]`

Representative "fix a UI overflow" ultracode iteration (order-of-magnitude; a **hypothesis**, not a result):

| Step | Model | ~Tokens (in/out) | ~Cost/iter |
|---|---|---|---|
| render + `analyze` (sight) | Haiku 4.5 (vision) | 3k / 0.5k | ~$0.01 *(see measurement caveat §8.5)* |
| **affected precise graders (tests/dom/lint/type)** | none (deterministic) BUT **real CI-runner cost** | — | **~$0.005–0.04 CI minutes** (NOT $0.00) |
| adversarial verify (only if advisory sole-signal) | Haiku 2nd judge | 2k / 0.3k | ~$0.005 (often skipped, §7.3) |
| fix | Sonnet 4.6 | 8k / 1k | ~$0.05 |
| re-render + re-analyze | Haiku 4.5 (vision) | 3k / 0.5k | ~$0.01 |
| **per-iteration total** | | | **~$0.08–0.12** |

- **The grader-runtime line.** Precise graders are not "$0.00 deterministic" — full test/integration/security suites have real **CI-runner wall-clock $ per pre-merge iteration**. To keep the loop affordable, step 6 of §7.3 re-runs **AFFECTED graders only** (incremental: unit/type/lint/dom), not the full suite, every iteration; the **full suite + security runs ONCE at the pre-merge gate**, not per inner-loop iteration. Without this split, loop cost is dominated by CI on a large repo and the per-ticket estimate is not credible.
- Expected iterations to converge: **3–6** ⇒ **~$0.30–0.70/ticket** (includes CI cost). Hard per-task ceiling enforced by the budget lease (§6.5); the budget grader kills the loop so worst case is bounded.

### 11.1 v1 build order — the thin vertical & "smallest first useful thing"  `[v1; ships ~2–4 weeks for the walking skeleton, full v1 ~1 quarter]`

> **Phase 0 — the walking skeleton / smallest-first-useful-thing (~2–4 weeks).** Build *only* items 1+2 below: the unified `Report`/`Percept` schema + `gate()` + scrubbed-fingerprint `progressed()`/`issue_signature()`, wired to the AgentVision `sight` adapter over MCP, driving a single-worker ultracode loop on one real repo's UI. **Definition-of-done (dogfooded through Verel's own verdict bus): Verel fixes a real UI overflow on a real page, and the loop terminates on a `pass` verdict it computed itself — not a self-asserted "done."** No memory, no fleet, no consolidation. This is the smallest thing that demonstrates the banner promise end to end and is shippable in ~2–4 weeks. Everything after is additive.

> **Scope honesty.** Even after cuts, full v1 is **five non-trivial subsystems**. We mitigate by (a) cutting worker fencing + the side-effect-WAL git-fencing-sink to v3, leaving v1's control plane at *single-process, single-writer, file-based WAL/outbox + scheduler-run fencing lease only*, and (b) putting the corpus-fungibility experiment (H2) BEFORE any registry work, so we don't build the flywheel until we know the asset transfers.

| # | Deliverable | Build on SDK vs net-new | DoD (gated by Verel's own verdict bus) |
|---|---|---|---|
| 1 | **Verdict bus core** — unified `Report`/`Percept`, typed `gate()` with `clamp_ceiling` + grader `run_receipt` attestation, scrubbed-`fingerprint` `issue_signature()`, strict-subset `progressed()`, named constants (`SEV_ORDER/GATING_SEVERITY/ADVISORY_CEIL/W/ε/M`). | **Net-new** (the unifying schema is ours). | `clamp_ceiling` unit-test table + fingerprint-stability invariant test both green *in CI run by the bus itself*. |
| 2 | **AgentVision `sight` adapter** on the bus via MCP, literal §8.3 field mapping; grader-identity keys off `Issue.source` not `Report.backend`; capability map imported from `CLASSIC_CAPABILITIES` with a drift test; persists `PerceptEvent`s and recomputes scrubbed progressed/stuck itself. | **Build on** the SDK's MCP mount + AgentVision's MCP server; adapter is net-new. | Drift test green; a real overflow fixed and loop terminates on a self-computed `pass`. |
| 3 | **One rented memory store (mem0) behind `MemoryView`** with trust/provenance/**split epistemic-confidence-vs-retrieval-strength**/entailment fields, the `subj_pred_key` interference rule, and the **transactional-outbox cross-store consistency contract (§5.9)**. | **Build on** mem0; the trust/consistency layer is net-new. No self-hosted KG, no CRDT. | Crash-injection test: outbox replay yields no dup/orphan facts, verified by the bus. |
| 4 | **Promotion-on-eval gate** against a held-out, agent-inaccessible, ATTESTED corpus with rotation cadence + leakage canary; the **corroborated entailment gate** (NLI + precise same-episode corroborator) ships here. | **Net-new** (the trust-domain separation + attestation is the core IP). | A planted leakage attempt is caught by the canary; a hollow grader FAILs the gate. |
| 5 | **Control plane (v1-cut):** single-writer scheduler with its own run-fencing lease (§6.10), retry+heartbeat supervision, budget LEASE ledger with per-call output reservation, side-effect-WAL with `pre_intent_sha` MUTATE-ABORT recovery, transactional intention dedup, trace-context propagation. **NO worker fencing tokens (v3).** | **Build on** SDK subagents/hooks/background tasks; scheduler/ledger/WAL are net-new. | Kill-and-resume test: an interrupted-rebase task recovers via Case C and re-runs idempotently; budget invariant holds on the last call. |
| 6 | **H2 corpus-fungibility experiment (§8.7) — a GATING milestone.** 3 repos; measure cross-repo verified-skill transfer through the gate. | Net-new measurement harness. | A number is produced. **If <20%: do NOT build the public registry; pivot the moat story to per-tenant lock-in.** |

### 11.2 The KILL-LIST — what we will explicitly NOT build  `[binding]`

1. **Multi-repo atomic-ish saga with compensating reverts** → **CUT from v1/v2.** Manual coordination; v3+ behind §6.3 isolation.
2. **CRDT support-counters** → **CUT entirely.** Single-writer consolidation removes the contention they solve.
3. **Self-built Neo4j KG + pgvector/LanceDB/SQLite triple-stack** → **CUT.** One rented backend (mem0) in v1.
4. **OTP supervision runtime semantics** → **CUT to retry-policy + heartbeat.** No live process to link to.
5. **Worker FENCING TOKENS + the server-side fencing sink** → **DEFERRED to v3** (with vector clocks). Fencing only matters under concurrent managers; v1 is single-writer-per-run. The ONE fencing lease v1 keeps is on the **scheduler-per-run** (§6.10), the real SPOF.
6. **The 5-weight (α/β/γ/δ/λ) MMR context assembler** → **DEFERRED to v2.** v1 ships fixed `recency + scope + confidence-gate + budget + interference rule + MMR-dedup`.
7. **"Working memory" and "prospective memory" as brain analogues** → **CUT as labels** (§5.2, §5.8); the underlying artifacts (bounded context assembly; durable cue-bound queue) remain, honestly named.
8. **Tool-smith, failure-ledger nightly clustering, cross-episode induction as a product** → v2, not v1.

### 11.3 Phases v2 → GA

- **v2 (consolidation + fleet + CI/CD; ~2 quarters).** Cross-episode consolidation pipeline (§5.5) incl. schema induction; fleet TEAM/GLOBAL tiers + trust promotion (§5.7); intention queue with transactional dedup (§6.8); tool-smith (§7.6); pre-merge/post-merge agent-run CI/CD with safety gates (§7.4); failure-ledger + regression-guard grader (§7.5); the v2 weighted MMR assembler (§5.6). **DoD:** a multi-agent fleet ships a verified change across two services with consolidation producing at least one `verified` cross-episode `DesignRule`, all gated by the bus.
- **v3 (distributed hardening + registry; gated on H1/H2).** Worker fencing tokens + server-side fencing sink (§6.1); multi-repo saga with bounded inconsistency window (§6.3); vector clocks (§6.7); intention-deactivation failure modeling (§5.8). **Public Skill Registry + public held-out benchmark only if §8.7 H2 ≥ threshold.** **DoD:** concurrent managers safely fence against a stale worker at the durable ref; if H2 holds, an external tenant consumes a `verified` skill from the registry and it passes their held-out gate.
- **GA.** Stable schemas (`schema_version` frozen), documented integration recipes (Cursor/Aider/generic agent-contract mirroring AgentVision's surfaces), SLOs on the verdict bus, and the moat story finalized per the measured H1/H2 outcomes.

**Dogfooding invariant across all phases:** Verel's own development is gated by Verel's own verdict bus. No Verel change merges on a self-asserted "done"; each must pass the bus, which is the strongest possible demonstration of the product.

---

## 12. Open questions / decisions for the owner

1. **Memory backend choice (blocks v1 item 3):** `mem0` vs `Letta`? Recommendation: `mem0` (lighter, vector+graph+KV, large adoption); Letta if its sleep-time-compute consolidation is worth coupling to. **Decision needed before Phase 0 ends.**
2. **AgentVision cost-exposure PR (blocks honest §11.0 economics):** are you OK landing a small upstream PR to expose token usage on `Report`, or should Verel meter by wrapping the Anthropic client? (§8.5.)
3. **H1 demand probe:** do we have 2–3 design partners willing to sign LOIs around "agents that don't ship broken UIs" *before* heavy build? The flywheel never starts without demand. (§8.7.)
4. **H2 transfer threshold:** is 20% cross-repo verified-skill transfer the right kill-line for the public registry, or do you want a different bar? (§8.7.)
5. **External name:** keep "Verel" or pick a verification+perception name before launch? (§10.3.)
6. **GLOBAL/public-registry openness:** if H2 holds, is the registry public (network effect, but gives competitors our corpus shape) or org-private (weaker flywheel, stronger lock-in)? (§5.7, §2.2.)
7. **Default model routing budget:** confirm Opus 4.8 orchestrator / Sonnet 4.6 manager+worker / Haiku 4.5 critic+consolidation, with the haiku→sonnet→opus stuck-ladder. Any cost ceilings that should change these defaults?
8. **Human-in-the-loop boundary:** which destructive actions (merges to default branch, repo reverts, GLOBAL promotion) require a human verdict vs. a policy-engine verdict at v1? (§7.4, §7.6.)

---

## 13. Appendix — critic-loop convergence record  `[verbatim]`

```
Round 1: mean critic score 68.2/100 (delta n/a)
  neuro-memory:72(warn), distsys:58(warn), eval-rigor:61(warn), vision-fidelity:78(warn), moat-feasibility:72(warn)
Round 2: mean critic score 76.2/100 (delta 8)
  neuro-memory:74(warn), distsys:71(warn), eval-rigor:82(pass), vision-fidelity:86(pass), moat-feasibility:68(warn)
Round 3: mean critic score 75.4/100 (delta -0.8)
  neuro-memory:82(pass), distsys:72(warn), eval-rigor:74(warn), vision-fidelity:88(pass), moat-feasibility:61(warn)
```

**One-line interpretation of why we stopped.** We stopped after Round 3 because the mean score *regressed* (−0.8) while the two highest-value axes converged to `pass` (neuro-memory 72→82, vision-fidelity 78→88): the remaining open warns (distsys, eval-rigor, moat-feasibility) are not unresolved *design* defects but honestly-unresolvable *strategic bets* (H1 demand, H2 corpus fungibility) and *deliberately deferred scope* (v3 distributed hardening) — further rounds were trading real-correctness fixes for adversarial point-scoring, so the design is converged and the residual risk is now empirical, not architectural.

---

*Source-of-truth note:* `CLASSIC_CAPABILITIES = ["contrast","overflow","broken_image","error_text","typo","blank","other"]` is verified at `/home/amitpatole/Eyes_For_AI_Agents/src/agentvision/core/checks/__init__.py:25`; `clipped`, `overlap`, `layout`, `missing_element` are NOT in it and `other` IS — the §8.2 capability tables and the §8.2 drift test are bound to this list programmatically so they cannot silently diverge from AgentVision source.