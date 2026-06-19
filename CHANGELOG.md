# Changelog

## 0.4.3 — eyes intent conformance (AgentVision 0.3.0 compatibility)

- **Forward-compat with AgentVision 0.3.0**: `verdict.models.IssueKind` gains
  `intent_mismatch`. AgentVision 0.3.0 added intent-conformance grading, which emits
  `intent_mismatch` issues; without this the sight adapter raised
  `ValueError: 'intent_mismatch' is not a valid IssueKind` on any conformance run.
- **Intent conformance reaches the brain**: `Percept` gains `matches_intent`,
  `intent_satisfied`, `intent_total`, populated by `senses.sight.from_agentvision` from the
  AgentVision Report's `conformance`, and recorded by `PerceptLog` — so the brain can compound
  *"did the artifact match what we set out to build"* across iterations. A full brain still
  ingests the rich Report and runs its own gate/stuck detection; it does not consume
  AgentVision's distilled `next_action`. +3 sight-adapter tests.

## 0.4.2 — docs sync

- README, Hugging Face landing, and module guide updated for the 0.4.x memory lifecycle
  (pin / volatile / TTL / staleness / correction chains); test count refreshed (148);
  the HF "Design & plan" link now points to the public ARCHITECTURE.md (not the internal
  strategy doc).

## 0.4.1 — failure-ledger × lifecycle (self-cleaning, permanent-where-it-matters)

- The ci-medic's **transient (retry) and flaky** failures are now written `volatile` to
  failure-memory, so they self-clean unless they RECUR (a recurrence re-asserts and confirms
  them). Genuine regressions are never volatile. Wired through `run_stage`.
- A failure marked **fixed** is now `promote`d AND **pinned** — confirmed regression knowledge
  never decays or prunes, so the regression guard catches a reintroduction however long later.
- `MemoryView` protocol gains `set_flags`/`pin`/`unpin`. +5 tests.

## 0.4.0 — memory lifecycle (pin / volatile / TTL / staleness / correction chains)

Ideas validated by the r/aiagents memory thread, added to `verel.memory` (both LocalMemory
and the mem0 adapter, identical behaviour via a shared `apply_decay`):
- **Pinned** memories ignore decay entirely and are never pruned (`mem.pin(id)`).
- **Volatile-until-confirmed**: a `volatile` memory is dropped unless corroborated/verified
  within its window (`VOLATILE_TTL_S`); corroboration/promotion clears the flag.
- **Hard TTL** (`ttl_s`) for ephemeral environment facts (e.g. "current branch is X").
- **Context-triggered staleness**: records idle past `STALE_AFTER_S` are flagged `stale`.
- **Correction chains**: superseding a value keeps the full prior history (`correction_chain(r)`)
  instead of overwriting it.
New helpers: `is_pinned/is_volatile/is_expired/correction_chain`, `set_flags/pin/unpin`.

## 0.3.2 — brand & docs polish

- New README with a hero banner + architecture infographic (matches AgentVision's polish).
- Brand graphics generated with OpenAI **gpt-image-2** (hero, key-visual, eval-loop); the
  architecture **infographic is rendered & verified by AgentVision** (the eyes Verel ships).
- Hugging Face Space landing redesigned (`media/space_index.html`). Image URLs are absolute
  so the banner renders on GitHub and PyPI alike. Heavy media excluded from the sdist.

## 0.3.1 — polish pass (lint/types clean, typed, dogfooded)

- **ruff + mypy clean** across `src/` (config in pyproject); ruff passes on tests/examples too.
- **Ships type information** (`py.typed`, PEP 561) — downstream users get Verel's types.
- **Dogfooding invariant enforced in CI**: a step runs Verel's own pre-merge verdict bus
  (pytest + ruff + mypy graders, attested) over Verel and asserts `pass` — Verel gates Verel.
- Tests modernized (`pytest.raises` over `assert False`); `PublicRegistry.list()` → `all()`
  (consistency with `MemoryView.all()`, removes builtin shadowing). Dev status → Alpha.

## 0.3.0 — refinements: real mem0, container sandbox, semantic reuse, enriched medic

- **Real mem0 backend** (`memory/mem0_backend.py`): updated to the mem0 **2.x** API
  (`filters=` on get_all/search, `update(id, data, metadata=)`); `make_ollama_mem0()` now
  configures a local Chroma store; recall uses mem0's **semantic** ordering (no longer
  discarded by a lexical re-rank). Live smoke verified (write → promote → semantic recall)
  against real mem0 + OpenAI vectors. `mem0` extra → `mem0ai>=2.0, chromadb`.
- **Container tool runner** (`toolsmith/container.py`): `bwrap` namespace sandbox — no
  network, read-only system-only fs, ephemeral tmp, cleared env, + rlimits. `ToolSmith(
  isolation="container"|"best")`. Verified live: network blocked, /home unreadable.
- **Embeddings-backed tool reuse**: `ToolRegistry.find` ranks by cosine when the memory has
  an embedder, so a tool is reused by MEANING ("make a web-friendly identifier" → slugify).
- **LLM-enriched ci-medic**: `enrich_diagnoses()` adds a root-cause hint to FIX_BRANCH
  diagnoses only; the deterministic classification (retry-vs-fix) is never changed by the LLM.
  Wired into `self_heal(enrich_chat=...)` → hints flow to the code-fixer.
- 135 tests (+1 gated live mem0 smoke).

## 0.2.1 — post-merge canary + verdict-driven rollback (CI/CD table complete)

- **Post-merge canary stage** (`ci/postmerge_stage`) and **`canary_rollback()`**: run the
  smoke/E2E canary on merged code; on a PRECISE-evidence failure, auto-revert.
- **`RollbackExecutor`**: agent proposes → `RollbackPolicy` authorizes (precise gating
  evidence only) → a safe, non-destructive `git revert` (never a history rewrite). An
  advisory-only (vision/LLM) failure can never trigger a destructive revert.
- Completes §7.4's stage table: inner-loop → pre-commit → pre-merge → post-merge/canary.
- 130 tests; demo_canary_rollback.py (live, real git, no key): bad merge auto-reverted,
  advisory-only refused.

## 0.2.0 — public Skill Registry + the H2 corpus-transfer experiment (the moat gate)

- **Public Skill Registry** (`verel.registry`): content-addressed, signed, provenance-tagged
  `SkillArtifact`s in a `PublicRegistry`. Export a verified tool, publish it, search/fetch it.
- **Cross-tenant transfer with re-verification** (`registry/transfer.py`): trust does NOT
  travel — an imported skill enters as `candidate` and only becomes `verified` if it passes
  the importing tenant's OWN held-out eval.
- **H2 experiment** (`registry/h2.py`): `measure_transfer()` measures the cross-tenant
  re-verification rate and returns the design's gating decision (≥20% → build the registry;
  <20% → pivot to per-tenant lock-in). Honest: skills a target can't evaluate aren't counted.
- Fixed a tool-smith `detect()` bug: weak lexical capability overlap could reuse the wrong
  tool; reuse now requires a strong match (`min_relevance`).
- 125 tests; demo_h2_moat.py (live): builds skills on Ollama, measures real fungibility.

## 0.1.1 — semantic recall + real tool sandbox

- **Semantic memory recall** (`memory/embed.py`): pluggable `Embedder` (`HashEmbedder` offline,
  `OpenAIEmbedder` semantic); `LocalMemory(embedder=...)` ranks recall by cosine similarity, so
  a query with no shared words still finds the right memory. Vectors persist across reinforcement.
- **Subprocess sandbox for tools** (`toolsmith/sandbox.py`): runs agent-built tool code in an
  isolated interpreter (`python -I -S`) with CPU/memory/file-size rlimits and a wall-clock
  timeout — a genuine process boundary, not just a restricted namespace. `ToolSmith(sandbox=True)`
  evaluates candidates there. Honest about limits (no network/read isolation; that's the §7.7 runner).
- 116 tests; demo_semantic_recall.py.

## 0.1.0 — first end-to-end release

The five design organs all have working, tested slices, gated by Verel's own verdict bus.

### Verdict bus (`verel.verdict`)
- Unified `Report`/`Issue`/`Percept` contract across senses; `gate()` with an explicit
  advisory **ceiling clamp**, **grader-execution attestation** (signed `run_receipt`,
  dead/hollow-gate guards), scrubbed per-grader **fingerprints**, and strict-subset
  **stuck/progress** detection.

### Eyes (`verel.senses`)
- AgentVision **sight adapter** — grader identity keys off `Issue.source`; `CLASSIC_CAPABILITIES`
  imported from source (drift-proof); crash-safe percept log with Verel-owned progressed/stuck.

### Agents (`verel.agents`)
- Provider-agnostic LLM client (**Ollama Cloud** default, `qwen3-coder:480b`; OpenAI fallback).
- Coding agent `FixHook` (fixes UIs) and `fix_code` (patches source for failing graders).

### Brain (`verel.memory`)
- `MemoryView` trust layer with the two orthogonal quantities (epistemic confidence vs
  retrieval strength), interference rule, documented ranking, exact prune rule.
- Zero-dep `LocalMemory` (sqlite) and `Mem0Memory` (rented mem0) behind the same Protocol.
- Failure ledger + **regression guard**, cross-episode consolidation, and the **held-out,
  attested, agent-inaccessible promotion gate** (inferred → verified; leakage canary).

### Fleet (`verel.fleet`)
- Single-writer scheduler over a Task DAG: barriers (all/k_of_n/optional), concurrency,
  retry→quarantine, hard budget lease, WAL resume; every node gated by the bus.
- **LLM-driven manager** (plane validates/clamps/falls back) and **isolated git worktrees**.

### Tool-smith (`verel.toolsmith`)
- detect → scaffold → test → register → reuse; signed, versioned registry as SKILL records;
  sandboxed `load_callable`; read-only/idempotent auto-verified, destructive human-gated.

### Agent-run CI/CD (`verel.ci`)
- Tests/lint/type **graders** on the bus (attested); inner-loop / pre-commit / pre-merge
  stages with failure-memory; **self-healing** loop; deterministic **ci-medic** and
  **rollback policy engine** (destructive never depends on advisory evidence); git pre-commit
  hook + `verel-ci` CLI. Hardened pytest with `-B` (no stale-`.pyc` false verdicts).

### Surfaces
- `verel` CLI (`doctor`/`loop`/`fleet`/`heal`/`ci`), MCP server (`verel-mcp`), `verel-ci`.

### Meta
- 106 tests (offline/CI-safe), 9 runnable demos, dogfooded through Verel's own verdict bus.

## 0.0.1 — name reservation placeholder
