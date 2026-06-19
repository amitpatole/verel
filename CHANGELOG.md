# Changelog

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
