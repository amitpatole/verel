# Changelog

## 0.8.0 — broadened senses: Python · JS/TS · Go · perf · security on one bus

The verdict bus stops being Python-only. A `GraderSpec` now carries its own parser, so graders
that share a `GraderKind` but not an output format coexist:
- **JS/TS**: `jstest_spec` (TAP — node:test/tape/vitest), `eslint_spec` (JSON), `tsc_spec`.
- **Go**: `gotest_spec` (`go test -json`), `govet_spec`.
- **Perf** (`perf_spec`): a PRECISE grader — a benchmark metric past an **explicit budget** is a
  gating ERROR (so a perf regression can drive rollback); within budget is clean. Never inferred.
- **Security** (`bandit_spec`, `npm_audit_spec`): SAST/dependency audit — HIGH/CRITICAL map to
  gating ERROR, MEDIUM→WARNING, LOW→INFO, so a low finding advises without blocking.
- **Language toolchains** (`verel.ci.LANGS`): every stage takes `language="python"|"js"|"go"`;
  `premerge_stage(..., security=True, perf=spec)` adds the precise senses. Adding a runtime is one
  `LangToolchain` entry.
- All ride the existing contract: attested `RunReceipt`, stable fingerprints, one gate, one
  stuck/progress signal. Parsers are pure, so the matrix is tested offline (no node/go/bandit).
- `examples/demo_polyglot_ci.py`; 171 offline-CI tests.

## 0.7.0 — per-capability seccomp jail (a tool earns each syscall by verifying)

The tightest isolation tier, and the one that ties containment to Verel's verification discipline:
a tool may use only the syscalls it **exercised while passing its held-out eval**.
- **Policy learning** (`toolsmith/seccomp_learn.py`): `learn_syscall_profile()` runs the tool over
  its eval cases under `strace` and unions the syscalls observed — the tool's footprint. Needs
  strace at build time only; enforcement needs just libseccomp.
- **Capability profile** (`seccomp_profile="capability"`): default-deny, allowing the learned
  policy unioned with a `RUNTIME_FLOOR` (interpreter+libc essentials, so a thin trace can never
  crash CPython) and the bwrap supervisor syscalls. Strictly ⊆ the allow-list jail — a syscall the
  tool never earned is refused even if the allow-list would permit it.
- **Frozen onto the tool**: `ToolRecord.syscall_policy` (operator metadata, not in the code
  signature); `ToolSmith(learn_syscalls=True)` learns + stores it on a verified build.
- Verified live under bwrap: the verified math tool runs 10/10; `socket()`, `subprocess`,
  `os.fork()` are refused; and a benign `os.pipe()` that the allow-list jail permits (returns 5)
  is **refused** under the tool's math policy — per-tool tightening, proven, not asserted.
- New exports: `PROFILE_CAPABILITY`, `capability_allow`, `learn_syscall_profile`,
  `strace_available`; `build_bpf(profile=, allow=)`, `run_container(seccomp_profile=, seccomp_allow=)`.
- `examples/demo_capability_jail.py`; 156 offline-CI tests.

## 0.6.0 — the strict allow-list seccomp jail (default-deny for untrusted tool code)

The 0.5.0 denylist was defense-in-depth; this is the real minimal jail, the last roadmap item
on tool isolation.
- **Allow-list profile** (`seccomp_profile="allowlist"`): a default-**deny** filter (EPERM on
  anything not listed) that allows only the syscalls a single-threaded, pure-compute CPython
  payload needs — derived by tracing `python3 -I -S` over representative pure tools, plus a margin
  for libc/stdlib variation, and the handful bwrap's own pid-namespace init needs to reap the
  child. By omission it withholds **all** network syscalls, **all** process-spawn syscalls
  (`clone`/`fork`/`vfork` — so no subprocess and no threads), and every privileged family.
- Verified live under bwrap: pure tools (math/json/re/hashlib/decimal/datetime) run; a tool that
  opens a `socket()`, runs a `subprocess`, or calls `os.fork()` is refused with EPERM.
- EPERM (not SIGSYS-KILL) is the default action, matching the Docker/podman convention — a
  refusal surfaces as a Python `PermissionError` instead of crashing the interpreter.
- `run_container(..., seccomp_profile=...)`; `build_bpf(..., profile=...)`; new `ALLOWED_SYSCALLS`,
  `PROFILE_DENYLIST`, `PROFILE_ALLOWLIST` exports. Default stays `denylist` (safe for arbitrary
  tools); the allow-list jail is opt-in for untrusted code.

## 0.5.0 — seccomp on the §7.7 container runner (closing the last sandbox overclaim)

The container tool runner promised "seccomp containment" in its docstring but only did namespace
isolation. Now it's real:
- **seccomp-bpf syscall filter** (`toolsmith/seccomp.py`): a deny-list filter (default ALLOW,
  EPERM on a curated set — ptrace, mount, raw `socket`, unshare/setns/clone3, bpf, kexec, module
  loading, keyring, chroot/pivot_root, device-node creation, cross-process memory peek) compiled
  via libseccomp and handed to `bwrap --seccomp`. Optional defense-in-depth: needs the `seccomp`
  or `pyseccomp` binding (new `verel[container]` extra); without it the namespace sandbox still
  applies and `seccomp_available()` reports False.
- `run_container(..., seccomp=True)` is the default; `exec_child` gained `pass_fds` to hand the
  compiled BPF program to the sandboxed child.
- Verified live: under seccomp a tool calling `socket()` is denied with EPERM, while the SAME
  tool succeeds with `seccomp=False` — proving the network namespace blocks `connect()`, not
  `socket()`, and seccomp is the layer that does. Normal pure tools run unaffected.
- Fixed a committed version drift: `verel.__version__` was stuck at 0.4.2 while the package was
  0.4.5; both now track the real version.
- 153 offline-CI tests (+1 always-on; the live containment checks skip where bwrap/libseccomp
  are absent).

## 0.4.5 — developer adoption (CI gate Action + pre-commit), in sync with the eyes

Symmetric adoption polish so the brain drops into a workflow as easily as the eyes:
- **Reusable GitHub Action** (`action.yml`): installs Verel (+ your deps) and runs the verdict
  bus gate (`verel-ci check`) — tests + lint + types in one verdict; fails the build on FAIL.
- **pre-commit hook** (`.pre-commit-hooks.yaml`): `verel-precommit` gates commits on the bus.
- README "Drop it into your workflow & your agents" section (Action, pre-commit, native hook,
  `verel-mcp`, `verel[sight]` for visual gating + `watch`).
No library code change; cut so a pinned `@v0.4.5` action ref and `pip install` align.

## 0.4.4 — temporal perception: the eyes can now *watch* (AgentVision 0.6.0)

AgentVision 0.6.0 added temporal verification (`watch` — playback/loading/liveness over a
frame sequence). The brain now drives and records it:

- **`verel.senses.watch(source, …)`** — a temporal sense mirroring `perceive()`. Returns the
  same `SightResult`, so the verdict bus consumes it like any sense. A deterministic video
  **stall** (currentTime not advancing) is DOM-sourced → precise → **gates to FAIL**; the
  temporal *vision* findings are advisory/clamped — exactly the right trust split.
- **`Percept` gains `playing` / `live` / `stabilized`**, extracted from the watch signal and
  recorded by `PerceptLog`, so the brain can gate releases on *verified playback* and
  **compound** "the player plays (with captions)" across builds instead of re-checking it.
- +2 sight-adapter tests (152 passing). Keeps eyes and brain in sync.

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
