# Changelog

## 0.20.0 — hosted shared memory: a fleet shares one brain over HTTP

The second shared-brain slice — agents on **different machines** read and write one store.
- **`MemoryServer`**: wraps a durable `MemoryView` (a `LocalMemory` from a `db_path`, opened
  cross-thread, or your own store) in a tiny stdlib HTTP service exposing the full Protocol —
  write / get / recall / all / corroborate / contradict / promote / demote / annotate / set_flags /
  pin / unpin / decay. Optional bearer token. The server is the **single writer**: every access is
  lock-serialized, so the interference rule (same `(subject,predicate,scope)` supersedes) stays
  correct under concurrent agents.
- **`RemoteMemory`**: a `MemoryView` over HTTP — a drop-in for `LocalMemory`/`mem0`, so
  `lattice_recall`, `graduate`, consolidation, and the promotion gate all work against the shared
  brain unchanged. Verified live: Alice writes, Bob recalls; corroboration is shared; 40 concurrent
  writes serialize cleanly; the interference rule holds over the wire; bad auth is rejected.
- `LocalMemory(check_same_thread=False)` so a server can serve it from its HTTP thread.
- `examples/demo_shared_brain.py` now ends with the hosted flow; 237 offline-CI tests.

Next slice: per-author trust + `import_belief` (re-verify on cross-agent import), then the
"librarian" curation pass.

## 0.19.0 — scope lattice: the foundation of a shared team brain

The first slice of the shared-brain work — the mechanic that turns individual memory into
collective memory, built on the existing trust layer (pure logic, no infra, any `MemoryView`).
- **`ScopeLattice`**: a child→parent map over scopes (`repo → team → org → global`); a scope with
  no explicit parent rolls up to `global`, so existing flat scopes behave exactly as before.
- **Resolve down** (`lattice_recall`): an agent recalls across its scope *and all ancestors* at
  once, ranked by the documented `rank()` plus a small specificity bonus so the most-specific scope
  wins ties (a repo override beats the team default, but the team's knowledge stays in view). A pure
  read — no recall-reinforcement side effect across scopes.
- **Graduate up** (`graduate`): a belief independently **verified** in `>= min_scopes` sibling child
  scopes is promoted to the parent as a **candidate** (records `detail['graduated_from']`) — it must
  re-earn `verified` at the higher level via the promotion gate. Single-scope quirks and unverified
  beliefs never graduate; trust is never decreed by height.
- `examples/demo_shared_brain.py`; 231 offline-CI tests.

Individual and collective cognition are the same verbs at different radii of the lattice — next
slices: a hosted shared `MemoryView` service, and per-author trust on cross-agent imports.

## 0.18.0 — schema-split propagation (close the one real consistency hole revision left)

0.15.0's revision could split a leaf rule but left the schemas above it derived from the old,
broader rule — a corrected leaf under an over-claiming principle.
- **`propagate_revision`**: after a split, every `SCHEMA` whose `subsumes` includes the revised
  rule is re-derived from its CURRENT members (the narrowed rule among them), superseding the stale
  principle and resetting to `candidate` so it must re-earn trust. It then recurses **up** the
  hierarchy (order-2 → order-3 → …), with a depth guard. A schema that can't be re-derived is
  `contradict`ed rather than left over-claiming; unrelated schemas are untouched.
- Wired into `revise_with_counterexample`: a split now returns the re-derived schemas
  (`Revision.propagated`). Verified live: splitting a rule re-derived both its order-2 principle
  and the order-3 meta-principle above it.
- 220 offline-CI tests.

## 0.17.0 — the hosted skill registry (the H2 sweep justified it; trust still doesn't travel)

The two-model H2 sweep measured ~88–89% cross-tenant transfer → BUILD, so the public registry is
now built as a service.
- **Hosted registry** (`registry/hosted.py`): `RegistryServer` serves a `PublicRegistry` over a
  tiny stdlib HTTP API — `POST /publish` (verifies the signature; refuses a tampered or unsigned
  artifact with 400), `GET /search`, `GET /fetch`, `GET /all`. Optional bearer token.
- **`RemoteRegistry`**: a `PublicRegistry`-shaped client over HTTP, so
  `import_skill(remote.get(hash), into=local, target_cases=...)` works unchanged across machines.
- **Trust does not travel — end to end**: the server stores and integrity-checks artifacts but
  confers no trust; a fetched skill enters as a `candidate` and only becomes `verified` by passing
  the importer's OWN held-out eval. Verified live over real HTTP: a universal skill (slugify)
  re-verifies for a second tenant; a tenant-specific one (tax_total@8%) stays a candidate for a
  10% tenant; a tampered publish is refused; bad auth is rejected.
- 216 offline-CI tests.

## 0.16.0 — hosted control plane: the fencing authority behind an HTTP API (cross-machine)

The lease stores needed a shared filesystem; this lets managers on different machines coordinate.
- **Control plane** (`fleet/control_plane.py`): `ControlPlaneServer` wraps a durable
  `SqliteLeaseStore` in a tiny, dependency-free (stdlib `http.server`) HTTP service —
  acquire/renew/release/complete + token/outcome. The **server is the clock authority** (it stamps
  `now` itself), so managers with skewed clocks can't disagree about lease expiry. An optional
  bearer token gates access.
- **`RemoteLeaseStore`**: a `LeaseStore` over HTTP that speaks the same Protocol, so
  `Scheduler(leases=RemoteLeaseStore(url), owner=host)` coordinates cross-machine with no other
  change. Fencing holds over the wire: a stale `complete` returns 409 and the client raises
  `FencingError`. **Verified live** — two schedulers pointed at one control plane run each task
  exactly once and converge; a stale leader's write is refused; bad auth is rejected.
- 211 offline-CI tests.

## 0.15.0 — contradiction-driven schema revision (consolidation that can be wrong, and recovers)

Consolidation only ever grew. Now it can contract when reality disagrees.
- **Revision** (`memory/revise.py`): a new failure in a rule's domain that the rule failed to
  prevent is a counterexample. `revise_with_counterexample` records it (`annotate`, no
  corroboration), `contradict`s the rule, and once `split_after` counterexamples accumulate asks
  the LLM to **split** the over-broad rule into a NARROWED general rule (which supersedes the
  original via the interference key) plus a specific EXCEPTION rule — both candidate + inferred. If
  belief collapses below the reject floor, the rule is `rejected`. `contradicts(rule, failure)` is
  the pure domain-match check. Revision only ever lowers trust or narrows scope; it never
  auto-verifies.
- **`MemoryView.annotate`**: a new backend method (LocalMemory + mem0) to update a record's audit
  detail (e.g. its counterexample list) WITHOUT the corroboration side effect of `write`.
- 210 offline-CI tests.

## 0.14.0 — H2 broadened + swept across models (the moat decision no longer rests on one run)

- **Model sweep** (`examples/run_h2_sweep.py`): the H2 corpus-transfer measurement now runs across
  multiple (provider, model) configs on a **broadened corpus** (8 universal + 4 tenant-specific
  skills × 4 tenants) and tabulates the transfer rate per model. Measured live:
  - Ollama `qwen3-coder:480b` — 12/12 built, **32/36 = 89% → BUILD**
  - OpenAI `gpt-4o-mini` — 11/12 built, **29/33 = 88% → BUILD**
  Per-skill rates are identical across the two models (universal 100%; tenant-specific only where
  the tenant's rule matches), so the BUILD decision holds across models, not just one run.
  `docs/H2_RESULTS.md` now records the cross-model comparison.
- No library code change — a measurement/experiment release.

## 0.13.0 — fleet: git fencing sink (durable) + cross-repo atomic sagas

Completes the distributed-safety story the fencing leases started.
- **Git fencing sink** (`fleet/fence_sink.py`): a `pre-receive` hook fences *pushes*, not just
  task-store writes. The pusher sends `(resource, token)` as git push options
  (`git push -o verel-resource=R -o verel-token=N`); the hook accepts only when the token **is**
  the current one for that resource (checked against the sqlite lease store) — a stale leader's
  push, an unknown resource, or a forged higher token are all refused. `write_pre_receive_hook`
  installs it and enables push options on the bare remote. **Verified end-to-end against a real
  bare repo**: a stale push is rejected by the hook, the current one accepted.
- **Cross-repo atomic sagas** (`fleet/saga.py`): a multi-repo change commits as a saga — each step
  has a forward action and a compensation; the first failure runs the compensations of the
  already-committed steps in **reverse** order and skips the rest, so the set is all-or-nothing.
  `git_revert_head` is the safe compensation (an inverse commit, never a reset). A compensation
  that itself fails is reported, not swallowed.
- 204 offline-CI tests (incl. real-git end-to-end checks, skipped where git is absent).

## 0.12.0 — consolidation: multi-hop schema hierarchy + cross-scope generalization

- **Multi-hop hierarchy** (`induce_hierarchy`): consolidation no longer stops at one schema level.
  It climbs — rules → order-2 principles → order-3 meta-principles → … — each level consolidating
  the one below, until the corpus stops supporting a higher level (returns `{order: [schemas]}`).
  Every node stays `candidate`; height never confers trust.
- **Cross-scope consolidation** (`consolidate_across_scopes`): a failure pattern that recurs across
  **several repos** is lifted into a `global` `DesignRule` — but only when its evidence spans
  `>= min_scopes` distinct scopes (it records `detail['spans']`); a single-repo quirk is refused.
- **Better clustering**: `cluster_records` now buckets by a record's natural category (a failure's
  `kind`, a rule's `covers_kind`, else the `MemoryKind`), so same-family rules group together —
  which is what lets a higher hierarchy level find more than one cluster.
- 198 offline-CI tests.

## 0.11.0 — H2 measured for real + a tool-smith reuse-safety fix it exposed

Ran the §8.7 corpus-transfer experiment on a **live-built** corpus to resolve the moat bet with
data instead of assumption.
- **Real H2 run** (`examples/run_h2.py`, Ollama `qwen3-coder:480b` → OpenAI fallback): the
  tool-smith builds a mixed corpus — universal skills (slugify, is_palindrome, word_count,
  initials) + tenant-specific ones (tax_total@8%, price_label, order_code) — then each verified
  skill is re-verified against 4 tenants' own held-out cases. Measured **17/21 = 81% transfer →
  BUILD** (well above the 20% kill-line): universal skills transfer 100%, tenant-specific ones
  only where the rule matches (tax_total 33%, the EUR/10% tenant rejects the USD/8% skills).
  Result recorded in `docs/H2_RESULTS.md`. One corpus, one model — honest, not the last word.
- **Tool-smith reuse must re-verify** (correctness fix the run exposed): `ToolSmith.build` reused
  a semantic capability match **without** re-running it against the new spec's held-out cases, so
  a close-but-different tool could be returned as "verified" (it collapsed two skills in the first
  H2 run). Reuse now re-evaluates the candidate against the new cases and only short-circuits on a
  pass; otherwise it rebuilds. +1 regression test.
- 193 offline-CI tests.

## 0.10.0 — distributed fleet: fencing leases for concurrent managers + multi-repo DAGs

The scheduler was single-writer by design (so split-brain couldn't happen). This lifts that limit
safely — the v3 fencing work the code had deferred.
- **Fencing leases** (`fleet/lease.py`): a `LeaseStore` where every lease carries a **monotonic
  token**. Taking over an expired lease bumps it; same-owner renewal keeps it. Every terminal
  write is **fenced** — a stale leader whose token isn't current is rejected (`FencingError`), so
  it can't corrupt shared state. `InMemoryLeaseStore` (one process) and `SqliteLeaseStore`
  (`BEGIN IMMEDIATE`, cross-process).
- **Concurrent managers**: `Scheduler(leases=store, owner=...)` runs only tasks it can lease,
  fences its terminal writes, and **adopts peers' recorded outcomes** — so N schedulers over one
  store run each task exactly once and converge. With no `leases`, behaviour is byte-for-byte the
  single-writer v1.
- **Multi-repo coordination** (`fleet/multirepo.py`): `plan_multi_repo` namespaces per-repo tasks
  (`repo::id`), rewrites intra-repo deps, adds `CrossDep` edges, and validates the combined DAG
  acyclic (a cross-repo cycle is rejected up front, never deadlocked). One fenced scheduler then
  enforces cross-repo ordering ("ship the client only after the API builds").
- `examples/demo_distributed_fleet.py`; 192 offline-CI tests.

## 0.9.0 — deepened consolidation: adaptive decay, semantic clustering, structured + 2nd-order rules

The Brain's "episodic → semantic" step gets richer and its decay gets smarter.
- **Adaptive decay** (`effective_half_life`): a memory's half-life now stretches with demonstrated
  usefulness — `support_count` (log) + `epistemic_confidence` above the prior — capped at 6×. A
  corroborated rule outlives a one-off. Reachability tuning only; truth still moves solely via
  corroborate/contradict. Wired into the shared `apply_decay`, so LocalMemory and mem0 match.
- **Semantic clustering** (`cluster_records`): consolidation buckets failures by kind first (a
  strong prior — distinct kinds never merge), then, with `semantic=True` and a real embedder,
  refines each bucket by MEANING (cosine single-link) into finer sub-patterns.
- **Structured induction**: an induced `DesignRule` now carries `condition` / `action` /
  `applies_to` slots (not just a one-liner), so its matcher and the held-out gate test something
  specific. Back-compatible with the old `{subject, rule}` form.
- **2nd-order schemas** (`induce_schemas`, new `MemoryKind.SCHEMA`): clusters the DesignRules
  themselves and induces a higher-level principle that subsumes a family of rules. Guards against
  re-consolidating schemas. Candidate + inferred — earns trust the same way.
- `examples/demo_consolidation.py`; 181 offline-CI tests. The LLM is Ollama Cloud (OpenAI
  fallback); the chat fn is injectable so the whole module is tested offline.

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
