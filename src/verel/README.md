# `verel` — module guide

A map of the package: what each module does, what to import from it, and where to go deeper. For
task-oriented docs (install, recipes, per-organ usage) read the **[Developer guide](../../docs/usage.md)**.

> **The thesis in one line:** an agent's output is a *hypothesis* until a grader returns a
> verdict. Verel unifies every check — tests, types, lint, vision, perf, security — into one
> `pass / warn / fail`, and only verified work is allowed to compound into memory.

```bash
pip install verel            # core (only runtime dep: pydantic)
```

```python
from verel.verdict import Report, Issue, IssueKind, Severity, GraderKind, Verdict, gate, assign

report = assign(Report(verdict=Verdict.FAIL, summary="2 type errors", grader=GraderKind.TYPECHECK,
                       issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR,
                                     source=GraderKind.TYPECHECK, message="bad return", locator="app.py:42")]))
print(gate([report], required={GraderKind.TYPECHECK}).verdict)   # Verdict.FAIL
```

---

## The six organs at a glance

| Organ | Package | Import the… | One line |
|---|---|---|---|
| ⚖️ **Verdict bus** | `verel.verdict` | `gate`, `Report`, `Issue` | the unified eval contract every sense speaks |
| 👁️ **Eyes / senses** | `verel.senses` | `perceive`, `watch` | AgentVision as a grounded perception sense (needs `verel[sight]`) |
| 🧠 **Brain** | `verel.memory` | `LocalMemory`, `consolidate_failures` | the trust layer — only verified facts/skills compound |
| 🚁 **Fleet** | `verel.fleet` | `Scheduler`, `Task` | agents managing agents, every node gated by the bus |
| 🔧 **Tool-smith** | `verel.toolsmith` | `ToolSmith`, `run_container` | agents build + sandbox their own tools |
| ♻️ **Agent-run CI/CD** | `verel.ci` | `run_stage`, `self_heal` | tests/lint/types/perf/security as graders, self-healing |
| 📦 **Skill registry** | `verel.registry` | `PublicRegistry`, `import_skill` | publish/fetch signed skills — trust does not travel |

---

## ⚖️ `verel.verdict` — the verdict bus

The single most load-bearing surface. Every grader produces a `Report`; `gate()` reduces a set to
one verdict under a few non-negotiable rules.

| File | What's in it |
|---|---|
| `models.py` | `Report` / `Issue` / `Percept` / `RunReceipt` / `GateResult`; the `Verdict`, `Severity`, `GraderKind`, `IssueKind` enums |
| `constants.py` | `SEV_ORDER`, `GATING_SEVERITY`, `ADVISORY_CEIL`, the `PRECISE_GRADERS` / `ADVISORY_GRADERS` sets |
| `fingerprint.py` | `assign()` / `fingerprint()` — scrubbed, stable per-issue fingerprints (line nums, addrs, floats normalized); `issue_signature()` |
| `gate.py` | `gate()` (advisory-ceiling clamp + dead/hollow-gate attestation), `progressed()` (strict-subset shrinkage), `sign_receipt()` / `verify_signature()` |

Rules `gate()` enforces: **advisory ceiling** (vision/LLM clamped to `warn`), **attestation** (a
required grader must carry a signed receipt or it fails), **stuck vs. progress** (progress = strict
shrinkage of the gating-failure set).

## 👁️ `verel.senses` — the eyes (needs `verel[sight]`)

| File | What's in it |
|---|---|
| `sight.py` | the AgentVision adapter — maps perception onto the bus; grader identity keys off `Issue.source`; `CLASSIC_CAPABILITIES` imported from source (drift-proof) |
| `percept_log.py` | a Verel-owned, crash-safe episodic percept log with its own progressed/stuck |
| `__init__.py` | `perceive()` (a single glance — DOM/contrast/OCR + intent), `watch()` (temporal: playback/loading/liveness), `PerceptLog`, `SightResult` |

## 🧠 `verel.memory` — the brain

A trust layer over a swappable backend. Two orthogonal quantities, never collapsed:
`epistemic_confidence` (belief) and `retrieval_strength` (reachability).

| File | What's in it |
|---|---|
| `view.py` | the `MemoryView` Protocol + `MemoryRecord`; the interference rule, documented `rank()`, exact prune rule, `apply_decay`/`effective_half_life` (adaptive), lifecycle (pin / volatile-until-confirmed / TTL / staleness / correction chains) |
| `local.py` | `LocalMemory` — the zero-dependency sqlite backend, optional semantic recall |
| `mem0_backend.py` | `Mem0Memory` — the rented mem0 store behind the SAME Protocol (`make_ollama_mem0()`) |
| `embed.py` | `HashEmbedder` (offline) / `OpenAIEmbedder` (semantic) + `cosine` — vectors for recall & clustering |
| `failure_ledger.py` | record failures → `mark_fixed` on PASS → the regression guard gates a reintroduction from memory alone |
| `consolidate.py` | episodes → candidate structured `DesignRule`s; `induce_hierarchy` (multi-hop schemas); `consolidate_across_scopes` (cross-repo → global); `cluster_records` |
| `revise.py` | **contradiction-driven revision** — `revise_with_counterexample` (weaken → split → reject), `propagate_revision` (re-derive schemas above a split), `contradicts` |
| `promotion.py` | the held-out, attested, agent-inaccessible eval gate: `inferred → verified` with a leakage canary (`PromotionGate`, `HeldOutCorpus`, `EvalCase`) |

Everything induced starts `candidate` / `inferred`; height, breadth, and survival never confer trust.

## 🔧 `verel.toolsmith` — agents build their own tools

`detect → scaffold → test → register → reuse`, admitted only on a passing attested eval (reuse
**re-verifies** — a close match isn't trusted blindly).

| File | What's in it |
|---|---|
| `smith.py` | `ToolSmith`, `ToolSpec`, `ToolCase`, `BuildResult` — the build lifecycle; `eval_tool_cases` |
| `registry.py` | the signed, versioned tool registry as SKILL records; `ToolRegistry`, `ToolRecord`, `SideEffect`, `load_callable` |
| `sandbox.py` | the rlimit subprocess sandbox (fresh interpreter, CPU/mem/file limits, timeout); `run_sandboxed` |
| `container.py` | the `bwrap` namespace runner (no net, read-only fs, ephemeral tmp); `run_container`, `best_runner` |
| `seccomp.py` | the seccomp-bpf filter — `denylist` / `allowlist` / `capability` profiles; `build_bpf`, `capability_allow` |
| `seccomp_learn.py` | `learn_syscall_profile` — derive a tool's per-capability syscall policy by tracing its verified eval |

Isolation tiers run weakest→strongest: `subprocess` → `container` → `container` + seccomp profile.

## 🚁 `verel.fleet` — agents managing agents

A scheduler over a Task DAG, every node gated by the bus.

| File | What's in it |
|---|---|
| `task.py` | `Task` (DAG node: deps/barriers/budget/retry), `Role`, `TaskState`, `Barrier`, `BudgetLease`, `RetryPolicy` |
| `scheduler.py` | `Scheduler` — barriers (all/k_of_n/optional), concurrency, retry→quarantine, hard budget, WAL resume; gates every node |
| `manager.py` / `llm_manager.py` | manager fan-out: the LLM proposes, the plane validates/clamps/falls back (`decide_fanout`, `plan_over_artifacts`) |
| `worktree.py` | one isolated git worktree per worker + an exclusive advisory lock (`WorktreeManager`) |
| `worker.py` | worker adapters — `ultracode_worker`, `worktree_ultracode_worker` |
| `lease.py` | **fencing leases** for concurrent managers — `InMemoryLeaseStore` / `SqliteLeaseStore`, monotonic tokens, `FencingError` |
| `fence_sink.py` | the **git pre-receive fencing sink** — `write_pre_receive_hook`, `validate_push` (a stale push is refused at the remote) |
| `multirepo.py` | `plan_multi_repo` + `CrossDep` — namespace per-repo tasks into one cross-linked, acyclic DAG |
| `saga.py` | **cross-repo atomic sagas** — `run_saga`, `SagaStep`, `git_revert_head` (a failure compensates landed repos in reverse) |
| `control_plane.py` | the **hosted control plane** — `ControlPlaneServer` + `RemoteLeaseStore` (lease authority over HTTP, cross-machine) |

## ♻️ `verel.ci` — agent-run CI/CD

Tests, lint, and types as first-class graders across **Python / JS-TS / Go**, plus **perf** and
**security**, on the same bus.

| File | What's in it |
|---|---|
| `graders.py` | per-language graders + pure parsers — `pytest`/`ruff`/`mypy`, `jstest`(TAP)/`eslint`/`tsc`, `gotest`/`govet`, `perf_spec`, `bandit`/`npm_audit`; `LANGS` toolchains |
| `pipeline.py` | the staged pipeline — `inner_loop_stage` / `precommit_stage` / `premerge_stage` / `postmerge_stage`, `run_stage` (+ failure-memory) |
| `medic.py` | classify each failure → retry / regen-lockfile / quarantine-flaky / fix-branch |
| `heal.py` | the self-healing loop — `self_heal` runs the code-fixer on genuine regressions, re-gating each round |
| `rollback.py` | the policy engine + executor — agent proposes, the engine authorizes only on **precise** evidence and does a safe `git revert` |
| `canary.py` | the post-merge canary → verdict-driven rollback (`canary_rollback`) |
| `hooks.py` + `__main__.py` | `verel-ci {check,precommit,install}` — the git-hook / CLI surface |

## 📦 `verel.registry` — the public skill registry

Content-addressed, signed skill artifacts; the one rule that keeps the flywheel honest is **trust
does not travel** — a fetched skill re-earns trust on import.

| File | What's in it |
|---|---|
| `artifact.py` | the content-addressed, signed, provenance-tagged `SkillArtifact` |
| `store.py` | `PublicRegistry` — publish (verifies signature) / get / search |
| `transfer.py` | `export_skill` + `import_skill` (install + **re-verify** against the importer's own cases) |
| `hosted.py` | the **hosted registry** — `RegistryServer` + `RemoteRegistry` (publish/fetch over HTTP) |
| `h2.py` | `measure_transfer` — the corpus-transfer experiment that *measures* whether the registry is a real moat (see [H2 results](../../docs/H2_RESULTS.md)) |

---

## Surfaces (top-level)

| File | Surface | Entry |
|---|---|---|
| `cli.py` | the `verel` CLI | `verel doctor \| loop \| fleet \| heal \| ci` |
| `ci/__main__.py` | the CI gate / git hook | `verel-ci check \| precommit \| install` |
| `mcp_server.py` | the MCP server | `verel-mcp` — tools: `verel_gate`, `verel_recall`, `verel_build_tool`, `verel_ci_check` |
| `agents/llm.py` | the model seam | provider-agnostic `chat()` — Ollama default, OpenAI fallback, Claude-ready |
| `loop.py` | the single-worker ultracode loop | `render → perceive → gate → fix → re-render`, terminating on a self-computed verdict |

---

## Examples

Runnable demos in [`examples/`](../../examples) — most run offline (the LLM is stubbed); the `run_h2*`
scripts need a key.

```bash
python examples/demo_polyglot_ci.py       # Python/JS/Go + perf + security graders on one bus
python examples/demo_consolidation.py     # failures → rules → schema hierarchy → revision
python examples/demo_capability_jail.py   # sandbox a tool to only the syscalls it earned
python examples/demo_distributed_fleet.py # concurrent managers (fencing) + multi-repo saga
python examples/demo_hosted_registry.py   # publish a skill; another tenant re-verifies it
python examples/demo_selfheal.py          # failing tests → agent patches → green
python examples/run_h2_sweep.py           # LIVE: measure cross-tenant transfer across models
```

220 offline-CI tests, ruff + mypy clean, ships `py.typed`. Verel gates its own development through
its own verdict bus in CI. Next stop: the **[Developer guide](../../docs/usage.md)** ·
**[Architecture & roadmap](../../docs/ARCHITECTURE.md)** · **[Changelog](../../CHANGELOG.md)**.
