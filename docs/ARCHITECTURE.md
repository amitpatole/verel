# Verel — Architecture & Roadmap

Verel is an agent framework built on one idea: **every agent action is a hypothesis, and
nothing is "done" until a grader returns a verdict.** A single verdict bus unifies every
kind of check — vision, tests, lint, types — into one `pass / warn / fail`, so *progress*,
*"done"*, and *what compounds into memory* are all decided in one place.

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/flow_diagram.png" alt="Verel eval-driven loop" width="92%">
</p>

This document describes how the pieces fit together and where the project is going. For the
exact module layout see the [module guide](https://github.com/amitpatole/verel/blob/main/src/verel/README.md); for the release history
see the [changelog](https://github.com/amitpatole/verel/blob/main/CHANGELOG.md).

---

## The five organs

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/architecture.png" alt="Verel system architecture" width="100%">
</p>

| Organ | Module | Responsibility |
|---|---|---|
| **Verdict bus** | `verel.verdict` | One `Report`/`Percept` schema for every sense; `gate()` reduces them to a verdict. |
| **Eyes / Senses** | `verel.senses` | AgentVision as a grounded perception adapter, plus the percept log. |
| **Brain** | `verel.memory` | The trust layer over a memory backend: what is believed, how strongly, and what compounds. |
| **Fleet** | `verel.fleet` | Agents managing agents — manager fan-out, scheduler, isolated worktrees. |
| **Tool-smith** | `verel.toolsmith` | Agents building, testing, and registering their own tools. |
| **Agent-run CI/CD** | `verel.ci` | Graders, staged pipeline, self-healing, and verdict-driven rollback. |

---

## The verdict bus (`verel.verdict`)

Every grader emits a `Report` of `Issue`s with a `verdict`. `gate()` reduces a set of reports
to a single verdict under a few load-bearing rules:

- **Advisory ceiling.** Per-issue trust keys off the issue *source*. Precise sources
  (DOM / CV / OCR / test / lint / typecheck) gate at full severity; advisory sources
  (vision / LLM-judge) are clamped to at most `warn`. An advisory opinion never gates a
  hard failure.
- **Grader attestation.** A *required* grader must present a signed `run_receipt` proving it
  ran the frozen suite over the changed files. A hollow `PASS, issues=[]` with no receipt
  **fails** the gate — "present-but-empty" can't mint green.
- **Scrubbed fingerprints.** Each issue gets a stable, normalized fingerprint (line numbers,
  addresses, timestamps, floats scrubbed) so the same logical failure hashes identically
  across runs — which is what makes stuck-detection reliable.
- **Stuck vs. progress.** Progress is defined as **strict shrinkage** of the gating-failure
  set. Pure churn or growth is not progress; a new gating issue is a regression.

---

## The Brain — memory that compounds (`verel.memory`)

Memory is state stored outside the model and selectively re-injected. Verel owns the **trust
layer** over a (swappable) backend — `LocalMemory` (zero-dependency SQLite) or `mem0` — behind
a single `MemoryView` protocol.

Each record carries **two orthogonal quantities, never collapsed into one**:
- `epistemic_confidence` — how true we believe it is. Moved **only** by corroboration (+) and
  contradiction (−). Retrieval never touches it.
- `retrieval_strength` — how reachable it is. Decays with disuse, resets on recall. The decay is
  **adaptive**: a memory's effective half-life stretches with demonstrated usefulness
  (`support_count` + `epistemic_confidence`), so a corroborated rule outlives a one-off — tuning
  of reachability only, never of truth.

On top of that:
- **Interference rule** — a new value for the same `(subject, predicate, scope)` supersedes
  rather than silently duplicating.
- **Consolidation** — an offline pass clusters recurring failures (by kind, or by **meaning** with
  an embedder) and induces a candidate **structured** `DesignRule` (`condition → action`,
  `applies_to`). `induce_hierarchy` then climbs a **multi-hop `SCHEMA` ladder** — rules → order-2
  principles → order-3 meta-principles — until the corpus stops supporting a higher level, so the
  top is the most general principle the evidence backs. `consolidate_across_scopes` lifts a pattern
  that recurs across **several repos** into a `global` rule (and refuses a single-repo quirk). All
  start `inferred`; height and breadth never confer trust.
- **Contradiction-driven revision** (`revise_with_counterexample`) — consolidation can also be
  *wrong*. A new failure in a rule's domain that the rule failed to prevent is a counterexample:
  it's recorded (via `annotate`, no corroboration), the rule is `contradict`ed, and once enough
  counterexamples accumulate the rule is **split** into a narrowed general rule (which supersedes
  the original) plus a specific exception rule — or, if belief collapses, `rejected`. Revision only
  ever lowers trust or narrows scope.
- **Promotion gate** — a candidate reaches `verified` **only** by passing a held-out,
  agent-inaccessible eval (with a leakage canary). Trust is earned, never asserted.
- **Failure ledger + regression guard** — past gating failures are remembered; reintroducing
  a previously-fixed failure fails the gate from memory alone.
- **Recall** — lexical by default; semantic (cosine) when an embedder is configured.
- **Lifecycle controls** — `pinned` memories ignore decay and are never pruned; `volatile`
  memories are kept only if corroborated/verified within a window; a hard `ttl_s` expires
  ephemeral environment facts; idle records are flagged `stale`; and supersedes keep a
  queryable **correction chain** instead of overwriting history.

---

## The Fleet — agents managing agents (`verel.fleet`)

A control plane over agent execution:

- **Manager** decomposes a goal into a fan-out of independent subtasks (LLM-driven, with the
  plane validating and clamping the decision — and falling back safely on bad output).
- **Scheduler** — runs a Task DAG with barrier policies (`all` / `k_of_n` / `optional`), a
  concurrency cap, retry → quarantine, a hard budget lease, and WAL-based crash resume. Every
  node is gated by the verdict bus, so a worker can't self-declare done.
- **Concurrent managers** — more than one scheduler can share a task store safely via **fencing
  leases** (`lease.py`): a lease carries a monotonic token, taking over an expired lease bumps it,
  and every terminal write is fenced — a stale leader whose token is no longer current is
  *rejected*, not allowed to corrupt shared state. Peers adopt each other's recorded outcomes, so
  each task runs exactly once. Backends: in-memory (one process) or sqlite (`BEGIN IMMEDIATE`,
  cross-process).
- **Git fencing sink** — fencing isn't only in the task store: a `pre-receive` hook on the remote
  (`fence_sink.py`) refuses a *push* whose token isn't current, so a paused leader can't push stale
  code over a successor's. The pusher passes `(resource, token)` as git push options; the hook
  checks them against the same sqlite store.
- **Multi-repo coordination** — `plan_multi_repo` namespaces per-repo tasks and adds cross-repo
  edges into one DAG, validated acyclic (a cross-repo cycle is rejected up front, never
  deadlocked). One fenced scheduler then enforces "ship the client only after the API builds".
- **Cross-repo atomic sagas** — a change spanning repos commits as a saga (`saga.py`): each step
  has a forward action and a compensation, and a failure runs the compensations of the
  already-committed steps in reverse (a safe `git revert`, never a reset) — all-or-nothing.
- **Hosted control plane** — for managers on *different machines* (no shared filesystem), the lease
  authority is wrapped in a tiny, dependency-free HTTP service (`control_plane.py`). The server is
  the clock authority (so skewed manager clocks can't disagree about expiry); a `RemoteLeaseStore`
  client speaks the same `LeaseStore` Protocol, so `Scheduler(leases=RemoteLeaseStore(url))`
  coordinates cross-machine unchanged. Terminal writes are still fenced (a stale `complete` is a
  409); an optional bearer token gates access.
- **Worktrees** — each worker runs in its own isolated git worktree with an exclusive
  advisory lease, so parallel workers never stomp each other.

---

## Tool-smith — agents build their own tools (`verel.toolsmith`)

Lifecycle: **detect → scaffold → test → register → reuse.** A capability request first tries
reuse (semantic when an embedder is present); if missing, an LLM scaffolds a function, it is
tested against held-out cases, and it is admitted to procedural memory **only on a passing,
attested eval**. Read-only/idempotent tools auto-verify; destructive tools require a
human-review verdict. Tool code is content-signed and executed under isolation
(`isolation="container"` uses a `bwrap` namespace sandbox — no network, read-only fs — plus an
optional seccomp-bpf syscall filter via `verel[container]`, in three profiles: a default denylist;
a default-deny allowlist jail (no network/subprocess/threads); and a per-tool **capability** jail
that allows only the syscalls a tool exercised while passing its held-out eval, learned via
`strace` and frozen onto the tool — so a verified tool that later attempts a new syscall is
refused at the kernel).

---

## Agent-run CI/CD (`verel.ci`)

Tests, lint, and types are first-class senses on the same bus — across **Python, JS/TS, and Go**
(`language=` on each stage), plus **perf** and **security** senses. A `GraderSpec` carries its own
parser, so `pytest`, `go test -json`, and a TAP runner — all `GraderKind.TEST` — parse by their own
format while sharing one schema, one gate, and one stuck/progress signal. The staged pipeline:

| Stage | What runs |
|---|---|
| **inner-loop** | lint / typecheck / fast unit on the working tree (per language) |
| **pre-commit** | unit + affected tests + a failure-memory regression check |
| **pre-merge** | full suite + lint + types, optionally **security** (SAST/audit) and a **perf** budget |
| **post-merge / canary** | smoke/E2E; on a precise-evidence failure, an automated rollback |

Perf and security are **precise** graders: a perf regression past an explicit budget, or a
HIGH/CRITICAL security finding, gates (and can drive rollback) — sub-threshold findings only
advise. Language toolchains live in `verel.ci.LANGS`; adding a runtime is one `LangToolchain` entry.

- **Self-healing** — on failure the ci-medic classifies each issue (retry / regen-lockfile /
  quarantine-flaky / fix-branch) and, for genuine regressions, invokes the code-fixer agent,
  re-gating every round until the graders pass or it escalates.
- **Rollback policy engine** — the agent *proposes*, a deterministic engine *authorizes* (only
  on precise gating evidence) and performs a safe, non-destructive `git revert`. A destructive
  action never depends on advisory evidence.

---

## Surfaces

- **Library** (`import verel`) · **CLI** (`verel doctor|loop|fleet|heal|ci`) ·
  **CI CLI / git hook** (`verel-ci`, `python -m verel.ci`) · **MCP server** (`verel-mcp`).

Default LLM provider is Ollama Cloud; OpenAI is the bundled fallback, and the provider seam in
`agents/llm.py` makes others (e.g. Claude) a small addition.

---

## Roadmap

**Done (all five organs, end-to-end):** verdict bus with attestation; AgentVision sight
adapter; the memory trust layer with consolidation + promotion gate (LocalMemory and mem0);
semantic recall; the fleet (manager + scheduler + worktrees); the tool-smith with subprocess
and container isolation; the full CI/CD stage table with self-healing and rollback; a
content-addressed skill registry with a cross-tenant transfer experiment; CLI + MCP surfaces.
The project is lint/type-clean, ships type information, and gates its own development through
its own verdict bus in CI.

**Next:**
- Broaden senses further — Rust/Java toolchains; richer perf harnesses; more SAST backends.
- Consolidation: propagate a split up the schema hierarchy (revise the principles a narrowed rule
  fed, not just the rule itself).
- Distributed hardening — replicate the control-plane store (today a single sqlite host is the
  authority); push-time identity (sign the push token to the fencing sink).
- A hosted skill registry — a first live H2 run measured 81% cross-tenant transfer (BUILD; see
  `docs/H2_RESULTS.md`), so this is now justified pending a broader corpus/model sweep.
- Seccomp profile portability across architectures (the learned policy is x86-64-derived today).

---

## Honest limits

- The in-process tool guard is a guardrail, not a sandbox; real isolation is the container
  runner — namespace isolation (no network, read-only fs) plus a seccomp-bpf syscall filter in
  three profiles: a default denylist, a default-deny allowlist jail (no network/subprocess/
  threads), and a per-tool capability jail allowing only the syscalls a tool earned while verified.
- Advisory (vision/LLM) findings inform but never gate destructive actions.
- Vision-model bounding boxes are advisory, not pixel-accurate; LLM outputs are not
  deterministic. Verel is explicit about which signals are precise and which are advisory.
