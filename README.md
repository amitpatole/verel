# Verel — Verified Agents 👁️🧠

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/hero.png" alt="Verel — the agent framework where nothing is done until a grader returns a verdict" width="100%">
</p>

<p align="center">
  <a href="https://pypi.org/project/verel/"><img src="https://img.shields.io/pypi/v/verel?color=8b7cff&label=pip%20install%20verel" alt="PyPI"></a>
  <a href="https://amitpatole.github.io/verel/"><img src="https://img.shields.io/badge/docs-amitpatole.github.io-5ad1e6" alt="Docs"></a>
  <img src="https://img.shields.io/badge/tests-198%20passing-46d39a" alt="tests">
  <img src="https://img.shields.io/badge/ruff%20%2B%20mypy-clean-5ad1e6" alt="lint">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
  <img src="https://img.shields.io/badge/LLM-Ollama%20Cloud%20%C2%B7%20OpenAI-8b7cff" alt="LLM">
</p>

> **Problem:** AI agents declare work *“done”* on their own say-so — shipping broken UIs,
> failing tests and unverified claims they can’t actually check.
> **Result:** Verel makes *“done”* a **verdict**, not an opinion — every action is graded by
> real senses (including **eyes**, via [AgentVision](https://github.com/amitpatole/agent-vision)),
> and **only verified work compounds** into the fleet’s shared memory.

Verel is an agent framework built on the idea that **every agent action is a hypothesis**:

```
write → perceive → gate (verdict bus) → fix → re-render → pass (self-computed)
```

One **verdict bus** unifies vision + tests + lint + types into a single `pass / warn / fail`,
so *progress*, *“done”*, and *what compounds* are all decided in one place — with grader
attestation so a hollow check can’t mint green.

## The 60-second pitch

```bash
pip install verel
verel doctor                 # check your environment
verel heal --repo .          # self-healing CI: failing tests → agent fixes → green
```

```python
from verel.ci import inner_loop_stage, self_heal
result = self_heal(".", inner_loop_stage(".", with_lint=False))   # tests fail → agent patches → pass
print(result.healed, result.terminated_on)
```

Default LLM is **Ollama Cloud** (`~/.config/ollama/key`, model `qwen3-coder:480b`); set
`VEREL_LLM_PROVIDER=openai` to switch. Claude is one branch away in `agents/llm.py`.

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/infographic.png" alt="Verel architecture — the five organs and the eval-driven loop" width="100%">
</p>

## The five organs

| Organ | Module | What it does |
|---|---|---|
| 🧠 **Brain** | `verel.memory` | Memory that compounds — trust + provenance, consolidation, and a **held-out, attested promotion gate**. Only verified facts/skills graduate. Lifecycle controls (**pin** / **volatile-until-confirmed** / **TTL** / **correction chains** / **adaptive decay** — useful memories decay slower) keep it from becoming a junk drawer. Consolidation induces **structured rules** (condition→action), a **multi-hop schema hierarchy** (rules → principles → meta-principles), and **cross-scope** rules (a bug recurring across repos becomes a global rule). Backends: zero-dep `LocalMemory` or rented `mem0`; semantic recall + clustering via embeddings. |
| 👁️ **Eyes** | `verel.senses` | **AgentVision** as a perception organ (DOM/contrast/OCR grounded) feeding both the verdict bus and the brain as one of many senses. |
| ⚖️ **Verdict bus** | `verel.verdict` | One schema for every sense, with an advisory **ceiling clamp**, **grader attestation**, scrubbed fingerprints, and strict-subset **stuck/progress** detection. |
| 🚁 **Fleet** | `verel.fleet` | Agents managing agents — an **LLM manager** fans out, a scheduler runs workers in **isolated git worktrees** under budget, each gated by the bus. **Concurrent managers** are safe via **fencing leases** (a stale leader's writes are rejected), and **multi-repo** changes run as one cross-linked DAG. |
| 🔧 **Tool-smith** | `verel.toolsmith` | Agents build their own tools: detect → scaffold → test → register → reuse, **sandboxed** (`bwrap`), admitted only on a passing attested eval. |
| ♻️ **Agent-run CI/CD** | `verel.ci` | Self-healing pipeline (inner-loop → pre-commit → pre-merge → canary) with a deterministic **rollback engine** that never acts on advisory evidence. Graders span **Python / JS-TS / Go** (tests · lint · types) plus **perf** (budget) and **security** (SAST/audit) senses — all on one bus, one gate. |

## Eyes & Brain — Verel × AgentVision

Two systems, one nervous system. **[AgentVision](https://github.com/amitpatole/agent-vision)
is the eyes**; **Verel is the brain.** The eyes perceive a rendered artifact and grade it —
including *does it match what we set out to build?* — then hand a clean signal up the optic
nerve. The brain decides with grader attestation, acts, and **only verified work compounds**
into memory. Then the eyes look again.

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/unified-architecture.png" alt="Eyes & Brain — AgentVision perceives and grades intent; Verel decides and compounds verified work into memory" width="100%">
</p>

They ship and version independently (`pip install agentvision`, `pip install verel`), but in
sync: AgentVision's perception maps onto Verel's verdict bus as one grounded sense among many,
and its **intent conformance** (`matches_intent`) is recorded in the brain's episodic memory
every iteration. A *full* brain like Verel ingests the rich `Report` and runs its own gate;
AgentVision's distilled `Handoff` is there for simpler brains. See
[AgentVision's handoff doc](https://github.com/amitpatole/agent-vision/blob/main/docs/handoff.md).

The eyes can also **watch over time** — `verel.senses.watch(...)` drives AgentVision's temporal
verification (playback / loading / liveness for streaming UIs, video, live dashboards). A
deterministic video **stall** gates the bus to FAIL, and `playing` / `live` / `stabilized`
land in the brain's memory — so a release can be gated on *verified playback*, and "the player
plays" compounds across builds.

## What makes it trustworthy

- **Grader attestation** — a required grader must present a signed `run_receipt` proving it
  ran the frozen suite over the changed files. A hollow `PASS, issues=[]` *fails* the gate.
- **Precise vs advisory** — per-issue trust keys off the source (DOM/CV/OCR/test = precise;
  vision/LLM-judge = advisory, clamped to `warn`). Destructive actions (rollback) **never**
  depend on advisory evidence.
- **Only verified work compounds** — a consolidated rule starts `inferred` and reaches
  `verified` *only* by passing a held-out, agent-inaccessible eval (with a leakage canary).
- **Dogfooded** — Verel gates its own development with its own verdict bus (CI runs the
  pre-merge gate over Verel and asserts `pass`). The infographic above was rendered and
  verified by the eyes Verel ships.

## Many faces, one core

| Surface | For |
|---|---|
| **Library** (`import verel`) | Python apps & custom harnesses |
| **CLI** (`verel …`) | `doctor` · `loop` · `fleet` · `heal` · `ci` |
| **CI CLI / git hook** (`verel-ci`, `python -m verel.ci`) | agent-run CI, pre-commit gates |
| **MCP server** (`verel-mcp`) | Cursor, Claude, any MCP host |

## Drop it into your workflow & your agents

**CI gate (GitHub Action)** — unify tests + lint + types into one verdict and fail the build:

```yaml
# .github/workflows/verify.yml
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v0.4.5
        with:
          repo: .
          install: "-e .[dev]"     # your project deps so its tests import
```

**pre-commit** (this repo ships `.pre-commit-hooks.yaml`):

```yaml
- repo: https://github.com/amitpatole/verel
  rev: v0.4.5
  hooks: [{ id: verel-precommit }]
```

**Native git hook / any script:**

```bash
verel-ci check --repo .       # verdict bus gate; non-zero exit on FAIL
verel-ci install --repo .     # wire a native pre-commit hook
```

**In your agents** — `verel-mcp` exposes the verdict bus + memory to any MCP host; the eyes
(AgentVision) plug in as the `sight` sense. Add `verel[sight]` for visual gating, and
`verel.senses.watch(...)` to gate on verified playback over time.

## Try the demos

```bash
python examples/demo_selfheal.py         # failing tests → agent patches code → green
python examples/demo_overflow_loop.py    # fix a UI until AgentVision returns pass
python examples/demo_fleet_worktrees.py  # LLM manager fans out → isolated-worktree workers
python examples/demo_h2_moat.py          # measure cross-tenant skill transfer → moat decision
python examples/demo_canary_rollback.py  # bad merge fails canary → safe auto git-revert
python examples/demo_capability_jail.py  # learn a tool's syscalls → deny everything it didn't earn
python examples/demo_polyglot_ci.py      # Python/JS/Go + perf + security graders on one bus
python examples/demo_consolidation.py    # failures → structured rules → a 2nd-order schema
python examples/demo_distributed_fleet.py # concurrent managers (fencing) + multi-repo DAG
python examples/run_h2.py                # LIVE: build skills, measure cross-tenant transfer
```

## Honesty (what we do **not** claim)

- The in-process tool guard is a guardrail, not a sandbox — real isolation is the `bwrap`
  container runner (`isolation="container"`): no network, read-only system-only fs, ephemeral
  tmp, cleared env, **and a seccomp-bpf syscall filter** (`verel[container]`). Three profiles,
  weakest→strongest: **denylist** (default; EPERM on ptrace/mount/raw-socket/namespace/module/bpf
  — safe for arbitrary tools), **allowlist** (default-deny, only what a pure-compute CPython needs
  — no network, subprocess, or threads), and **capability** — the tightest: a tool may use only
  the syscalls it *exercised while passing its held-out eval* (learned via `strace`), so anything
  it never earned — including a syscall the allow-list would permit — is refused at the kernel.
- The moat (a public verified-skill registry) is a **bet** we *measure*, not assume — the **H2
  experiment** (`verel.registry`) re-verifies live-built skills against other tenants' held-out
  cases. A first real run (Ollama `qwen3-coder:480b`, 7 skills × 4 tenants) measured **81%
  transfer → BUILD** ([results](docs/H2_RESULTS.md)): universal skills transfer 100%,
  tenant-specific ones only where the rule matches. One corpus, one model — re-run before betting.
- Advisory (vision/LLM) findings are advisory; they inform, they don’t gate destructive acts.

## Documentation

📖 **Full docs site: [amitpatole.github.io/verel](https://amitpatole.github.io/verel/)**

- [Get started](docs/getting-started.md) · [Architecture & roadmap](docs/ARCHITECTURE.md) ·
  [Module guide](src/verel/README.md) · [Changelog](CHANGELOG.md)

## License

MIT © Amit Patole · eyes by [AgentVision](https://github.com/amitpatole/agent-vision)
