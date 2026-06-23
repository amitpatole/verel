# Developer guide

How to use Verel as a library, a CLI, a CI gate, and an MCP server. Every example here runs
against the real API; the ones that need a model say so.

The one idea underneath all of it: **an agent's output is a hypothesis until a grader returns a
verdict.** You compose graders (any sense — tests, lint, types, vision, perf, security) into a
`Report`, reduce them with `gate()`, and only verified work is allowed to compound.

---

## Install

```bash
pip install verel                 # core (only dependency: pydantic)
pip install "verel[dev]"          # + pytest / ruff / mypy graders (the CI gate)
pip install "verel[sight]"        # + AgentVision eyes (visual gating + temporal watch)
pip install "verel[container]"    # + seccomp-bpf for the bwrap tool sandbox
pip install "verel[mem0]"         # + the rented mem0 memory backend
pip install "verel[mcp]"          # + the MCP server
```

| Extra | Pulls in | Enables |
|---|---|---|
| `dev` | pytest, ruff, mypy | the Python test/lint/type graders |
| `sight` | `agentvision[render]` | `verel.senses` — DOM/contrast/OCR vision + `watch` |
| `container` | `pyseccomp` | the seccomp syscall filter on the `bwrap` tool runner |
| `mem0` | `mem0ai`, `chromadb` | `Mem0Memory` as the `MemoryView` backend |
| `mcp` | `mcp`, `anyio` | `verel-mcp` (Cursor / Claude / any MCP host) |

Verify your environment:

```bash
verel doctor
```

### Configure the LLM

Anything that authors or judges with a model uses the provider seam in `verel.agents.llm`. Default
is **Ollama Cloud**; **OpenAI** is the bundled fallback.

```bash
export VEREL_LLM_PROVIDER=ollama        # default; or: openai
export VEREL_CODER_MODEL=qwen3-coder:480b
```

Keys resolve from an env var first, then `~/.config/<provider>/key`:

| Provider | Env var | Key file | Default model |
|---|---|---|---|
| `ollama` | `OLLAMA_API_KEY` | `~/.config/ollama/key` | `qwen3-coder:480b` |
| `openai` | `OPENAI_API_KEY` | `~/.config/OpenAI/key` | `gpt-4o-mini` |

Everything that calls a model takes an injectable `chat` function, so unit tests (and the
offline examples in `examples/`) run with no key at all.

---

## The surfaces

| Surface | Entry point | Use it for |
|---|---|---|
| **Library** | `import verel` | building your own harness on the verdict bus |
| **CLI** | `verel …` | `doctor` · `loop` · `fleet` · `heal` · `ci` |
| **CI CLI / git hook** | `verel-ci …` | a verdict-bus gate in CI or a pre-commit hook |
| **MCP server** | `verel-mcp` | exposing gate / recall / build-tool / ci-check to an MCP host |
| **GitHub Action** | `amitpatole/verel@v0.38.0` | failing a build on a FAIL verdict |
| **pre-commit** | `.pre-commit-hooks.yaml` | gating commits |

### CLI reference

```bash
verel doctor                              # environment + key check
verel version
verel loop <artifact> [--backend local] [--max-iter 5]    # ultracode visual loop (needs sight + LLM)
verel fleet "<goal>" --artifacts a.html b.html            # LLM manager fan-out
verel heal --repo . [--max-rounds 3]                      # self-healing CI (needs LLM)
verel ci <args…>                                          # delegates to verel-ci
```

```bash
verel-ci check    --repo .   [--no-lint]   # run the inner-loop stage; print the verdict
verel-ci precommit --repo .                # pre-commit stage; non-zero exit aborts the commit
verel-ci install  --repo .                 # install the native git pre-commit hook
```

### GitHub Action & pre-commit

```yaml
# .github/workflows/verify.yml
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v0.38.0
        with:
          repo: .
          install: "-e .[dev]"      # your project deps so its tests import
```

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/amitpatole/verel
  rev: v0.38.0
  hooks: [{ id: verel-precommit }]
```

---

## The verdict bus (`verel.verdict`)

The contract every sense speaks. A grader emits a `Report` of `Issue`s; `gate()` reduces a set of
reports to one `pass` / `warn` / `fail`.

```python
from verel.verdict import Issue, IssueKind, Report, Severity, GraderKind, Verdict, gate, assign

report = assign(Report(                       # assign() stamps stable fingerprints
    verdict=Verdict.FAIL,
    summary="2 type errors",
    grader=GraderKind.TYPECHECK,
    issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR,
                  source=GraderKind.TYPECHECK, message="Incompatible return type",
                  locator="app.py:42")],
))

result = gate([report], required={GraderKind.TYPECHECK})
print(result.verdict)            # Verdict.FAIL
```

Load-bearing rules `gate()` enforces:

- **Advisory ceiling** — per-issue trust keys off `Issue.source`. Precise sources
  (`TEST`/`LINT`/`TYPECHECK`/`DOM`/`CV`/`OCR`/`SECURITY`/`PERF`) gate at full severity; advisory
  ones (`VISION`/`LLM_JUDGE`) are clamped to at most `warn`.
- **Attestation** — a *required* grader must carry a signed `run_receipt` proving it ran the
  frozen suite over the changed files. A hollow `PASS, issues=[]` with no receipt **fails**.
- **Stuck vs. progress** — `progressed(curr, prev)` is strict shrinkage of the gating-failure set;
  pure churn or growth is not progress.

---

## Agent-run CI/CD (`verel.ci`)

Tests, lint, and types as first-class graders, across **Python · JS/TS · Go**, plus **perf** and
**security**. Stages compose graders and gate them with attestation + failure-memory.

```python
from verel.ci import inner_loop_stage, premerge_stage, run_stage

res = run_stage(inner_loop_stage(".", language="python", with_lint=True, with_types=True))
print(res.verdict, [r.grader.value for r in res.reports])
```

Pick a language; add precise senses:

```python
from verel.ci import premerge_stage, perf_spec, run_stage

stage = premerge_stage(
    ".", language="go",            # python | js | go
    security=True,                 # SAST (bandit) / dependency audit (npm)
    perf=perf_spec(".", ["./bench"], budgets={"p95_ms": 150}),  # regression past budget gates
)
res = run_stage(stage)
```

Each `GraderSpec` carries its own parser, so `pytest`, `go test -json`, and a TAP runner — all
`GraderKind.TEST` — coexist on one bus. Language toolchains live in `verel.ci.LANGS`; the graders
are `pytest_spec`/`ruff_spec`/`mypy_spec`, `jstest_spec`/`eslint_spec`/`tsc_spec`,
`gotest_spec`/`govet_spec`, plus `bandit_spec`/`npm_audit_spec`/`perf_spec`.

### Self-healing

```python
from verel.ci import inner_loop_stage, self_heal

result = self_heal(".", inner_loop_stage(".", with_lint=False))   # needs an LLM key
print(result.healed, result.terminated_on)
```

On a failure the **ci-medic** classifies each issue (retry / regen-lockfile / quarantine-flaky /
fix-branch) and, for genuine regressions, invokes the code-fixer — re-gating each round until the
graders pass or it escalates.

### Verdict-driven rollback

The agent *proposes*; a deterministic engine *authorizes* — and only on **precise** gating evidence
(never an advisory opinion), performing a safe `git revert` (never a history rewrite).

```python
from verel.ci import RollbackExecutor, RollbackProposal
outcome = RollbackExecutor().maybe_rollback(repo, proposal, reports)
```

---

## The brain — memory that compounds (`verel.memory`)

A trust layer over a swappable backend (`LocalMemory`, zero-dep sqlite; or `mem0`). Each record
carries **two orthogonal quantities** — `epistemic_confidence` (belief; moved only by
corroborate/contradict) and `retrieval_strength` (reachability; decays, resets on recall).

```python
from verel.memory import LocalMemory, MemoryRecord, MemoryKind
from verel.memory.view import make_key

mem = LocalMemory()                                   # or LocalMemory(embedder=OpenAIEmbedder())
mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="auth", predicate="uses",
                       text="sessions are JWT, 15-min expiry", scope="repo:app",
                       subj_pred_key=make_key("auth", "uses", "repo:app")))
hits = mem.recall("how does login work", scope="repo:app", k=3)
```

Trust is **earned, never asserted** — a candidate reaches `verified` only by passing a held-out,
agent-inaccessible eval (with a leakage canary):

```python
from verel.memory import PromotionGate, HeldOutCorpus, EvalCase
corpus = HeldOutCorpus([
    EvalCase(text="a card overflows the viewport on a 320px screen",
             covers_kind="overflow", label="prevent"),   # "prevent" | "allow"
])
gate = PromotionGate(mem, corpus)        # ratifies candidates → verified via the bus
```

### Consolidation: episodes → rules → schemas

```python
from verel.memory import consolidate_failures, induce_hierarchy, consolidate_across_scopes

# recurring FAILUREs in a scope → candidate, structured DesignRules (condition → action)
rules = consolidate_failures(mem, scope="repo:app", min_cluster=2)

# rules → order-2 principles → order-3 meta-principles, until the corpus stops supporting more
levels = induce_hierarchy(mem, scope="repo:app", min_size=2)

# a pattern recurring across several repos → one `global` rule (records detail['spans'])
glob = consolidate_across_scopes(mem, ["repo:a", "repo:b"], min_scopes=2)
```

### Contradiction-driven revision

Consolidation can be **wrong**. A new failure in a rule's domain that the rule failed to prevent is
a counterexample: the rule is weakened, and once enough accumulate it's **split** into a narrowed
rule + an exception — and the split **propagates up** the schema hierarchy so principles above stop
over-claiming.

```python
from verel.memory import revise_with_counterexample, contradicts

if contradicts(rule, new_failure):
    rev = revise_with_counterexample(mem, rule, new_failure)   # needs an LLM for the split
    print(rev.action)            # "weakened" | "split" | "rejected"
    print(rev.propagated)        # schemas above the rule that were re-derived
```

Everything starts `candidate` / `inferred`; height, breadth, and survival never confer trust.

### mem0 backend

```python
from verel.memory import make_ollama_mem0      # needs verel[mem0]
mem = make_ollama_mem0()                        # same MemoryView Protocol; recall is semantic
```

---

## Tool-smith — agents build their own tools (`verel.toolsmith`)

`detect → scaffold → test → register → reuse`. A tool is admitted only on a passing attested eval;
reuse **re-verifies** against the new spec's cases (a close match isn't trusted blindly).

```python
from verel.memory import LocalMemory
from verel.toolsmith import ToolRegistry, ToolSmith, ToolSpec, ToolCase, SideEffect

smith = ToolSmith(ToolRegistry(LocalMemory()), isolation="container")   # needs an LLM key
res = smith.build(ToolSpec(
    name="slugify", capability="convert a title to a url slug",
    side_effect=SideEffect.READ_ONLY,
    cases=[ToolCase(args=["Hello World"], expected="hello-world")],
))
print(res.trust, res.registered)
```

### Isolation tiers

Untrusted, agent-authored code runs in a separate trust domain. From weakest to strongest:

| `isolation=` | What it is |
|---|---|
| `"subprocess"` | fresh interpreter + rlimits + wall-clock timeout (dependency-free) |
| `"container"` | `bwrap` namespace sandbox — no network, read-only fs, ephemeral `/tmp`, cleared env |
| `"container"` + `verel[container]` | …plus a **seccomp-bpf** filter |

Three seccomp profiles (`run_container(..., seccomp_profile=…)`):

- `denylist` (default) — EPERM on dangerous syscalls; safe for arbitrary tools.
- `allowlist` — default-deny; only pure-compute syscalls (no network/subprocess/threads).
- `capability` — the tightest: only the syscalls a tool exercised while passing its eval (learn
  with `learn_syscall_profile`, then enforce via `tool.syscall_policy`).

---

## The fleet — agents managing agents (`verel.fleet`)

A single-writer scheduler over a Task DAG, every node gated by the bus.

```python
import asyncio
from verel.fleet import Scheduler, Task, WorkerResult
from verel.verdict import Verdict

async def worker(task):                       # your agent; returns a graded result
    ...
    return WorkerResult(verdict=Verdict.PASS)

tasks = [Task(id="a"), Task(id="b", deps=["a"])]
state = asyncio.run(Scheduler(worker, concurrency=4).run(tasks))
```

Barriers (`all` / `k_of_n` / `optional`), retry → quarantine, a hard budget lease, and WAL-based
crash resume are all on `Task` / `Scheduler`.

### Concurrent managers (fencing)

More than one scheduler can share a task store safely via **fencing leases** — a stale leader's
writes are rejected:

```python
from verel.fleet import Scheduler, InMemoryLeaseStore   # or SqliteLeaseStore for cross-process
store = InMemoryLeaseStore()
s1 = Scheduler(worker, leases=store, owner="m1")
s2 = Scheduler(worker, leases=store, owner="m2")          # each task runs exactly once
```

Across **machines**, put the lease authority behind the HTTP control plane:

```python
from verel.fleet import ControlPlaneServer, RemoteLeaseStore
srv = ControlPlaneServer("/var/lib/verel/leases.db", auth_token="…").start()
sched = Scheduler(worker, leases=RemoteLeaseStore(srv.url, auth_token="…"), owner="host-1")
```

### Multi-repo + atomic sagas

```python
from verel.fleet import plan_multi_repo, CrossDep, run_saga, SagaStep, git_revert_head

dag = plan_multi_repo({"api": api_tasks, "client": client_tasks},
                      [CrossDep(to_repo="client", dependent="ship", from_repo="api", needs="build")])

# all-or-nothing across repos: a failure compensates the repos that already landed, in reverse
res = run_saga([SagaStep("api",    forward_api,    lambda _r: git_revert_head("/repos/api")),
                SagaStep("client", forward_client, lambda _r: git_revert_head("/repos/client"))])
```

A **git pre-receive fencing sink** (`write_pre_receive_hook`) extends the fence to pushes: a push
carrying a stale token is refused at the remote.

---

## Eyes / senses (`verel.senses`) — needs `verel[sight]`

AgentVision as a grounded perception sense on the same bus.

```python
from verel.senses import perceive, watch
percept = perceive("dist/index.html")           # DOM / contrast / OCR, + intent conformance
clip = watch("https://app.local/player")         # temporal: playback / loading / liveness
```

A precise visual failure (overflow, clipped, missing element) gates; the advisory vision-LLM
opinion is clamped to `warn`.

---

## Skill registry (`verel.registry`)

Content-addressed, signed skill artifacts — and the rule that keeps the flywheel honest: **trust
does not travel.** A fetched skill enters as a `candidate` and only becomes `verified` by passing
the importer's OWN held-out eval.

```python
from verel.registry import export_skill, import_skill, PublicRegistry

art = export_skill(verified_tool, origin="tenant:A")
PublicRegistry("/srv/skills").publish(art)        # verifies the signature; refuses a tamper
res = import_skill(art, into=my_registry, target_cases=my_cases)
print(res.reverified)                             # True only if it passed MY eval
```

Host it over HTTP for cross-machine sharing:

```python
from verel.registry import RegistryServer, RemoteRegistry
srv = RegistryServer("/srv/skills", auth_token="…").start()
remote = RemoteRegistry(srv.url, auth_token="…")
import_skill(remote.get(content_hash), into=my_registry, target_cases=my_cases)
```

Whether a public registry is even a moat is *measured*, not assumed — `measure_transfer` (the H2
experiment) re-verifies skills across tenants. See [H2 results](H2_RESULTS.md).

---

## Cookbook

Runnable, mostly offline — see the [`examples/`](https://github.com/amitpatole/verel/tree/main/examples) directory:

| Want to… | Run |
|---|---|
| gate a repo on tests+lint+types | `verel-ci check --repo .` |
| self-heal failing tests | `python examples/demo_selfheal.py` |
| grade Python/JS/Go + perf + security on one bus | `python examples/demo_polyglot_ci.py` |
| consolidate failures → rules → schema → revise | `python examples/demo_consolidation.py` |
| sandbox a tool to only the syscalls it earned | `python examples/demo_capability_jail.py` |
| run concurrent managers + a multi-repo saga | `python examples/demo_distributed_fleet.py` |
| publish a skill and have another tenant re-verify | `python examples/demo_hosted_registry.py` |
| measure cross-tenant skill transfer (live) | `python examples/run_h2.py` |

See also the [Architecture & roadmap](ARCHITECTURE.md) for how the organs fit together.
