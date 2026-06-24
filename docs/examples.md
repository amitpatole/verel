# Real-world scenarios

Six situations a team actually hits — and what Verel does about them. Every block below is **real
captured output** from a runnable script in [`examples/`](https://github.com/amitpatole/verel/tree/main/examples);
nothing here is mocked up. Run any of them yourself:

```bash
pip install verel
python examples/demo_selfheal.py
```

The throughline: **an agent never decides "done" — a grader does.** Each scenario shows that rule
holding under a different kind of pressure.

---

## 1. Your CI went red — and fixed itself

**The situation.** A push breaks the test suite. Normally someone gets paged, reads the failure,
patches the code, and re-runs. Verel closes that loop: the real `pytest` grader fails, an agent
patches the **source** (never the tests), and the stage re-gates until the graders themselves go
green. The agent proposes; the verdict bus disposes.

```python
from verel.ci import inner_loop_stage, self_heal
result = self_heal(".", inner_loop_stage(".", with_lint=False))
print(result.healed, result.terminated_on)
```

```text
── Self-healing CI (real pytest grader + Ollama code-fixer) ──
  round 1: verdict=fail  medic=['fix_branch']  patched=['mathx.py', 'strx.py']
  round 2: verdict=pass  medic=[]  patched=[]

healed=True  terminated_on=passed
Result: PASS — agent healed failing CI to green; graders decided done
```

The fix landed in the source under test; the tests were never touched. `terminated_on=passed`
means the loop stopped because the *graders* went green, not because the agent claimed success.

> `python examples/demo_selfheal.py` — uses a live LLM code-fixer (Ollama by default; set
> `VEREL_LLM_PROVIDER=openai` to switch). The grader is real `pytest`.

---

## 2. A bad merge slipped through — caught at canary, reverted on precise evidence

**The situation.** A change passes review and merges, but it's wrong. Verel runs the merged code
through a **canary** grader; on a *precise* gating failure it performs a deterministic `git revert`
back to the last good HEAD — and, crucially, it **refuses** to do anything destructive when the only
evidence is advisory (a vision or LLM hunch).

```python
from verel.ci import canary_stage, rollback_engine
# canary fails on HEAD → engine reverts to HEAD~1; then an advisory-only failure is offered
```

```text
── Canary on the merged code (HEAD=c2852b1, VALUE=999) ──
  canary verdict=fail  rolled_back=True
  policy: authorized: 1 precise gating failure(s) justify rollback to HEAD~1
  reverted c2852b1 → new HEAD 59ce62e
  app.py now: VALUE = 1

── An ADVISORY-only failure must NOT trigger a destructive revert ──
  executed=False  reason=denied: only ADVISORY graders support this rollback — destructive action refused
  HEAD unchanged: True

Result: PASS — bad merge auto-reverted on precise evidence; advisory-only refused
```

The rollback engine acts on hard, reproducible evidence and **never** on advisory signals — so an
agent's opinion can inform a human but can't trigger a `git revert` on its own.

> `python examples/demo_canary_rollback.py`

---

## 3. One fix, the whole fleet — concurrent agents that can't collide or half-apply

**The situation.** You point a fleet of agents at a backlog spanning several repos. Two risks:
two managers grabbing the same task (double work, races), and a multi-repo change landing in repo A
but failing in repo B (a half-applied mess). Verel fences managers with **leases** (a stale leader's
writes are rejected — even at the git remote) and commits cross-repo work as an **atomic saga** that
compensates everything already landed if any repo fails.

```text
8 tasks across 2 concurrent managers — ran once each: True
  work split by lease: {'m1': 5, 'm2': 3}

stale leader A fenced off: stale token for 'deploy': 1 < current 2 — write …
  current leader B's write accepted: outcome=passed

cross-repo DAG: ['api::migrate', 'api::build', 'client::ship']
  client shipped only after api built: True

cross-repo saga (client fails):
  committed=[] compensated=['commit:api'] failed=['commit:client']
  repos left landed: [] (empty → atomic: nothing half-applied)
```

Every task ran exactly once; a deposed manager's writes were refused; and when one repo failed, the
saga rolled the others back so **nothing was left half-applied**.

> `python examples/demo_distributed_fleet.py`

---

## 4. A polyglot monorepo — one gate for Python, JS, Go, perf, and security

**The situation.** A real repo isn't one language. You want *one* pass/fail signal across
`pytest`, `jest`, `go test`, lint, type-checkers, a perf budget, and a security scanner — not eight
dashboards. Verel maps every sense onto **one verdict schema**, so a single gate (and a single
stuck/progress signal) covers them all.

```text
Go inner-loop: FAIL
  test      [-] 1 issue(s) — TestLogin failed

JS pre-merge: FAIL
  test      [-] 1 issue(s) — submit posts the form
  typecheck [-] 0 issue(s)

Python pre-merge + perf + security: FAIL
  security  [-] 1 issue(s) — B602 subprocess with shell=True
  perf      [-] 1 issue(s) — p95_ms 240 exceeds budget 150

All senses share one schema, one gate, one stuck/progress signal.
```

A failing Go test, a broken JS form, a shell-injection finding, and a blown latency budget all speak
the *same* verdict language — so "is this mergeable?" is one question with one answer.

> `python examples/demo_polyglot_ci.py`

---

## 5. An agent built its own tool — and got jailed to exactly what it earned

**The situation.** An agent needs a capability you don't have a tool for. Verel lets it
detect → scaffold → test → register the tool — but only admits it on a **passing held-out eval**, and
then runs it under a **capability jail**: the tool may use only the syscalls it actually exercised
*while passing that eval* (learned via `strace`). Anything it never earned is refused at the kernel —
even syscalls a normal allow-list would have permitted.

```text
learned 28 syscalls → enforced 71 (allow-list jail would permit 83)
  denied here but allowed by the allow-list jail: ['clock_nanosleep', 'epoll_wait', 'nanosleep', 'pipe2', 'select', 'sysinfo', ...]

verified tool under its capability jail: 5
pipe() under the ALLOW-LIST jail: 5
pipe() under the CAPABILITY jail: REFUSED — [Errno 1] Operation not permitted
socket() under the CAPABILITY jail: REFUSED — [Errno 1] Operation not permitted
subprocess under the CAPABILITY jail: REFUSED — [Errno 1] Operation not permitted
```

The tool that only ever did arithmetic can't open a socket or spawn a subprocess — not by policy
review, but because it never earned those syscalls on the eval that admitted it.

> `python examples/demo_capability_jail.py` (Linux + `bwrap` for the real container; the jail
> profile is learned from the tool's own passing run)

---

## 6. A shared team brain — compounding, un-poisonable, and crash-tolerant

**The situation.** A fleet of agents keeps relearning the same lessons, and you don't want one
noisy (or malicious) agent poisoning everyone's memory — or a single memory node being a SPOF.
Verel's shared brain lets agents recall *down* a scope lattice (`self → team → org → global`) and
**graduate** verified beliefs *up*; a peer's claim **re-verifies before it's trusted** (trust never
travels), authors earn reputation, and the store runs as a **leader-fenced HA cluster** that
survives node loss.

```text
── Cross-agent trust: trust does not travel; authors earn reputation ──
  agent-A's belief (my check passes): VERIFIED locally
  agent-B's belief (my check fails):  stayed CANDIDATE — trust did not travel
  reputations → agent-A prior=0.92 (10, 10), agent-B prior=0.33 (3, 10)

── Replicated HA: leader-fenced, fault-tolerant, no split-brain ──
  leader A wrote despite a dead follower — status ReplicationStatus(acks=2, lagging=1, quorum=1)
  failover: B is now leader (token 2); A is fenced out.
  deposed leader A refused: NotLeaderError — no split-brain.
  quorum read: with the leader DOWN, a read still returns 'restart the worker pool'
               (freshest by version) from a surviving replica — strong reads couldn't.
```

A bad actor's belief stays a candidate until *your* check agrees; a crashed leader is fenced out with
no split-brain; and a point read survives the leader being down by reading the freshest copy from a
surviving replica.

> `python examples/demo_shared_brain.py`

---

## 7. A green test suite that proves nothing — caught

**The situation.** An agent's PR ships passing tests — but do they actually *test* the change? A
suite can call the code and assert nothing, and "all green" hides it. Verel's **test-effectiveness**
grader injects small faults into the changed code and re-runs the suite: a fault no test catches (a
*surviving mutant*) is a hard, deterministic FAIL — not an opinion. Strengthen the assertion and the
same gate goes green.

```text
── Green suite, but it asserts nothing ── baseline_pass=True  mutants=3  survivors=3  →  FAIL
     surviving mutant: return→None at billing.py:2 — no test catches it
     surviving mutant: *→/ at billing.py:2 — no test catches it
     surviving mutant: +→- at billing.py:2 — no test catches it
── Same code, now a real assertion ── baseline_pass=True  mutants=3  survivors=0  →  PASS
```

`tests exist` is not `tests test`. The grader gates (`GraderKind.MUTATION` is deterministic
evidence, not advisory), so an agent can't pad a PR with toothless tests to look done.

> `python examples/demo_mutation.py` (no API key — built-in AST mutator + the repo's own pytest)

---

## Run them all

```bash
python examples/demo_selfheal.py          # 1 · red CI heals itself (live LLM + real pytest)
python examples/demo_canary_rollback.py   # 2 · bad merge auto-reverted on precise evidence
python examples/demo_distributed_fleet.py # 3 · fenced concurrent managers + atomic cross-repo saga
python examples/demo_polyglot_ci.py       # 4 · Python/JS/Go + perf + security on one gate
python examples/demo_capability_jail.py   # 5 · a tool jailed to the syscalls it earned
python examples/demo_shared_brain.py      # 6 · shared brain — un-poisonable, HA, crash-tolerant
python examples/demo_mutation.py          # 7 · a green-but-toothless suite FAILS the gate
python examples/demo_rest_gate.py         # 8 · gate over HTTP + an HMAC-verified PR webhook
```

More feature-level demos (consolidation into structured rules, the tool-smith lifecycle, semantic
recall, **pluggable memory backends** — `demo_backend_registry.py`, the H2 cross-tenant transfer
experiment) live in [`examples/`](https://github.com/amitpatole/verel/tree/main/examples).

New here? The fastest hands-on path is **[Try it yourself](try-it.md)** — a from-scratch,
copy-paste walkthrough (no API key) where you catch a real bug, fix it, and watch Verel remember it.
