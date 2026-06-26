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
from verel.ci import postmerge_stage, canary_rollback, RollbackExecutor
res = canary_rollback(".", postmerge_stage("."))   # canary fails on HEAD → reverts to HEAD~1
print(res.verdict.value, res.rolled_back)
# a later advisory-only failure offered to RollbackExecutor().maybe_rollback(...) is refused
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

## 9. "The ticket said A, the PR did B" — caught before merge

**The situation.** An agent's PR passes its own tests but doesn't actually implement what the ticket
asked. Verel's **spec grader** extracts the acceptance criteria from the *ticket* (not the diff), has
the LLM compile each into pytest checks, **runs them**, and gates on a violation — the verdict comes
from executing code, not from an opinion.

```text
── code matches the ticket ──  verdict=pass
── ticket says A, code does B ──  verdict=fail
     [error] the code does not satisfy the ticket: total_with_tax([60,40],0.10) == 110.0
```

The model only *proposes* the checks; a majority vote over independent generated checks decides, so a
single wrong test can't false-fail a merge, and a criterion that can't be grounded stays advisory
(never a gate). Generated checks run under real OS isolation (bwrap no-net + read-only fs + seccomp +
rlimits) and fail closed without it — executing LLM-authored code from a possibly-hostile PR safely.

> `python examples/demo_spec_grader.py` (no API key — the LLM is stubbed; the checks really execute)

---

## 13. A dangerous IAM grant in a Terraform plan — caught before apply

**The situation.** An agent (or a human) writes Terraform that attaches a wildcard admin policy and
opens SSH to the world. It passes `terraform validate`, tests, lint, and types — IAM blast radius is
invisible to all of them, and only surfaces as an incident or a failed audit later. Verel's **IAM
change sensor** reads the `terraform show -json` plan, normalizes every IAM-affecting change, and runs
deterministic risk rules that gate **before** apply — no cloud credentials, nothing applied.

```text
=== IAM change sensor — grade a terraform plan before apply ===

broken plan: FAIL  (apply → irreversible; 1 destroy/replace (aws_db_instance.legacy), 2 IAM widening (aws_iam_policy.admin, aws_security_group_rule.ssh))
  [info    ] iac  DESTROY_OR_REPLACE     aws_db_instance.legacy
  [error   ] iam  WILDCARD_ACTION        aws_iam_policy.admin
  [error   ] iam  WILDCARD_RESOURCE      aws_iam_policy.admin
  [error   ] iam  OPEN_INGRESS           aws_security_group_rule.ssh

fixed plan: PASS  (apply → irreversible; 2 IAM widening (aws_iam_policy.admin, aws_security_group_rule.ssh))

→ 3 IAM risk(s) caught in the broken plan, each grounded on a plan address. No cloud credentials, no apply — the dangerous grant never reaches AWS.
```

Each finding is grounded on the plan address. Note the verdict and the gateway class are independent:
the *fixed* plan PASSes (no risk rule fires) yet its apply is still `irreversible` — any IAM grant
crosses a blast-radius line, so it needs human approval even when it's safe. Sensing covers all three
surfaces (IaC plans, Kubernetes RBAC, and direct IAM SDK/CLI calls); acting is gated by the
[terraform actuator](graders.md#iac-devops-grade-terraform-kubernetes-cloud-iam-before-apply)
applying *exactly* the approved plan file.

> `python examples/demo_iac.py` (no cloud credentials — pure offline sensor over a sample plan)

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
python examples/demo_spec_grader.py       # 9 · "ticket says A, code does B" → a grounded FAIL
python examples/demo_invariant_grader.py  # 10 · a declared business rule violated → a grounded FAIL
python examples/demo_smell_grader.py      # 11 · over-engineering → complexity gates, speculative flagged
python examples/demo_gateway.py           # 12 · gate the action boundary: write blocked, deploy dry-run
python examples/demo_iac.py               # 13 · a dangerous IAM grant in a terraform plan → grounded FAIL
```

## More feature-level demos

The scenarios above are the headline loops; these zoom in on a single organ or mechanism. Every one
is a runnable, real-output script in [`examples/`](https://github.com/amitpatole/verel/tree/main/examples):

- **[`demo_agent_loop.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_agent_loop.py)**
  — the headline loop: a broken page in, a real LLM agent authors the fix, Verel's own eyes perceive
  it, and the loop terminates only when Verel itself computes `pass`.
- **[`demo_overflow_loop.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_overflow_loop.py)**
  — the walking-skeleton: Verel fixes a real UI overflow and stops on a `pass` it computed itself.
- **[`demo_cicd.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_cicd.py)**
  — agent-run CI/CD with the **real** pytest grader (no LLM): fail → fix → re-gate to pass, plus the
  rollback policy refusing to act on advisory evidence.
- **[`demo_fleet_loop.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_fleet_loop.py)**
  — agents managing agents: a manager fans out one worker per page, run concurrently under a budget by
  the single-writer scheduler.
- **[`demo_fleet_worktrees.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_fleet_worktrees.py)**
  — the full picture: an LLM manager decomposes the goal and each worker runs in its **own isolated git
  worktree**, concurrently.
- **[`demo_toolsmith.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_toolsmith.py)**
  — the tool-smith lifecycle (scenario 5 up close): an agent scaffolds a tool, tests it against held-out
  cases, and registers it to procedural memory **only on a passing, attested eval**.
- **[`demo_memory_loop.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_memory_loop.py)**
  — the fleet stops repeating mistakes: a real fix is recorded, marked `fixed` on pass, and consolidated
  into a candidate semantic rule.
- **[`demo_promotion.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_promotion.py)**
  — only verified work compounds: a candidate rule earns `verified` through a held-out, attested,
  agent-inaccessible eval (with the leakage canary blocking a contaminated promotion).
- **[`demo_consolidation.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_consolidation.py)**
  — episodic failures cluster into structured `DesignRule`s, which in turn induce a 2nd-order schema —
  offline, no API key.
- **[`demo_semantic_recall.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_semantic_recall.py)**
  — the brain recalls by **meaning**: a query sharing no vocabulary with a stored rule still retrieves it.
- **[`demo_sdk_shims.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_sdk_shims.py)**
  — one `gate()` hook into any agent framework: the same callable + function-calling schema for OpenAI,
  Anthropic, the Claude Agent SDK, LangGraph, CrewAI, and AutoGen.
- **[`demo_h2_moat.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_h2_moat.py)**
  — the corpus-transfer experiment that decides the moat: do verified skills **re-verify across tenants**?
  Measured, not assumed.

Also see **[`demo_backend_registry.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_backend_registry.py)**
and **[`demo_hosted_registry.py`](https://github.com/amitpatole/verel/blob/main/examples/demo_hosted_registry.py)**
for the **pluggable memory backends** (local SQLite, a shared hosted brain, or an external DB).

New here? The fastest hands-on path is **[Try it yourself](try-it.md)** — a from-scratch,
copy-paste walkthrough (no API key) where you catch a real bug, fix it, and watch Verel remember it.
