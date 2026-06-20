# 5-minute tutorial

By the end of this you'll have watched Verel do the one thing it exists to do: **turn "done" from
an opinion into a verdict** — gate a real repo, let an agent heal failing tests, and watch a fixed
bug get *remembered* so it can't sneak back.

Everything in steps 1–3 runs with **no API key**. Step 4 (the agent fixing code) needs an LLM.

```bash
pip install "verel[dev]"      # core + the pytest/ruff/mypy graders
verel doctor                  # sanity-check your environment
```

---

## 1. Make a verdict, not a guess (30s)

A failing check should *fail loudly* — but a check that didn't really run shouldn't be allowed to
say "pass" either. That's the whole game. Drop this in `demo.py`:

```python
from verel.verdict import Report, Issue, IssueKind, Severity, GraderKind, Verdict, gate, assign

# a type-checker found a real error
typed = assign(Report(
    verdict=Verdict.FAIL, summary="1 type error", grader=GraderKind.TYPECHECK,
    issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TYPECHECK,
                  message="Incompatible return type", locator="app.py:42")],
))

print(gate([typed], required={GraderKind.TYPECHECK}).verdict)   # Verdict.FAIL
```

```bash
python demo.py        # → Verdict.FAIL
```

Now try to sneak a **hollow pass** past it — a grader that claims success with no evidence:

```python
hollow = Report(verdict=Verdict.PASS, summary="all good", grader=GraderKind.TEST, issues=[])
print(gate([hollow], required={GraderKind.TEST}).verdict)       # Verdict.FAIL — no signed receipt
```

It still fails. A *required* grader must present a signed `run_receipt` proving it ran the real
suite over the changed files. "Present-but-empty" can't mint green. **That** is why a Verel verdict
is trustworthy.

---

## 2. Gate a real repo (1 min)

Point the bus at any Python project and unify tests + lint + types into one verdict:

```bash
verel-ci check --repo .
```

```python
from verel.ci import inner_loop_stage, run_stage

res = run_stage(inner_loop_stage(".", with_lint=True, with_types=True))
print(res.verdict)                                  # pass / warn / fail
for r in res.reports:
    print(" ", r.grader.value, "->", r.verdict.value)
```

Same contract, three languages — swap `language="js"` or `language="go"`, or add precise senses:

```python
from verel.ci import premerge_stage, perf_spec, run_stage
stage = premerge_stage(".", security=True,                       # SAST + dependency audit
                       perf=perf_spec(".", ["./bench"], {"p95_ms": 150}))  # gates on a budget
```

---

## 3. Memory that compounds (1 min)

Verel remembers fixed failures so they can't quietly come back — a regression guard that gates
from memory *alone*, no re-run needed.

```python
from verel.memory import FailureLedger, LocalMemory
from verel.verdict import Report, Issue, IssueKind, Severity, GraderKind, Verdict, assign

mem = LocalMemory()
ledger = FailureLedger(mem, scope="repo:app")

bug = assign(Report(verdict=Verdict.FAIL, summary="login 500s", grader=GraderKind.TEST,
                    issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR,
                                  source=GraderKind.TEST, message="KeyError: token", locator="auth.py:31")]))

ledger.record(bug)                                          # we hit this bug...
ledger.mark_fixed([i.fingerprint for i in bug.issues])     # ...and fixed it. Verel remembers.

# later, the same failure reappears in a new change:
hits = ledger.check_regressions(bug)
print("blocked as a regression:", bool(hits))   # True — caught from memory, no test re-run
```

Only **verified** knowledge compounds: a consolidated rule starts `inferred` and reaches
`verified` only by passing a held-out, agent-inaccessible eval. Trust is earned, never asserted.

---

## 4. Let an agent heal failing CI (2 min) — needs an LLM

This is the payoff. A repo ships with **failing tests and no hint of the fix**. Verel runs the real
pytest grader, the ci-medic classifies the failures, an agent patches the **source** (never the
tests), and the stage re-gates — round after round — until the *graders themselves* return green.

```bash
# default LLM is Ollama Cloud (~/.config/ollama/key); set VEREL_LLM_PROVIDER=openai to switch
python examples/demo_selfheal.py
```

```python
from verel.ci import inner_loop_stage, self_heal

stage = inner_loop_stage("/path/to/broken/repo", with_lint=False)
result = self_heal("/path/to/broken/repo", stage, max_rounds=4)

for r in result.rounds:
    print(f"round {r.n}: verdict={r.verdict}  medic={r.actions}  patched={r.changed}")
print("healed:", result.healed, "| terminated_on:", result.terminated_on)
```

The agent only ever sees the **grader's findings**, never the test code, and it can't self-declare
success — the verdict bus decides "done." If a patch doesn't actually clear the failures, Verel
detects `stuck` (no strict shrinkage of the gating-failure set) and **stops instead of thrashing**.

---

## Where to go next

- **[Developer guide](usage.md)** — every surface and organ, with runnable snippets.
- **[Architecture](ARCHITECTURE.md)** — how the six organs fit together.
- Run the rest of the [`examples/`](https://github.com/amitpatole/verel/tree/main/examples) — polyglot CI, the tool-smith's seccomp jail, the distributed fleet, the hosted skill registry.

That's the whole thesis in five minutes: **nothing is done until a grader says so, and only what's
verified gets to compound.**
