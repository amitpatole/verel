# Try it yourself — make a bug stay fixed

A complete, **copy-paste** walkthrough on a repo you build from scratch in 3 minutes. By the end
you'll have seen Verel do the three things it exists to do, on your own machine:

1. **Catch a real bug** — turn a failing test into a grounded `FAIL` verdict (not an opinion).
2. **Confirm the fix** — the same gate flips to `PASS` only when the grader actually passes.
3. **Remember it** — the fixed bug is recorded so a silent reintroduction is **blocked from memory
   alone**, no re-run needed.

Steps 1–3 need **no API key** — they're deterministic, so the output below is exactly what you'll
see. (The optional [finale](#optional-let-an-agent-fix-it-for-you) lets an LLM do the fixing.)

Every output block here is **real captured output** from running these exact commands — nothing is
mocked.

---

## 0. Install (30s)

```bash
pip install "verel[dev]"      # core + the pytest / ruff / mypy graders
verel doctor                  # sanity-check your environment
```

`verel doctor` ends with the memory backend it will use:

```text
verel 0.41.0
  ...
  -> memory backend: local  (available: local, remote)
```

## 1. A repo with a real bug (1 min)

A tiny tax helper with a genuine defect — it forgets to add the tax — and a test that catches it:

```bash
mkdir taxes-demo && cd taxes-demo
```

```python
# taxes.py
def subtotal(prices):
    return sum(prices)

def total_with_tax(prices, rate):
    # BUG: forgets to add the tax — returns the pre-tax subtotal
    return subtotal(prices)
```

```python
# test_taxes.py
from taxes import total_with_tax

def test_applies_tax():
    # $100 of goods at 10% tax must be $110
    assert total_with_tax([60, 40], 0.10) == 110.0
```

Now gate the repo — unify tests + lint + types into one verdict:

```bash
verel-ci check --repo .
```

```text
[inner_loop:python] verdict=fail
  - test: 1 issue(s)
      test:error test_taxes.py::test_applies_tax assert 100 == 110.0
```

The process exits **non-zero** (`echo $?` → `1`), so this is a hard CI gate, and the failure is
**grounded** — it points at the exact test and the exact assertion that failed. No agent gets to
call this "done."

## 2. Fix it — the gate flips to PASS (30s)

Apply the tax:

```python
# taxes.py
def subtotal(prices):
    return sum(prices)

def total_with_tax(prices, rate):
    return round(subtotal(prices) * (1 + rate), 2)
```

```bash
verel-ci check --repo .
```

```text
[inner_loop:python] verdict=pass
```

Exit `0`. The verdict flipped to `pass` **because the real grader passed** — not because anyone
claimed it did.

## 3. Make the fix stick — remember the bug (1 min)

This is what makes Verel a *brain* and not just a linter: a fixed failure is remembered, so if the
same bug sneaks back in a future change it's caught **from memory alone**, with no test re-run.

```python
# remember_the_bug.py
import pathlib
from verel.ci import inner_loop_stage, run_stage
from verel.memory import FailureLedger, LocalMemory

mem = LocalMemory("brain.db")          # a real on-disk brain (swap for an external DB — see below)
ledger = FailureLedger(mem, scope="repo:taxes")

# Re-break the code to capture a REAL failing verdict from the grader:
good = pathlib.Path("taxes.py").read_text()
pathlib.Path("taxes.py").write_text(good.replace("* (1 + rate), 2)", "), 2)  # tax dropped again"))
fail = run_stage(inner_loop_stage(".", with_lint=False, with_types=False))
print("gate verdict:", fail.verdict.value)

fps = []
for r in fail.reports:
    fps += ledger.record(r)            # remember every grounded failure
print("recorded fingerprints:", len(fps))

ledger.mark_fixed(fps)                 # ...we fix it
pathlib.Path("taxes.py").write_text(good)
print("marked fixed:", len(fps))

# ...later the same bug sneaks back in a new change. Caught from MEMORY alone — no re-run:
regs = [g for r in fail.reports for g in ledger.check_regressions(r)]
print("regression blocked from memory:", bool(regs))
```

```bash
python remember_the_bug.py
```

```text
gate verdict: fail
recorded fingerprints: 1
marked fixed: 1
regression blocked from memory: True
```

`regression blocked from memory: True` is the payoff — Verel recognized the returning bug from its
fingerprint without re-running the suite. **A fix, once verified, compounds.**

## Point the brain at an external store (out of the box)

That `brain.db` is the zero-dependency default. The brain is **pluggable** — select a backend by
name with one env var, no code change:

```bash
export VEREL_MEMORY_BACKEND=local          # the default (SQLite)
export VEREL_MEMORY_STORE=team-brain.db    # or any path
verel doctor                               # confirms: -> memory backend: local (available: local, remote)
```

```python
from verel.memory import load_backend, known_backends
print(known_backends())                    # ['local', 'remote']
brain = load_backend("local")              # resolved by name through the backend registry
```

`remote` points a whole fleet at one shared, authenticated brain (`VEREL_BRAIN_URL`). External
databases (Postgres/pgvector, LanceDB, Redis) ship as `pip install verel[<db>]` extras that register
under the same selector — see [Configuration](configuration.md#memory-backend). The trust layer
(corroborate / supersede / recall / the regression guard you just used) is **identical** whichever
backend is selected.

## Optional: let an agent fix it for you

Steps 1–3 had *you* write the fix. With an LLM key, an agent does it — it reads only the grader's
findings (never the test), patches the **source**, and loops until the graders themselves go green:

```bash
# default LLM is Ollama Cloud (~/.config/ollama/key); set VEREL_LLM_PROVIDER=openai to switch
verel heal --repo .
```

For a self-contained version that builds its own broken repo, run
[`examples/demo_selfheal.py`](https://github.com/amitpatole/verel/tree/main/examples/demo_selfheal.py):

```text
  round 1: verdict=fail  medic=['fix_branch']  patched=['mathx.py', 'strx.py']
  round 2: verdict=pass  medic=[]  patched=[]
healed=True  terminated_on=passed
```

`terminated_on=passed` means the loop stopped because the **graders** went green — not because the
agent said so.

---

## What you just proved

| Step | Capability | What decided "done" |
|---|---|---|
| 1 | The gate catches a real bug, grounded at `file::test` | the `pytest` grader, not a claim |
| 2 | The gate flips to PASS only on a real pass | the grader's verdict |
| 3 | A fixed bug is remembered; a reintroduction is blocked from memory | the failure ledger |
| ↪ | The brain is pluggable (local → remote → external DB) | one env var, same contract |

Next: the [5-minute tutorial](tutorial.md) (hollow-pass rejection, polyglot CI, attested receipts),
the [real-world scenarios](examples.md) with captured output, or the [use cases](use-cases.md) by
persona.
