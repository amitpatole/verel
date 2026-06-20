# Contributing to Verel

Thanks for considering a contribution! Verel is small, typed, and **dogfooded** — it gates its own
development through its own verdict bus, so the bar for "done" is the same for the project as it is
for its users: *nothing is done until a grader returns a verdict.*

## Quick start

```bash
git clone https://github.com/amitpatole/verel && cd verel
uv venv --python 3.11 && source .venv/bin/activate     # or: python -m venv .venv
uv pip install -e ".[dev]"                              # core + pytest/ruff/mypy graders
python -m pytest -q                                    # run the suite (offline; LLM tests skip)
```

Optional extras pull in more surfaces: `.[sight]` (AgentVision eyes), `.[container]` (seccomp tool
sandbox), `.[mem0]` (rented memory backend), `.[mcp]` (MCP server).

## The one rule: gate your change the way Verel gates everything

Before you open a PR, run the **same pre-merge verdict bus CI runs** — Verel over Verel:

```python
from verel.ci import premerge_stage, run_stage
r = run_stage(premerge_stage(".", covers=["src"]), diff_files={"src"})
assert r.verdict.value == "pass"     # this is exactly what CI asserts
```

or the individual graders:

```bash
ruff check src/ tests/        # lint (and ruff check --fix to autofix)
mypy src/verel                # types — src/ is fully typed and must stay clean
python -m pytest -q           # tests
```

A PR that doesn't pass these won't pass CI — the gate is not advisory. Tests live in `tests/`;
parsers and pure logic are tested **offline** (the LLM is injected as a stub), so most of the suite
runs with no API key. Anything that needs a model takes an injectable `chat` function — keep it
that way so contributors can run your tests without a key.

## How the project is laid out

The **[module guide](src/verel/README.md)** maps every module across the six organs (verdict,
senses, memory, toolsmith, fleet, ci, registry) with what to import from each. The
**[developer guide](docs/usage.md)** shows how the pieces are used. Read those before a non-trivial
change.

A few conventions worth knowing:

- **Match the surrounding code** — comment density, naming, and idiom. Modules are heavily
  commented with the *why*; keep that.
- **Trust is earned, never asserted.** Anything induced/imported enters as a `candidate`; it
  becomes `verified` only by passing a held-out, attested eval. Don't add a path that mints trust.
- **Precise vs. advisory.** A destructive action (rollback, revert) must never depend on advisory
  (vision/LLM) evidence. If you touch the gate or rollback, preserve that invariant.
- **Pure parsers.** Graders parse tool output with pure functions over `(stdout, stderr)`, tested
  with canned samples — no need to install the tool to test the parser.

## Pull requests

1. Branch off `main`; keep the change focused.
2. Add or update tests — new behaviour needs a test; a bug fix needs a regression test.
3. Update docs if you changed a surface (README organ table, `docs/usage.md`, the module guide).
4. Make sure ruff + mypy + pytest are all green (the gate above).
5. Open the PR with a clear description of *what* and *why*. CI runs the same gate and asserts
   `pass`.

By contributing you agree your work is licensed under the project's **MIT** license.

## Good first issues

New here? Look for the **[`good first issue`](https://github.com/amitpatole/verel/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)**
label — those are scoped, self-contained, and have a clear pattern to follow in the existing code
(e.g. adding a new language toolchain mirrors the JS/Go graders in `verel/ci/graders.py`). Comment
on the issue to claim it. Questions are welcome on the issue itself.
