"""Test-effectiveness grader — a green suite that proves nothing FAILS the gate (Verified Review A).

A passing test suite is not evidence if it asserts nothing. Verel injects small faults into the
changed code and re-runs the suite: a fault no test catches (a "surviving mutant") is a hard,
deterministic FAIL — not an LLM hunch. Strengthen the test and the same gate goes green.

Run:  python examples/demo_mutation.py
Needs: nothing (no API key) — uses the built-in AST mutator + the repo's own pytest.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.mutation import run_mutation

CODE = "def total_with_tax(prices, rate):\n    return round(sum(prices) * (1 + rate), 2)\n"
WEAK = ("from billing import total_with_tax\n\n"
        "def test_runs():\n    total_with_tax([60, 40], 0.10)\n")  # calls it, asserts NOTHING
STRONG = ("from billing import total_with_tax\n\n"
          "def test_applies_tax():\n    assert total_with_tax([60, 40], 0.10) == 110.0\n")


def _gate(repo: Path, label: str) -> None:
    res = run_mutation(str(repo), ["billing.py"], cap_per_file=10)
    survivors = res.survivors
    verdict = "PASS" if (res.baseline_pass and not survivors) else "FAIL"
    print(f"── {label} ── baseline_pass={res.baseline_pass}  mutants={res.total}  "
          f"survivors={len(survivors)}  →  {verdict}")
    for s in survivors:
        print(f"     surviving mutant: {s['op']} at {s['file']}:{s['line']} — no test catches it")


with tempfile.TemporaryDirectory() as d:
    repo = Path(d)
    (repo / "billing.py").write_text(CODE)

    (repo / "test_billing.py").write_text(WEAK)
    _gate(repo, "Green suite, but it asserts nothing")

    (repo / "test_billing.py").write_text(STRONG)
    _gate(repo, "Same code, now a real assertion")

print("\nResult: the toothless suite FAILS the gate; the real assertion makes it PASS — "
      "'tests exist' is not 'tests test'.")
