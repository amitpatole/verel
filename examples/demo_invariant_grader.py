"""Business-rule / invariant grader — "business rules get ignored" becomes a grounded FAIL (C).

You declare invariants (here inline; normally a `verel_invariants.yaml` in the repo). The LLM compiles
each into a property check, runs it, and gates on a violation. The LLM is stubbed so this runs with no
API key; the check really executes. Invariants are HUMAN-declared (not from a hostile ticket), so the
injection surface is smaller than the spec grader — and execution reuses the same OS-isolated runner.

Run:  python examples/demo_invariant_grader.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.invariants import grade_invariants

INVARIANT = "total_with_tax(prices, rate) is never less than sum(prices)"
_CHECK = ("from taxes import total_with_tax\n\ndef test_inv():\n"
          "    assert total_with_tax([10, 20], 0.1) >= sum([10, 20])\n")


def stub_chat(messages):
    return _CHECK  # the generated property check for the invariant


def grade(code: str, label: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "taxes.py").write_text(code)
        rep = grade_invariants(d, [INVARIANT], ["taxes.py"], chat=stub_chat, n=2, isolation="subprocess")
        print(f"── {label} ──  verdict={rep.verdict.value}")
        for i in rep.issues:
            print(f"     [{i.severity.value}] {i.message}")


grade("def total_with_tax(p, r):\n    return round(sum(p) * (1 + r), 2)\n", "rule upheld")
grade("def total_with_tax(p, r):\n    return sum(p) - 1  # discounts below subtotal\n", "rule violated")

print("\nResult: a declared business rule is enforced by EXECUTING a property check derived from it — "
      "a violation is a grounded FAIL, not a code-review opinion.")
