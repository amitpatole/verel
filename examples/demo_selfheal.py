"""Self-healing CI — the flagship end-to-end loop (§7.4 v2).

A repo ships with failing tests and no hint of the fix. Verel runs the real pytest grader,
the ci-medic classifies the failures, the code-fixer agent (Ollama Cloud) patches the
SOURCE (never the tests), and the stage re-gates — round after round — until the graders
themselves return PASS. The agent proposes; the verdict bus decides done.

Run:  python examples/demo_selfheal.py     (needs ~/.config/ollama/key)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.agents.llm import have_key
from verel.ci import inner_loop_stage, self_heal

# Two real, independent bugs across two modules; the tests encode the spec.
MATH_SRC = "def fib(n):\n    # BUG: wrong base/recurrence\n    return n\n"
STR_SRC = "def is_palindrome(s):\n    # BUG: ignores case/spaces incorrectly\n    return s == s\n"
TESTS = """\
from mathx import fib
from strx import is_palindrome


def test_fib():
    assert [fib(i) for i in range(7)] == [0, 1, 1, 2, 3, 5, 8]


def test_palindrome():
    assert is_palindrome("A man a plan a canal Panama")
    assert not is_palindrome("hello")
"""


def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "mathx.py").write_text(MATH_SRC)
        (repo / "strx.py").write_text(STR_SRC)
        (repo / "test_spec.py").write_text(TESTS)

        stage = inner_loop_stage(str(repo), with_lint=False)
        print("── Self-healing CI (real pytest grader + Ollama code-fixer) ──")
        res = self_heal(str(repo), stage, max_rounds=4)

        for r in res.rounds:
            print(f"  round {r.n}: verdict={r.verdict}  medic={r.actions}  patched={r.changed}")
        print(f"\nhealed={res.healed}  terminated_on={res.terminated_on}")
        if res.healed:
            print("  final mathx.py:\n   ", (repo / "mathx.py").read_text().replace("\n", "\n    "))

        print("\nResult:", "PASS — agent healed failing CI to green; graders decided done"
              if res.healed else f"stopped on {res.terminated_on}")
        return 0 if res.healed else 1


if __name__ == "__main__":
    raise SystemExit(main())
