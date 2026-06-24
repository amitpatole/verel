"""Over-engineering smell — "random abstractions for problems nobody had" → a grounded signal (D).

Deterministic AST analysis (no code execution, no API key): an over-complex function gates; a public
abstraction referenced nowhere is flagged as speculative. The future home is the `olfel` organ.

Run:  python examples/demo_smell_grader.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.smell import grade_smell


def show(label: str, files: dict[str, str], targets: list[str], budget: int = 8) -> None:
    with tempfile.TemporaryDirectory() as d:
        for name, src in files.items():
            (Path(d) / name).write_text(src)
        rep = grade_smell(d, targets, complexity_budget=budget)
        print(f"── {label} ──  verdict={rep.verdict.value}")
        for i in rep.issues:
            print(f"     [{i.severity.value}] {i.message}")


# 1) a tangled, over-complex function → gates
tangled = "def route(x):\n    r = 0\n" + "".join(
    f"    if x == {i}:\n        r = {i}\n" for i in range(12)) + "    return r\n"
show("an over-complex function", {"m.py": tangled}, ["m.py"])

# 2) a speculative abstraction nobody uses → advisory
show("a speculative abstraction", {
    "new.py": "class AbstractWidgetFactoryProvider:\n    def build(self):\n        return None\n",
    "app.py": "def run():\n    return 42\n",
}, ["new.py"])

# 3) clean, simple, used code → passes
show("simple, used code", {
    "lib.py": "def add(a, b):\n    return a + b\n",
    "app.py": "from lib import add\n\ndef run():\n    return add(1, 2)\n",
}, ["lib.py"])

print("\nResult: over-engineering becomes a measurable signal — complexity over budget gates, a "
      "speculative abstraction is surfaced — not a subjective review comment.")
