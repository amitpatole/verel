"""Spec/intent conformance — "the ticket says A, the code does B" becomes a grounded verdict (B).

The LLM proposes checks from the TICKET; execution verifies them; a violated criterion GATES. Here
the LLM is stubbed (so the demo runs with no API key), but the generated checks REALLY execute
against the repo — that's the whole point: the verdict comes from running code, not an opinion. In
production, `chat=default_chat()` uses your configured LLM (Ollama/OpenAI).

Run:  python examples/demo_spec_grader.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.spec import grade_spec

TICKET = "Total must include tax: total_with_tax([60, 40], 0.10) should be 110.0."

# A stubbed LLM: extracts one behavioral criterion, then generates a real pytest check for it.
_CRITERIA = '[{"id":"c1","statement":"total_with_tax([60,40],0.10) == 110.0","kind":"behavioral"}]'
_CHECK = ("from taxes import total_with_tax\n\n"
          "def test_tax():\n    assert total_with_tax([60, 40], 0.10) == 110.0\n")


def stub_chat(messages):
    return _CRITERIA if "json array" in messages[0]["content"].lower() else _CHECK


def grade(code: str, label: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "taxes.py").write_text(code)
        # isolation="subprocess": trusted-local demo (our own repo + stub checks). On untrusted PRs
        # the default is "container" (bwrap, no-net, read-only) — and it fails closed without bwrap.
        rep = grade_spec(d, TICKET, ["taxes.py"], chat=stub_chat, n=2, isolation="subprocess")
        print(f"── {label} ──  verdict={rep.verdict.value}")
        for i in rep.issues:
            print(f"     [{i.severity.value}] {i.message}")


# 1) code that honors the ticket → the generated check passes → PASS
grade("def total_with_tax(p, r):\n    return round(sum(p) * (1 + r), 2)\n", "code matches the ticket")

# 2) code that ignores the requirement (forgets the tax) → the check fails → FAIL (gated)
grade("def total_with_tax(p, r):\n    return round(sum(p), 2)  # BUG: tax dropped\n",
      "ticket says A, code does B")

print("\nResult: intent conformance is decided by EXECUTING checks derived from the ticket — a "
      "violated acceptance criterion is a grounded FAIL, not an LLM hunch.")
