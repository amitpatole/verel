"""One hook into any agent framework — give the agent a tool that gates its own work (Reach R3).

Verel grades artifacts, so the integration is identical everywhere: a `gate()` callable + a
function-calling schema. This shows the universal pieces; the docs give the 1-line wiring for OpenAI
/ Anthropic / Claude Agent SDK / LangGraph / CrewAI / AutoGen.

Run:  python examples/demo_sdk_shims.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from verel.integrations.sdk import anthropic_tools, gate, openai_tools, run_tool_call

# The function-calling schema you hand your agent (OpenAI shape; anthropic_tools() for Claude):
print("OpenAI tool schema:")
print(json.dumps(openai_tools()[0]["function"], indent=2)[:280], "...\n")
print("Anthropic tool name:", anthropic_tools()[0]["name"], "\n")

with tempfile.TemporaryDirectory() as d:
    repo = Path(d)
    (repo / "m.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_m.py").write_text("from m import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")

    # 1) the universal callable — any framework that takes a Python function as a tool uses THIS:
    print("gate() callable          →", {k: gate(str(repo), lint=False)[k] for k in ("verdict",)})

    # 2) the model emits a tool call (name + JSON args); your loop runs it via run_tool_call:
    result = run_tool_call("verel_gate", {"repo": str(repo), "lint": False})
    print("run_tool_call('verel_gate') →", {"verdict": result["verdict"]})

print("\nResult: one tool, every framework — the agent calls verel_gate before 'done' and reads the "
      "verdict. Treat work complete only on verdict == 'pass'.")
