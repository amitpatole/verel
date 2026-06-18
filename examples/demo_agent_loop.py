"""Autonomous agent loop — the headline Phase-0 demo (design §11.1 item 5).

A broken page goes in. A real LLM coding agent authors the fix. Verel's own eyes
(AgentVision) perceive it, Verel's verdict bus gates it, and the loop terminates ONLY when
Verel itself computes `pass`. No hand-written fix — the agent does the work, the framework
decides done.

Run:  python examples/demo_agent_loop.py
Needs: pip install -e ".[sight]"  AND an LLM key. Default provider is Ollama Cloud
(~/.config/ollama/key), default model qwen3-coder:480b. Override with VEREL_LLM_PROVIDER /
VEREL_CODER_MODEL — see src/verel/agents/llm.py.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from verel.agents import make_fix_hook
from verel.agents.llm import have_key
from verel.loop import ultracode_loop
from verel.verdict import Verdict

# Two planted defects an agent must reason about: a horizontal overflow AND a real
# low-contrast caption. The agent is told only the grader findings — not the fix.
BROKEN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pricing card</title>
<style>
  body { margin: 0; font-family: system-ui, sans-serif; background: #ffffff; }
  .card { box-sizing: border-box; width: 1600px; padding: 24px; border: 1px solid #ddd; }
  .title { color: #111; font-size: 28px; }
  .caption { color: #d8d8d8; font-size: 14px; }
</style></head>
<body>
  <div class="card">
    <div class="title">Pro plan</div>
    <div class="caption">Billed annually. Cancel anytime.</div>
  </div>
</body></html>
"""


async def main() -> int:
    if not have_key():
        print("SKIP: no LLM key (Ollama Cloud: ~/.config/ollama/key or OLLAMA_API_KEY).")
        return 0

    with tempfile.TemporaryDirectory() as d:
        artifact = str(Path(d) / "card.html")
        Path(artifact).write_text(BROKEN)

        fix = make_fix_hook()  # real LLMCoder
        outcome = await ultracode_loop(
            artifact, fix, backend="local", log_dir=str(Path(d) / "percepts"), max_iter=5
        )

        print(f"\nterminated_on={outcome.terminated_on}  final={outcome.final_verdict.value}")
        for it in outcome.iterations:
            print(f"  iter {it.n}: verdict={it.verdict.value:4}  "
                  f"progressed={it.progressed}  stuck={it.stuck}  gating={len(it.gating)}")

        print("\nFinal page:\n" + Path(artifact).read_text())
        ok = outcome.passed and outcome.final_verdict == Verdict.PASS
        print("Result:", "PASS — agent fixed it; loop terminated on a self-computed `pass`"
              if ok else f"stopped on {outcome.terminated_on} (the framework refused to fake done)")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
