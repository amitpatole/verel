"""Memory demo — "the fleet stops repeating mistakes" (design §5, §7.5).

Session 1: an agent fixes a real overflow; Verel records the failure in long-term memory
           and, on PASS, marks it `fixed` (verified knowledge).
Consolidate: Ollama Cloud turns the episodic failure into a CANDIDATE semantic DesignRule.
Session 2: the SAME bug is reintroduced. Before wasting a single fix cycle, the regression
           guard recalls it from memory and FAILS the gate — terminating on `regression`.

Run:  python examples/demo_memory_loop.py
Needs: pip install -e ".[sight]"  + Ollama Cloud key (~/.config/ollama/key).
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from verel.agents import make_fix_hook
from verel.agents.llm import have_key
from verel.loop import ultracode_loop
from verel.memory import FailureLedger, LocalMemory, MemoryKind, consolidate_failures

BROKEN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>card</title>
<style>
  body { margin: 0; font-family: system-ui, sans-serif; background: #fff; }
  .card { box-sizing: border-box; width: 1600px; padding: 24px; border: 1px solid #ddd; }
  .title { color: #111; font-size: 28px; }
</style></head>
<body><div class="card"><div class="title">Pro plan</div></div></body></html>
"""


async def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    with tempfile.TemporaryDirectory() as d:
        mem = LocalMemory(Path(d) / "memory.sqlite")  # persists across both sessions
        ledger = FailureLedger(mem, scope="repo:demo")
        fix = make_fix_hook(verbose=False)
        artifact = str(Path(d) / "card.html")

        print("── Session 1: agent fixes the overflow ──")
        Path(artifact).write_text(BROKEN)
        o1 = await ultracode_loop(artifact, fix, backend="local",
                                  log_dir=str(Path(d) / "p1"), ledger=ledger)
        print(f"  terminated_on={o1.terminated_on}  iters={len(o1.iterations)}")
        failures = mem.all(kind=MemoryKind.FAILURE)
        print(f"  memory now holds {len(failures)} failure(s); "
              f"status={[f.detail.get('status') for f in failures]}")

        print("\n── Consolidate (Ollama Cloud): episodic failure → candidate DesignRule ──")
        rules = consolidate_failures(mem, scope="repo:demo", min_cluster=1)
        for r in rules:
            print(f"  [{r.trust.value}] DesignRule: {r.subject} → {r.text}")

        print("\n── Session 2: the SAME bug is reintroduced ──")
        Path(artifact).write_text(BROKEN)  # regression!
        o2 = await ultracode_loop(artifact, fix, backend="local",
                                  log_dir=str(Path(d) / "p2"), ledger=ledger, max_iter=3)
        print(f"  terminated_on={o2.terminated_on}  regressions={len(o2.regressions)}")
        for reg in o2.regressions:
            print(f"  ⮕ memory blocked it: {reg.text}  (was fixed, reintroduced)")

        ok = o1.passed and o2.terminated_on == "regression" and o2.regressions
        print("\nResult:", "PASS — Verel remembered the fix and refused to repeat the mistake"
              if ok else "NOT MET")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
