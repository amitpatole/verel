"""Fleet demo — agents managing agents (design §6).

An Orchestrator goal ("fix the design system's broken pages") is handed to a Manager, which
fans out one independent Worker per page. The single-writer Scheduler runs the workers
concurrently under a budget; each Worker autonomously fixes its page (Ollama Cloud coder)
and is GATED by AgentVision through the verdict bus — no worker self-declares done. A shared
failure ledger means a regression in any page is caught from fleet memory.

Run:  python examples/demo_fleet_loop.py     (needs ".[sight]" + ~/.config/ollama/key)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from verel.agents.llm import have_key
from verel.fleet import (
    BudgetLease,
    RetryPolicy,
    Scheduler,
    plan_over_artifacts,
    to_tasks,
    ultracode_worker,
)
from verel.fleet.manager import validate_fanout
from verel.memory import FailureLedger, LocalMemory

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{name}</title>
<style>
  body {{ margin:0; font-family:system-ui,sans-serif; background:#fff; }}
  .box {{ box-sizing:border-box; width:{w}px; padding:20px; }}
  .t {{ color:#111; font-size:24px; }}
</style></head><body><div class="box"><div class="t">{name}</div></div></body></html>
"""


async def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    with tempfile.TemporaryDirectory() as d:
        # two broken pages = a tiny "design system"
        pages = []
        for name, w in (("pricing", 1800), ("settings", 2200)):
            p = Path(d) / f"{name}.html"
            p.write_text(PAGE.format(name=name, w=w))
            pages.append(str(p))

        # Manager fans out one independent worker per page; the plane validates it.
        fanout = plan_over_artifacts("fix overflowing pages", pages, concurrency_cap=2)
        ok, reason = validate_fanout(fanout)
        print(f"manager fan-out: {len(fanout.subtasks)} workers, valid={ok} ({reason})")

        mem = LocalMemory(Path(d) / "fleet.sqlite")
        ledger = FailureLedger(mem, scope="repo:design-system")
        tasks = to_tasks(fanout, budget=BudgetLease(max_iters=5), retry=RetryPolicy(max=2, backoff_s=[0]))

        sched = Scheduler(
            ultracode_worker(backend="local", ledger=ledger, log_dir=str(Path(d) / "fleet")),
            concurrency=fanout.concurrency_cap,
            budget=BudgetLease(max_wallclock_s=600),
            wal_path=str(Path(d) / "wal.jsonl"),
        )
        print("orchestrator: running fleet…")
        state = await sched.run(tasks)

        for tid, st in state.items():
            print(f"  {tid}: {st.value}")
        failures = mem.all()
        print(f"shared fleet memory: {len(failures)} failure record(s) "
              f"({sum(f.detail.get('status')=='fixed' for f in failures)} fixed)")

        ok = all(s.value == "passed" for s in state.values())
        print("\nResult:", "PASS — the fleet fixed every page, each gated by its own eyes"
              if ok else "NOT MET")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
