"""Fleet + worktrees + LLM manager — the full "agents managing agents" picture (§6).

An LLM Manager (Ollama Cloud) decides how to decompose the goal into independent workers.
The control plane validates/clamps that decision, then the Scheduler runs each worker in its
OWN isolated git worktree, concurrently: the worker autonomously fixes its page (Ollama
coder), is gated by AgentVision through the verdict bus, and commits the fix on its own
branch. Parallel workers never stomp each other; nothing merges on a self-asserted "done".

Run:  python examples/demo_fleet_worktrees.py   (needs ".[sight]" + ~/.config/ollama/key)
"""

from __future__ import annotations

import asyncio
import subprocess
import tempfile
from pathlib import Path

from verel.agents.llm import have_key
from verel.fleet import (
    BudgetLease,
    RetryPolicy,
    Scheduler,
    decide_fanout,
    to_tasks,
    validate_fanout,
    worktree_ultracode_worker,
)
from verel.fleet.worktree import WorktreeManager
from verel.memory import FailureLedger, LocalMemory

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{name}</title>
<style>
  body {{ margin:0; font-family:system-ui,sans-serif; background:#fff; }}
  .box {{ box-sizing:border-box; width:{w}px; padding:20px; }}
  .t {{ color:#111; font-size:24px; }}
</style></head><body><div class="box"><div class="t">{name}</div></div></body></html>
"""
PAGES = {"pricing": 1800, "settings": 2200, "profile": 2600}


def _init_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    def g(*a):
        subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.name", "verel"); g("config", "user.email", "verel@local")
    (root / "README.md").write_text("# design-system\n")
    g("add", "-A"); g("-c", "user.name=verel", "-c", "user.email=verel@local", "commit", "-q", "-m", "init")
    return root


async def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    with tempfile.TemporaryDirectory() as d:
        repo = _init_repo(Path(d) / "design-system")
        artifacts = list(PAGES)  # logical artifact ids (the worker seeds the real file)

        # 1) LLM MANAGER decomposes the goal; the plane validates it.
        print("── Manager (Ollama) decomposing goal ──")
        fanout = decide_fanout("fix every overflowing page in the design system",
                               artifacts=artifacts)
        ok, reason = validate_fanout(fanout)
        print(f"  decision={fanout.decision}  workers={len(fanout.subtasks)}  valid={ok} ({reason})")
        print(f"  rationale: {fanout.rationale[:90]}")

        # 2) each worker runs in its OWN worktree; seed writes the broken page there.
        mgr = WorktreeManager(repo)
        ledger = FailureLedger(LocalMemory(Path(d) / "mem.sqlite"), scope="repo:design-system")

        def seed(wt, task):
            name = (task.artifact or task.id)
            wt.write(f"{name}.html", PAGE.format(name=name, w=PAGES.get(name, 2000)))
            return str(wt.path / f"{name}.html")

        worker = worktree_ultracode_worker(mgr, seed=seed, backend="local", ledger=ledger)
        tasks = to_tasks(fanout, budget=BudgetLease(max_iters=5), retry=RetryPolicy(max=2, backoff_s=[0]))
        # map each task's artifact id onto the page name for seeding
        for t in tasks:
            t.artifact = t.artifact or t.id

        sched = Scheduler(worker, concurrency=fanout.concurrency_cap,
                          budget=BudgetLease(max_wallclock_s=900))
        print("\n── Orchestrator running fleet in isolated worktrees ──")
        state = await sched.run(tasks)
        for tid, st in state.items():
            print(f"  {tid}: {st.value}")

        ok_all = all(s.value == "passed" for s in state.values())
        print("\nResult:", "PASS — LLM manager fanned out; every worker fixed its page in an "
              "isolated worktree, each gated by its own eyes" if ok_all else "NOT MET")
        return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
