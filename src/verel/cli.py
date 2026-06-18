"""`verel` — the unified command line for the framework.

Subcommands (each lazily imports what it needs, so `verel doctor` works on a minimal install):
  verel doctor                         check the environment (python, git, ollama, sight, tools)
  verel loop  <artifact> [--backend]   run the ultracode visual loop (agent fix + AgentVision)
  verel fleet <goal> --artifacts a b   LLM manager fan-out → workers fix each artifact
  verel ci    <check|heal|...> --repo  agent-run CI (delegates to `python -m verel.ci`)
  verel heal  --repo PATH              self-healing CI: failing tests → agent fixes → pass
  verel version
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__


def _doctor() -> int:
    import shutil
    from pathlib import Path

    def ok(b):
        return "OK " if b else "-- "

    print(f"verel {__version__}")
    print(f"  {ok(sys.version_info >= (3, 10))}python {sys.version.split()[0]}")
    print(f"  {ok(shutil.which('git'))}git")
    print(f"  {ok((Path.home() / '.config/ollama/key').exists())}ollama cloud key (~/.config/ollama/key)")
    print(f"  {ok((Path.home() / '.config/OpenAI/key').exists())}openai key (fallback)")
    try:
        import agentvision  # noqa: F401
        sight = True
    except ImportError:
        sight = False
    print(f"  {ok(sight)}agentvision (eyes) — `pip install verel[sight]`")
    print(f"  {ok(shutil.which('ruff'))}ruff (lint grader)")
    print(f"  {ok(shutil.which('mypy'))}mypy (typecheck grader)")
    try:
        import mem0  # noqa: F401
        m = True
    except ImportError:
        m = False
    print(f"  {ok(m)}mem0 (rented memory backend) — `pip install verel[mem0]`")
    return 0


async def _loop(args) -> int:
    from .agents import make_fix_hook
    from .loop import ultracode_loop

    outcome = await ultracode_loop(args.artifact, make_fix_hook(verbose=True),
                                   backend=args.backend, max_iter=args.max_iter)
    print(f"terminated_on={outcome.terminated_on} verdict={outcome.final_verdict.value}")
    return 0 if outcome.passed else 1


async def _fleet(args) -> int:
    from .fleet import BudgetLease, Scheduler, decide_fanout, to_tasks, ultracode_worker

    fo = decide_fanout(args.goal, artifacts=args.artifacts)
    print(f"manager: {fo.decision}, {len(fo.subtasks)} worker(s)")
    tasks = to_tasks(fo, budget=BudgetLease(max_iters=args.max_iter))
    for t in tasks:
        t.artifact = t.artifact or t.id
    sched = Scheduler(ultracode_worker(backend=args.backend), concurrency=fo.concurrency_cap)
    state = await sched.run(tasks)
    for tid, st in state.items():
        print(f"  {tid}: {st.value}")
    return 0 if all(s.value == "passed" for s in state.values()) else 1


def _heal(args) -> int:
    from .ci import inner_loop_stage, self_heal

    stage = inner_loop_stage(args.repo, with_lint=False)
    res = self_heal(args.repo, stage, max_rounds=args.max_rounds)
    for r in res.rounds:
        print(f"  round {r.n}: {r.verdict}  actions={r.actions}  changed={r.changed}")
    print(f"healed={res.healed} terminated_on={res.terminated_on}")
    return 0 if res.healed else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="verel", description="verified agents framework")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check the environment")
    sub.add_parser("version", help="print version")

    lp = sub.add_parser("loop", help="run the ultracode visual loop")
    lp.add_argument("artifact")
    lp.add_argument("--backend", default="local")
    lp.add_argument("--max-iter", type=int, default=5)

    fl = sub.add_parser("fleet", help="LLM manager fan-out over artifacts")
    fl.add_argument("goal")
    fl.add_argument("--artifacts", nargs="+", required=True)
    fl.add_argument("--backend", default="local")
    fl.add_argument("--max-iter", type=int, default=5)

    hl = sub.add_parser("heal", help="self-healing CI (failing tests → agent fixes → pass)")
    hl.add_argument("--repo", required=True)
    hl.add_argument("--max-rounds", type=int, default=3)

    ci = sub.add_parser("ci", help="agent-run CI (delegates to verel.ci)")
    ci.add_argument("ci_args", nargs=argparse.REMAINDER)

    args = p.parse_args(argv)
    if args.cmd == "version":
        print(__version__)
        return 0
    if args.cmd == "doctor":
        return _doctor()
    if args.cmd == "loop":
        return asyncio.run(_loop(args))
    if args.cmd == "fleet":
        return asyncio.run(_fleet(args))
    if args.cmd == "heal":
        return _heal(args)
    if args.cmd == "ci":
        from .ci.__main__ import main as ci_main
        return ci_main(args.ci_args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
