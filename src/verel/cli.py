"""`verel` — the unified command line for the framework.

Subcommands (each lazily imports what it needs, so `verel doctor` works on a minimal install):
  verel doctor                         check the environment (python, git, ollama, sight, tools)
  verel loop  <artifact> [--backend]   run the ultracode visual loop (agent fix + AgentVision)
  verel fleet <goal> --artifacts a b   LLM manager fan-out → workers fix each artifact
  verel ci    <check|heal|...> --repo  agent-run CI (delegates to `python -m verel.ci`)
  verel heal  --repo PATH              self-healing CI: failing tests → agent fixes → pass
  verel verify <receipt.json>          verify a run-receipt (ed25519 = publicly verifiable; §11)
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

    import os as _os

    from .memory.registry import known_backends
    backend = _os.environ.get("VEREL_MEMORY_BACKEND") or (
        "remote" if _os.environ.get("VEREL_BRAIN_URL") else "local")
    print(f"  -> memory backend: {backend}  (available: {', '.join(known_backends())})")
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


def _verify(args) -> int:
    """Verify a receipt with NO trust in its producer: ed25519 needs only a trusted public key,
    so a stranger can confirm an agent's `gate` verdict was real. Exit 0 iff valid."""
    import json

    from .verdict import RunReceipt, verify_receipt

    allowed = {"ed25519"} if args.require_public else None
    try:
        with open(args.receipt, encoding="utf-8") as fh:
            receipt = RunReceipt.model_validate(json.load(fh))
    except (OSError, ValueError) as e:
        print(f"-- could not read receipt: {e}")
        return 2
    res = verify_receipt(receipt, allowed_algs=allowed)
    mark = "OK " if res.valid else "-- "
    public = "public-verifiable" if res.public_verifiable else "shared-secret" if res.valid else "—"
    print(f"{mark}{res.alg}  runner={res.runner_identity or '?'}  [{public}]")
    print(f"   {res.reason}")
    return 0 if res.valid else 1


def _serve(args) -> int:
    import os
    import threading

    from .integrations import GateServer
    # Secrets from env (never argv — argv leaks in the process list): a bearer token and the GitHub
    # webhook secret. A routable bind with no token + TLS fails closed inside GateServer.
    srv = GateServer(
        args.repo, host=args.host, port=args.port,
        auth_token=os.environ.get("VEREL_GATE_TOKEN"),
        webhook_secret=os.environ.get("VEREL_GATE_WEBHOOK_SECRET"),
        certfile=args.certfile, keyfile=args.keyfile, lint=not args.no_lint,
    ).start()
    print(f"verel gate server on {srv.url}  (repo={srv.repo})", flush=True)
    print("  POST /gate  ·  POST /github  ·  GET /health", flush=True)
    try:
        threading.Event().wait()  # serve until interrupted
    except KeyboardInterrupt:
        srv.stop()
    return 0


def _mcp(args) -> int:
    from .integrations import mcp_config_json, mcp_install_hint
    print(mcp_config_json() if getattr(args, "json", False) else mcp_install_hint())
    return 0


def _rules(args) -> int:
    from pathlib import Path

    from .integrations import rules_snippet
    filename, content = rules_snippet(args.target)
    if not args.write:
        print(content)
        return 0
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and "Verification gate (Verel)" in path.read_text():
        print(f"{filename} already contains the Verel gate instruction — nothing to do.")
        return 0
    with path.open("a", encoding="utf-8") as fh:
        if path.stat().st_size:
            fh.write("\n\n")
        fh.write(content if content.endswith("\n") else content + "\n")
    print(f"wrote the Verel gate instruction to {filename}")
    return 0


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

    vf = sub.add_parser("verify", help="verify a run-receipt (ed25519 = publicly verifiable)")
    vf.add_argument("receipt", help="path to a receipt JSON file")
    vf.add_argument("--require-public", action="store_true",
                    help="reject HMAC receipts; require ed25519 public verifiability")

    mc = sub.add_parser("mcp", help="plug Verel into an MCP agent host")
    mcsub = mc.add_subparsers(dest="mcp_cmd", required=True)
    mci = mcsub.add_parser("install", help="print the verel-mcp server config + where to add it")
    mci.add_argument("--json", action="store_true", help="print only the JSON config block")

    sv = sub.add_parser("serve", help="run the REST gate server over a repo (POST /gate, /github)")
    sv.add_argument("--repo", default=".", help="the repo this server gates")
    sv.add_argument("--host", default="127.0.0.1", help="bind host (routable host requires TLS + token)")
    sv.add_argument("--port", type=int, default=8750)
    sv.add_argument("--certfile", help="TLS cert (required for a non-loopback bind)")
    sv.add_argument("--keyfile", help="TLS key")
    sv.add_argument("--no-lint", action="store_true", help="skip the lint grader")

    rl = sub.add_parser("rules", help="emit a rules-file snippet so any agent gates via Verel")
    from .integrations import RULES_TARGETS
    rl.add_argument("--target", choices=sorted(RULES_TARGETS), default="agents",
                    help="agent host (default: agents → AGENTS.md)")
    rl.add_argument("--write", action="store_true",
                    help="write/append the snippet to its file in the current repo (else print)")

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
    if args.cmd == "verify":
        return _verify(args)
    if args.cmd == "mcp":
        return _mcp(args)
    if args.cmd == "rules":
        return _rules(args)
    if args.cmd == "serve":
        return _serve(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
