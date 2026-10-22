"""`verel` — the unified command line for the framework.

Subcommands (each lazily imports what it needs, so `verel doctor` works on a minimal install;
run `verel <command> --help` for flags):
  verel doctor                         check the environment (python, git, graders, sandbox, keys)
  verel loop  <artifact> [--backend]   run the ultracode visual loop (agent fix + AgentVision)
  verel fleet <goal> --artifacts a b   LLM manager fan-out → workers fix each artifact
  verel ci    <check|precommit|iac|telecom…> --repo   agent-run CI (delegates to `verel-ci`)
  verel heal  --repo PATH              self-healing CI: failing tests → agent fixes → pass
  verel verify <receipt.json>          verify a run-receipt (ed25519 = publicly verifiable)
  verel verify-access <policy>         opt-in effective cloud-access verifier (online)
  verel serve  [--repo]                REST gate + PR webhook (fail-closed bind policy)
  verel mcp install                    expose Verel over the Model Context Protocol
  verel rules  --target FILE           write the Verel-gate instruction for any agent
  verel version
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from . import __version__


def _doctor() -> int:
    import shutil
    from pathlib import Path

    def ok(b):
        return "OK " if b else "-- "

    import subprocess

    def tool_ok(cmd) -> bool:  # a real invocation probe (not just PATH) — catches a broken/mismatched tool
        try:
            return subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    print(f"verel {__version__}")
    print("  — core grading (no key / no network needed):")
    print(f"  {ok(sys.version_info >= (3, 10))}python {sys.version.split()[0]}")
    print(f"  {ok(shutil.which('git'))}git")
    # pytest is the ONE grader `required` by every stage — probed the same way the grader runs it
    # (sys.executable), so `doctor` can't say OK while the very next `verel-ci check` errors (adoption P0).
    print(f"  {ok(tool_ok([sys.executable, '-m', 'pytest', '--version']))}"
          f"pytest (test grader — required) — `pip install verel[dev]`   [{sys.executable}]")
    print(f"  {ok(shutil.which('ruff'))}ruff (lint grader) — `pip install verel[dev]`")
    print(f"  {ok(shutil.which('mypy'))}mypy (typecheck grader) — `pip install verel[dev]`")
    # Untrusted-code sandbox tier — Linux-only; on macOS/Windows these paths fail CLOSED (they don't run
    # the core gate, only agent-built tools / generated spec-checks / MCP build_tool).
    print("  — sandbox tier (untrusted-code isolation; Linux-only, fails closed elsewhere):")
    print(f"  {ok(shutil.which('bwrap'))}bubblewrap (container sandbox — Linux only)")
    print(f"  {ok(shutil.which('systemd-run'))}systemd-run (cgroup memory bound for containered checks)")
    try:
        import pyseccomp  # noqa: F401
        _seccomp = True
    except ImportError:
        _seccomp = False
    print(f"  {ok(_seccomp)}pyseccomp (seccomp-bpf syscall filter) — `pip install verel[container]`")
    print("  — agentic features (`verel heal` / `loop` / `fleet` — needs an LLM key):")
    print(f"  {ok((Path.home() / '.config/ollama/key').exists())}"
          "ollama cloud key (~/.config/ollama/key or OLLAMA_API_KEY)")
    print(f"  {ok((Path.home() / '.config/OpenAI/key').exists())}"
          "openai key (fallback, VEREL_LLM_PROVIDER=openai)")
    try:
        import agentvision  # noqa: F401
        sight = True
    except ImportError:
        sight = False
    print(f"  {ok(sight)}agentvision (eyes) — `pip install verel[sight]`")
    print("  — optional: IaC / K8s graders (`verel[iac]` + external binaries):")
    # IaC / DevOps graders + IAM sensor (IAC-KICKOFF.md) — external binaries, install `verel[iac]`.
    # terraform/tofu is the IAC grader + IAM-change source; the rest broaden coverage by phase.
    _tf = shutil.which("terraform") or shutil.which("tofu")
    print(f"  {ok(_tf)}terraform/tofu (IaC + IAM-sensor grader)")
    for _bin, _label in (("trivy", "trivy (IaC security grader)"),
                         ("tflint", "tflint (IaC lint grader)"),
                         ("checkov", "checkov (IaC security grader)"),
                         ("conftest", "conftest/OPA (policy grader)"),
                         ("infracost", "infracost (cost grader)"),
                         ("parliament", "parliament (IAM least-priv grader)"),
                         ("cloudsplaining", "cloudsplaining (IAM least-priv grader)"),
                         ("kubectl", "kubectl (K8s validate + RBAC sensor)"),
                         ("helm", "helm (K8s render + RBAC sensor)"),
                         ("kube-score", "kube-score (K8s posture grader)"),
                         ("kube-linter", "kube-linter (K8s posture grader)"),
                         ("polaris", "polaris (K8s posture grader)")):
        print(f"  {ok(shutil.which(_bin))}{_label}")
    # Cloud creds for the effective-access verifier (Phase 5) — resolved from ~/.config (never logged).
    from .actuators.cloudcreds import resolve as _resolve_creds
    for _cloud in ("aws", "gcp", "azure"):
        cc = _resolve_creds(_cloud)
        warn = f"  ⚠ {cc.warning}" if cc.warning else ""
        print(f"  {ok(cc.available)}{_cloud} creds — {cc.source}{warn}")
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
    print("\n  next: `verel-ci check --repo .` — grade a repo into one signed verdict (no key needed).")
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
    from .agents.llm import LLMError
    from .ci import inner_loop_stage, self_heal

    stage = inner_loop_stage(args.repo, with_lint=False)
    try:
        res = self_heal(args.repo, stage, max_rounds=args.max_rounds)
    except LLMError as e:  # agentic features need an LLM key — a config problem, not a crash
        print(f"-- {e}\n   `verel heal` needs an LLM; run `verel doctor` to check your key setup.",
              file=sys.stderr)
        return 2
    for r in res.rounds:
        print(f"  round {r.n}: {r.verdict}  actions={r.actions}  changed={r.changed}")
    print(f"healed={res.healed} terminated_on={res.terminated_on}")
    return 0 if res.healed else 1


def _pilot(args) -> int:
    """Shadow-mode pilot: `record` gates + logs a would-be verdict, `eval` scores the log against human
    labels and recommends which graders earned enforcement, `verify` checks the log's hash chain."""
    from ._chainlog import LogBusy
    from .pilot import LogCorrupt, ShadowLog, evaluate, load_labels, parse_mode, run_pilot
    from .pilot.render import render
    if args.pilot_cmd == "demo":
        from .pilot.demo import run_demo
        return run_demo()
    # --domain: the log's MAC domain (empty for CLI logs, "<tenant>/pilot" for service data)
    log = ShadowLog(getattr(args, "log", None) or os.devnull, domain=getattr(args, "domain", "") or "")
    try:
        if args.pilot_cmd == "verify":
            n = log.verify(args.expect_head, segment=args.segment)
            print(f"OK: {n} records, chain intact" + ("" if args.segment else f", head={log.head()}"))
            return 0
        if args.pilot_cmd in ("promote", "demote", "policy", "health", "default"):
            return _pilot_policy(args, log)
        if args.pilot_cmd == "repair":
            dropped = log.repair()
            print(f"repaired: dropped {dropped} unacknowledged record(s); {log.verify()} live, "
                  f"head={log.head()}")
            return 0
        if args.pilot_cmd == "archive":
            from datetime import datetime, timezone
            total = log.verify()
            seg = args.segment or f"{args.log}.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.archive"
            moved = log.archive_first(max(0, total - max(0, args.keep_last)), seg)
            print(f"archived {moved} decisions to {seg}; {log.verify()} live, head={log.head()}")
            return 0
        if args.pilot_cmd == "eval":
            ev = evaluate(log.records(), load_labels(args.labels), warn_is_positive=args.warn_positive,
                          min_samples=args.min_samples, min_precision=args.min_precision,
                          min_recall=args.min_recall, max_errored_rate=args.max_errored_rate)
            if args.json:
                import json as _json
                print(_json.dumps(ev.model_dump(mode="json"), indent=2))
            else:
                print(render(ev))
            return 0
        import json as _json

        from ._safeio import read_regular
        from .verdict.models import Report
        raw = _json.loads(read_regular(args.reports, 10_000_000).decode("utf-8"))
        reports = [Report.model_validate(r) for r in (raw if isinstance(raw, list) else [raw])]
        policy = None
        if args.policy:
            from .pilot.policy import PolicyStore
            policy = PolicyStore(args.policy).current()
        dec = run_pilot(reports, artifact_id=args.artifact_id, mode=parse_mode(args.mode), log=log,
                        policy=policy)
        from .memory.view import canonical_text as _s
        print(f"{dec.enforced.value.upper()} (would-be {dec.would_be.value}, mode {dec.mode.value})"
              + (f": {_s(dec.reason)}" if dec.reason else ""))
        return 1 if dec.blocked else 0
    except LogCorrupt as e:
        print(f"error: pilot log failed integrity check: {e}", file=sys.stderr)
        return 2
    except LogBusy:
        print("error: the evidence log is busy (another writer holds it); try again", file=sys.stderr)
        return 2
    except (ValueError, OSError, RecursionError, MemoryError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def _auth(args) -> int:
    from .auth import AuditLog, add_token, list_tokens, revoke_token
    from .memory.view import canonical_text as _s
    try:
        if args.auth_cmd == "add":
            tok = add_token(args.file, id=args.id, role=args.role, tenant=args.tenant, expires=args.expires)
            print(f"token for {_s(args.id)} (role={args.role}, tenant={args.tenant}). "
                  "SHOWN ONCE, store it now:")
            print(tok)
            return 0
        if args.auth_cmd == "revoke":
            ok = revoke_token(args.file, args.id)
            print("revoked" if ok else "no such token id")
            return 0 if ok else 1
        if args.auth_cmd == "list":
            for t in list_tokens(args.file):
                print(f"  {_s(t['id']):<24} role={t['role']:<9} tenant={t['tenant']:<16} "
                      f"expires={t.get('expires', '-')}")
            return 0
        n = AuditLog(args.log).verify()
        print(f"OK: {n} audit records, chain intact")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"error: {type(e).__name__}: {_s(str(e))[:300]}", file=sys.stderr)
        return 2


def _serve_pilot(args) -> int:
    import os
    import signal
    import threading

    from .auth import Authenticator, OIDCConfig, OIDCVerifier, TokenStore
    from .pilot.service import PilotServer
    tokens = TokenStore(args.tokens) if args.tokens else None
    oidc = None
    if args.oidc_issuer:
        oidc = OIDCVerifier(OIDCConfig(issuer=args.oidc_issuer, audience=args.oidc_audience or "",
                                       jwks_file=args.oidc_jwks_file, jwks_url=args.oidc_jwks_url))
    insecure = os.environ.get("VEREL_GATE_INSECURE", "").strip().lower() in ("1", "true", "yes", "on")
    srv = PilotServer(args.data_dir, Authenticator(tokens, oidc), host=args.host, port=args.port,
                      certfile=args.certfile, keyfile=args.keyfile, insecure=insecure).start()
    print(f"verel pilot service on {srv.url}  (data={srv.root})", flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
    srv.stop()
    return 0


from pathlib import Path as _Path  # noqa: E402


def _load_sinks(path: str | None) -> dict:
    """sinks.json: {"tenant": {"sink-id": {"url": ..., "secret_env": "ENV_NAME", "allow_http": false}}}.
    Secrets are read from the named environment variable, never stored in the file."""
    import json
    import os

    from .connectors.webhook import Sink
    if not path:
        return {}
    cfg = json.loads(_Path(path).read_text(encoding="utf-8"))
    out: dict = {}
    for tenant, sinks in cfg.items():
        for sid, s in sinks.items():
            secret = os.environ.get(str(s.get("secret_env", "")), "")
            if not secret:
                env = s.get("secret_env")
                raise ValueError(f"sink {tenant}/{sid}: environment variable {env!r} is not set")
            out.setdefault(tenant, {})[sid] = Sink(url=s["url"], secret=secret,
                                                   allow_http=bool(s.get("allow_http", False)))
    return out


def _worker(args) -> int:
    import signal
    import threading
    from pathlib import Path as _P

    from .jobs import JobQueue, WorkerContext, run_pool
    roots: dict[str, dict[str, _P]] = {}
    pins: dict[tuple[str, str, str], str] = {}
    for spec in args.root or []:
        key, _, path = spec.partition("=")
        tenant, _, name = key.partition("/")
        if not (tenant and name and path):
            print("error: --root must be TENANT/NAME=/absolute/path", file=sys.stderr)
            return 2
        roots.setdefault(tenant, {})[name] = _P(path).resolve()
    for spec in args.pin or []:
        key, _, rel = spec.partition("=")
        head, _, kind = key.partition(":")
        tenant, _, name = head.partition("/")
        known = name in roots.get(tenant, {})
        if not (tenant and name and rel) or kind not in ("spec", "policy") or not known:
            print("error: --pin must be TENANT/NAME:spec=relpath or TENANT/NAME:policy=relpath for a "
                  "configured --root", file=sys.stderr)
            return 2
        pins[(tenant, name, kind)] = rel
    try:
        ctx = WorkerContext(data_dir=_P(args.data_dir), roots=roots, pins=pins, sinks=_load_sinks(args.sinks))
    except (ValueError, OSError, KeyError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    q = JobQueue(args.db)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    threads = run_pool(q, ctx, concurrency=args.concurrency, stop=stop, lease_s=args.lease_s)
    print(f"verel worker: {len(threads)} thread(s), tenants={sorted(roots)}, db={args.db}", flush=True)
    try:
        stop.wait()
    except KeyboardInterrupt:
        stop.set()
    for t in threads:
        t.join(timeout=10)
    return 0


def _jobs(args) -> int:
    import json

    from .jobs import JobQueue
    q = JobQueue(args.db)
    try:
        if args.jobs_cmd == "stats":
            print(json.dumps(q.stats(args.tenant)))
            return 0
        if args.jobs_cmd == "purge":
            print(f"purged {q.purge(args.older_than_days * 86400)} jobs")
            return 0
        if args.jobs_cmd == "show":
            row = q.get(args.tenant, args.id)
            print(json.dumps(row, indent=2) if row else "not found")
            return 0 if row else 1
        payload = json.loads(_Path(args.payload).read_text(encoding="utf-8"))
        print(q.enqueue(args.tenant, args.kind, payload, dedupe_key=args.dedupe_key))
        return 0
    except (ValueError, OSError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def _hotfolder(args) -> int:
    import time as _t
    from pathlib import Path as _P

    from ._chainlog import LogBusy
    from .connectors.hotfolder import HotFolder, scan_once
    from .memory.view import canonical_text as _s
    hf = HotFolder(root=_P(args.root).resolve(), data_dir=_P(args.data_dir), tenant=args.tenant,
                   spec=args.spec, mode=args.mode, settle_s=args.settle_s,
                   facts_timeout_s=args.facts_timeout_s, continuous=not args.once,
                   require_binding=not args.no_require_binding)
    try:
        while True:
            try:
                for o in scan_once(hf):
                    if o.action == "graded":
                        print(f"{_s(o.name)}: would-be {o.would_be}, enforced {o.enforced}"
                              + (f" -> {o.moved_to}" if o.moved_to else ""), flush=True)
            except LogBusy:  # a writer held the evidence log: not fatal for a watcher; try next interval
                if args.once:
                    print("error: evidence log is busy; try again", file=sys.stderr)
                    return 2
            if args.once:
                return 0
            _t.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def _media(args) -> int:
    if args.media_cmd == "demo":
        from .media.demo import run_demo
        return run_demo()
    return 2


def _pilot_policy(args, log) -> int:
    from .pilot import load_labels
    from .pilot.policy import PolicyError, PolicyStore, autodemote, health
    from .pilot.policy import evaluate_for_promotion as _ev
    store = PolicyStore(args.policy, domain=getattr(args, "domain", "") or "")
    try:
        if args.pilot_cmd == "policy":
            pol = store.current()
            print(f"default: {pol.default.value}")
            for g, m in sorted(pol.graders.items()):
                print(f"  {g:<12} {m.value}")
            for r in store.records()[-10:]:
                print(f"  [{r.ts[:19]}] {r.by}: {r.action} {r.grader} -> {r.mode}"
                      + (" (OVERRIDE)" if r.overridden else "") + (f" - {r.reason}" if r.reason else ""))
            return 0
        if args.pilot_cmd == "default":
            store.set_default(args.mode, args.by, args.reason)
            print(f"default mode is now {args.mode}")
            return 0
        if args.pilot_cmd == "demote":
            store.demote(args.grader, args.to, args.by, args.reason)
            print(f"{args.grader} -> {args.to}")
            return 0
        labels = load_labels(args.labels)
        if args.pilot_cmd == "health":
            recs = log.records()
            hs = (autodemote(store, recs, labels) if args.apply else
                  [h for h in health(recs, labels, store.current()) if not h.healthy])
            allh = health(recs, labels, store.current()) if not args.apply else hs
            for h in allh:
                print(f"  {h.grader:<12} {'healthy' if h.healthy else 'UNHEALTHY'}: {h.reason}")
            if args.apply and hs:
                print(f"demoted to advisory: {', '.join(h.grader for h in hs)}")
            return 1 if hs else 0
        ev = _ev(log.records(), labels)
        rec = store.promote(args.grader, args.to, args.by, ev, reason=args.reason,
                            override_reason=args.override_reason)
        note = " (OVERRIDDEN: evidence bar waived)" if rec.overridden else ""
        print(f"{args.grader} -> {rec.mode}{note}")
        return 0
    except PolicyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


def _guard(args) -> int:
    """Static document-ingress scan for hidden content / prompt injection. `scan` grades one or more
    files and prints grounded findings (exit 1 on FAIL); `demo` runs a no-API-key walkthrough."""
    if args.guard_cmd == "demo":
        from .guard.demo import run_demo
        return run_demo()

    from .guard import grade_docs
    report = grade_docs(args.paths)
    if args.json:
        import json as _json
        print(_json.dumps(report.model_dump(mode="json"), indent=2))
        return 1 if report.verdict.value == "fail" else 0

    from .memory.view import canonical_text as _s  # terminal-safe render of untrusted snippets
    print(f"{report.verdict.value.upper()}: {_s(report.summary)}")
    for i in report.issues:
        det = i.detail.get("detection_id", "?")
        print(f"  [{i.severity.value:<8}] {det:<10} {_s(str(i.locator or ''))}")
        print(f"             {_s(i.message)}")
    return 1 if report.verdict.value == "fail" else 0


def _fmt_when(ts: float) -> str:
    """A UTC ISO instant for a bi-temporal readout; `0`/open renders as 'now'."""
    from datetime import datetime, timezone
    if not ts:
        return "now"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def _render_asof(r) -> str:
    """One line for an as-of snapshot: value, its VALID interval, and trust tier. Untrusted text is
    sanitized by the caller (`canonical_text`)."""
    lo = _fmt_when(r.valid_from or r.created_ts)
    hi = _fmt_when(r.valid_to) if r.valid_to else "open"
    head = f"{r.subject} {r.predicate}".strip()
    return f"{head}: {r.text}  [{lo} .. {hi}]  ({r.trust.value})"


def _memory(args) -> int:
    """Operator review of the memory trust layer — the human-in-the-loop path that resolves
    CANDIDATE facts. CLI-only by design: an agent must not be able to approve its own facts over
    MCP. Every mutation is appended to the hash-chained memory audit log with the operator as actor."""
    import os

    from .memory import (
        AuditedMemory,
        MemoryAudit,
        MemoryKind,
        RejectedApprovalError,
        approve,
        load_backend,
        pending,
        reject,
        render_line,
        render_record,
    )
    from .memory.view import canonical_text as _s  # terminal-safe: strips ANSI/control/newline

    if args.memory_cmd == "rubric":
        from .memory.rubric import assess
        assessment = assess()
        print(assessment.render())
        return 0 if assessment.score == len(assessment.results) else 1

    try:
        import getpass
        operator = getpass.getuser()
    except Exception:
        operator = "operator"
    audit = MemoryAudit.from_env()

    if args.memory_cmd == "audit":
        if args.verify:
            ok, reason = audit.verify()
            print(("OK  " if ok else "-- ") + f"audit chain: {reason}  ({audit.path})")
            return 0 if ok else 1
        entries = audit.entries(args.record_id or None)
        for e in entries[-args.limit:]:
            b = _s(str((e.get("before") or {}).get("trust", "—")))
            a = _s(str((e.get("after") or {}).get("trust", "—")))
            # actor/action/record_id can carry attacker-controlled strings (round-13/M3) — sanitize
            print(f"{e.get('ts', 0):.0f}  {_s(str(e.get('actor', '?'))):<20} "
                  f"{_s(str(e.get('action', '?'))):<12} {_s(str(e.get('record_id', '?')))}  {b} -> {a}")
        print(f"({len(entries)} entr{'y' if len(entries) == 1 else 'ies'} total, {audit.path})")
        return 0

    backend = os.environ.get("VEREL_MEMORY_BACKEND", "local")
    try:
        mem = AuditedMemory(load_backend(backend), audit, actor=f"cli:{operator}")
    except Exception as e:
        print(f"-- could not load memory backend {backend!r}: {type(e).__name__}: {e}")
        return 2

    if args.memory_cmd == "pending":
        kind = MemoryKind(args.kind) if args.kind else None
        recs = pending(mem, scope=args.scope, kind=kind, limit=args.limit)
        for r in recs:
            print(render_line(r, width=args.width))
        print(f"({len(recs)} candidate(s) awaiting review; "
              f"approve with `verel memory approve <id>`, reject with `verel memory reject <id>`)")
        return 0
    if args.memory_cmd == "show":
        rec = mem.get(args.id)
        if rec is None:
            print(f"-- no record {args.id!r}")
            return 1
        print(render_record(rec))
        return 0
    if args.memory_cmd == "approve":
        try:
            rec = approve(mem, args.id, reviewed_by=operator)
        except RejectedApprovalError as e:
            print(f"-- refused: {e}")
            return 1
        if rec is None:
            print(f"-- no record {args.id!r}")
            return 1
        print(f"OK  {_s(rec.id)} -> {rec.trust.value} (reviewed by {operator}, audited)")
        return 0
    if args.memory_cmd == "reject":
        rec = reject(mem, args.id, reviewed_by=operator, reason=args.reason)
        if rec is None:
            print(f"-- no record {args.id!r}")
            return 1
        print(f"OK  {_s(rec.id)} -> {rec.trust.value} (durable tombstone — this value can no longer "
              f"be recalled or re-promoted)")
        return 0
    if args.memory_cmd in ("recall", "members"):
        import time as _time

        from .memory import members_as_of, parse_when, recall_as_of
        kind = MemoryKind(args.kind) if args.kind else None
        if args.as_of:
            as_of = parse_when(args.as_of)
            if as_of is None:
                print(f"-- could not parse --as-of {args.as_of!r} (use ISO-8601 or epoch seconds)")
                return 2
        else:
            as_of = _time.time()  # default: "as of now" — current open-interval values
        when = _fmt_when(as_of)
        if args.memory_cmd == "recall":
            recs = recall_as_of(mem, args.query, as_of=as_of, scope=args.scope, kind=kind, k=args.k)
            print(f"as of {when} — {len(recs)} record(s) for {args.query!r}:")
        else:
            recs = members_as_of(mem, predicate=args.predicate, as_of=as_of, value=args.value,
                                 scope=args.scope, kind=kind)
            held = f"={args.value!r}" if args.value else ""
            print(f"as of {when} — {len(recs)} holder(s) of {args.predicate!r}{held}:")
        for r in recs:
            print("  " + _s(_render_asof(r)))
        return 0
    return 2


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
    # VEREL_GATE_INSECURE=1 waives in-process TLS for a routable bind — ONLY for a TLS-terminating
    # ingress/proxy in front (auth is STILL required). Used by the Helm chart's behind-ingress path.
    insecure = os.environ.get("VEREL_GATE_INSECURE", "").strip().lower() in ("1", "true", "yes", "on")
    srv = GateServer(
        args.repo, host=args.host, port=args.port,
        auth_token=os.environ.get("VEREL_GATE_TOKEN"),
        webhook_secret=os.environ.get("VEREL_GATE_WEBHOOK_SECRET"),
        certfile=args.certfile, keyfile=args.keyfile, lint=not args.no_lint, insecure=insecure,
    ).start()
    print(f"verel gate server on {srv.url}  (repo={srv.repo})", flush=True)
    print("  POST /gate  ·  POST /github  ·  GET /health  ·  GET /ready", flush=True)
    # Drain cleanly on SIGTERM (k8s pod termination) as well as SIGINT (Ctrl-C), so a rolling update
    # stops accepting + shuts the server down within the grace period instead of being SIGKILLed.
    import signal
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
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


def _verify_access(args) -> int:
    """OPT-IN effective-access check — query what the cloud ACTUALLY grants (AWS IAM Access Analyzer /
    GCP Policy Analyzer / Azure role assignments). Needs cloud READ creds (resolved from ~/.config,
    never logged) and makes live provider calls — deliberately NOT part of the offline gate."""
    from .actuators import EffectiveAccessVerifier, resolve
    creds = resolve(args.cloud)
    if not creds.available:
        print(f"verify-access: no {args.cloud} credentials ({creds.source}) — fail closed", file=sys.stderr)
        return 2
    if creds.warning:
        print(f"verify-access: warning: {creds.warning}", file=sys.stderr)
    v = EffectiveAccessVerifier()
    try:
        if args.cloud == "aws":
            if args.principal_arn:
                # Effective-access: ask the account what the principal is ACTUALLY allowed (round-7).
                from .ci.iac import _PRIVESC_ACTIONS
                actions = args.action or sorted(_PRIVESC_ACTIONS)
                rep = v.aws_simulate_principal(args.principal_arn, actions, creds)
            elif args.policy_file:
                rep = v.aws_validate_policy(args.policy_file, creds)
            else:
                print("verify-access: aws needs --principal-arn (effective access) or --policy-file "
                      "(static validation)", file=sys.stderr)
                return 2
        elif args.cloud == "gcp":
            if not args.scope:
                print("verify-access: --scope is required for gcp (e.g. projects/<id>)", file=sys.stderr)
                return 2
            rep = v.gcp_analyze_iam(args.scope, creds)
        else:
            rep = v.azure_role_assignments(creds)
    except ValueError as e:  # safe_arg rejected an injected option/metachar in policy_file / scope
        print(f"verify-access: {e}", file=sys.stderr)
        return 2
    print(f"[verify-access:{args.cloud}] verdict={rep.verdict.value}  ({creds.source})")
    if rep.errored:
        print(f"  ! {rep.summary}", file=sys.stderr)
    for i in rep.issues[:50]:
        print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:80]}")
    from .verdict.models import Verdict
    return 0 if rep.verdict != Verdict.FAIL else 1


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

    mm = sub.add_parser("memory", help="operator review of the memory trust layer "
                                       "(list/approve/reject CANDIDATE facts; audit log)")
    mmsub = mm.add_subparsers(dest="memory_cmd", required=True)
    mp = mmsub.add_parser("pending", help="list CANDIDATE facts awaiting human review")
    mp.add_argument("--scope", help="filter to one scope (e.g. repo:x)")
    mp.add_argument("--kind", help="filter to one kind (fact|design_rule|schema|failure|skill)")
    mp.add_argument("--limit", type=int, default=50)
    mp.add_argument("--width", type=int, default=100, help="max line width for the listing")
    msh = mmsub.add_parser("show", help="show one record: chain, ledger, review metadata")
    msh.add_argument("id")
    map_ = mmsub.add_parser("approve", help="promote a CANDIDATE to VERIFIED on human authority")
    map_.add_argument("id")
    mrj = mmsub.add_parser("reject", help="reject a fact — durable tombstone, never recalled again")
    mrj.add_argument("id")
    mrj.add_argument("--reason", default="", help="recorded in the record + audit log")
    mau = mmsub.add_parser("audit", help="show or verify the hash-chained memory mutation log")
    mau.add_argument("--record-id", help="filter entries to one record id")
    mau.add_argument("--limit", type=int, default=50)
    mau.add_argument("--verify", action="store_true", help="verify the hash chain end-to-end")
    mrc = mmsub.add_parser("recall", help="bi-temporal recall — what was believed about a query AS OF "
                                          "a past instant (point-in-time; read-only)")
    mrc.add_argument("query", help="text to match (subject/predicate/value tokens)")
    mrc.add_argument("--as-of", help="ISO-8601 or epoch seconds; default = now")
    mrc.add_argument("--scope", help="filter to one scope (also sees global)")
    mrc.add_argument("--kind", help="filter to one kind (fact|design_rule|schema|failure|skill)")
    mrc.add_argument("-k", type=int, default=5, help="max records to return")
    mmb = mmsub.add_parser("members", help="set-membership as-of — every subject holding a predicate "
                                           "(optionally =value) at a past instant (e.g. who was admin then)")
    mmb.add_argument("--predicate", required=True, help="the relation (e.g. role)")
    mmb.add_argument("--value", help="filter to holders of this exact value (e.g. admin)")
    mmb.add_argument("--as-of", help="ISO-8601 or epoch seconds; default = now")
    mmb.add_argument("--scope", help="filter to one scope (also sees global)")
    mmb.add_argument("--kind", help="filter to one kind (fact|design_rule|schema|failure|skill)")
    mmsub.add_parser("rubric", help="self-assess the memory against the agent-memory-atlas rubric "
                                    "(7 binary dimensions, live behavioural probes)")

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

    gd = sub.add_parser("guard", help="scan untrusted documents for hidden content / prompt injection "
                                      "BEFORE an LLM sees them (docx + text; static, no API key)")
    gdsub = gd.add_subparsers(dest="guard_cmd", required=True)
    gds = gdsub.add_parser("scan", help="scan one or more documents; exit 1 on FAIL")
    gds.add_argument("paths", nargs="+", help="document paths to scan")
    gds.add_argument("--json", action="store_true", help="emit the full Report as JSON")
    gdsub.add_parser("demo", help="no-API-key walkthrough: hostile doc → grounded FAIL → fixed → PASS")

    au = sub.add_parser("auth", help="manage pilot-service bearer tokens (hashed at rest) and audit logs")
    ausub = au.add_subparsers(dest="auth_cmd", required=True)
    aua = ausub.add_parser("add", help="create a token (printed once; only its SHA-256 is stored)")
    aua.add_argument("--file", required=True)
    aua.add_argument("--id", required=True)
    aua.add_argument("--role", required=True, help="viewer | operator | admin")
    aua.add_argument("--tenant", required=True)
    aua.add_argument("--expires", help="ISO date")
    aur = ausub.add_parser("revoke", help="revoke a token by id (effective on the next request)")
    aur.add_argument("--file", required=True)
    aur.add_argument("--id", required=True)
    aul = ausub.add_parser("list", help="list token ids, roles, tenants (never secrets)")
    aul.add_argument("--file", required=True)
    auv = ausub.add_parser("verify-audit", help="verify the audit log's keyed hash chain")
    auv.add_argument("--log", required=True)

    sp_ = sub.add_parser("serve-pilot", help="multi-tenant pilot HTTP service: tokens/OIDC, roles, "
                                             "per-tenant logs, audit trail")
    sp_.add_argument("--data-dir", required=True)
    sp_.add_argument("--tokens", help="token file made with `verel auth add`")
    sp_.add_argument("--oidc-issuer")
    sp_.add_argument("--oidc-audience")
    sp_.add_argument("--oidc-jwks-file")
    sp_.add_argument("--oidc-jwks-url")
    sp_.add_argument("--host", default="127.0.0.1")
    sp_.add_argument("--port", type=int, default=8099)
    sp_.add_argument("--certfile")
    sp_.add_argument("--keyfile")

    wk = sub.add_parser("worker", help="run grading workers over the durable job queue")
    wk.add_argument("--db", required=True, help="SQLite job queue file")
    wk.add_argument("--data-dir", required=True)
    wk.add_argument("--root", action="append",
                    help="TENANT/NAME=/abs/path: a media root that tenant's jobs may name (repeatable)")
    wk.add_argument("--pin", action="append",
                    help="TENANT/NAME:spec=relpath (or :policy=) pins the delivery spec / provenance policy; "
                         "REQUIRED for policy and enforce modes")
    wk.add_argument("--sinks", help="webhook sinks JSON (secrets come from env vars it names)")
    wk.add_argument("--concurrency", type=int, default=4)
    wk.add_argument("--lease-s", type=float, default=60.0)

    jb = sub.add_parser("jobs", help="enqueue / inspect jobs in the queue")
    jbsub = jb.add_subparsers(dest="jobs_cmd", required=True)
    jbe = jbsub.add_parser("enqueue")
    jbe.add_argument("--db", required=True)
    jbe.add_argument("--tenant", required=True)
    jbe.add_argument("--kind", required=True, help="media_grade | provenance_grade | webhook")
    jbe.add_argument("--payload", required=True, help="JSON file")
    jbe.add_argument("--dedupe-key")
    jbs = jbsub.add_parser("stats")
    jbs.add_argument("--db", required=True)
    jbs.add_argument("--tenant")
    jbp = jbsub.add_parser("purge", help="delete done/dead jobs older than N days")
    jbp.add_argument("--db", required=True)
    jbp.add_argument("--older-than-days", type=float, default=7.0)
    jbw = jbsub.add_parser("show")
    jbw.add_argument("--db", required=True)
    jbw.add_argument("--tenant", required=True)
    jbw.add_argument("--id", required=True)

    hf = sub.add_parser("hotfolder", help="watch a folder: grade dropped files, write verdict sidecars "
                                          "(shadow by default; never deletes)")
    hf.add_argument("--root", required=True, help="contains incoming/ and the spec file")
    hf.add_argument("--data-dir", required=True)
    hf.add_argument("--tenant", required=True)
    hf.add_argument("--spec", default="spec.yaml", help="delivery spec, relative to --root")
    hf.add_argument("--mode", default="shadow", help="shadow (default) | advisory | enforce")
    hf.add_argument("--settle-s", type=float, default=5.0)
    hf.add_argument("--facts-timeout-s", type=float, default=3600.0)
    hf.add_argument("--interval", type=float, default=10.0)
    hf.add_argument("--once", action="store_true", help="scan once and exit (stability = file mtime age)")
    hf.add_argument("--no-require-binding", action="store_true",
                    help="WEAKER: accept facts that do not name the file they measured (asset.sha256). "
                         "Anyone who can write to incoming/ can then pair a bad file with good facts.")

    md = sub.add_parser("media", help="media & communications delivery grading (see also: verel-ci media)")
    mdsub = md.add_subparsers(dest="media_cmd", required=True)
    mdsub.add_parser("demo", help="no-API-key walkthrough: bad loudness/sync/captions → FAIL → fixed → PASS; "
                                  "tampered content credentials → FAIL")

    pl = sub.add_parser("pilot", help="shadow-mode pilot: record would-be verdicts, score vs human labels, "
                                      "recommend what earned enforcement")
    plsub = pl.add_subparsers(dest="pilot_cmd", required=True)
    plsub.add_parser("demo", help="no-API-key synthetic pilot: shadow-record → label → evaluate → graduate")
    plr = plsub.add_parser("record", help="gate one artifact's reports (JSON) and log the would-be verdict")
    plr.add_argument("--reports", required=True, help="JSON file: one Report or a list of Reports")
    plr.add_argument("--artifact-id", required=True)
    plr.add_argument("--mode", default="shadow", help="shadow (default) | advisory | enforce")
    plr.add_argument("--log", required=True, help="hash-chained JSONL decision log")
    plr.add_argument("--domain", default="", help="MAC domain of the evidence (empty for CLI-made logs; "
                      "'<tenant>/pilot' (or '/policy') for data written by `verel serve-pilot`)")
    plr.add_argument("--policy", help="promotion policy history: per-grader modes decide what is enforced "
                                      "(then --mode is ignored)")
    ple = plsub.add_parser("eval", help="score the log against labels; exit 0 always (it's a report)")
    ple.add_argument("--log", required=True)
    ple.add_argument("--domain", default="", help="MAC domain of the evidence (empty for CLI-made logs; "
                      "'<tenant>/pilot' (or '/policy') for data written by `verel serve-pilot`)")
    ple.add_argument("--labels", required=True, help='JSON/JSONL of {"artifact_id","defect"}')
    ple.add_argument("--min-samples", type=int, default=30)
    ple.add_argument("--min-precision", type=float, default=0.95)
    ple.add_argument("--min-recall", type=float, default=0.5,
                     help="a grader must also catch at least this share of real defects to graduate")
    ple.add_argument("--max-errored-rate", type=float, default=0.05,
                     help="a grader that errors on more than this share of artifacts cannot graduate")
    ple.add_argument("--warn-positive", action="store_true", help="count WARN as a positive prediction")
    ple.add_argument("--json", action="store_true")
    for name, hlp in (("promote", "raise a grader's mode; to ENFORCE it must have earned it (evidence is "
                                  "computed from --log/--labels now) or you give --override-reason"),
                      ("demote", "lower a grader's mode (always allowed; needs a reason)"),
                      ("default", "set the policy default mode for graders without their own entry"),
                      ("policy", "show the current per-grader modes and recent history"),
                      ("health", "check enforcing graders against recent labeled outcomes; --apply demotes")):
        pp = plsub.add_parser(name, help=hlp)
        pp.add_argument("--policy", required=True, help="policy history file (keyed, hash-chained)")
        pp.add_argument("--domain", default="", help="MAC domain ('<tenant>/policy' for service data)")
        if name in ("promote", "health"):
            pp.add_argument("--log", required=True)
            pp.add_argument("--labels", required=True)
        if name in ("promote", "demote"):
            pp.add_argument("--grader", required=True)
            pp.add_argument("--to", required=(name == "promote"), default="advisory")
            pp.add_argument("--reason", default="")
        if name == "promote":
            pp.add_argument("--override-reason", help="admin override: record why the evidence bar is waived")
        if name == "default":
            pp.add_argument("--mode", required=True)
            pp.add_argument("--reason", default="")
        if name in ("promote", "demote", "default"):
            pp.add_argument("--by", default=os.environ.get("USER", "operator"))
        if name == "health":
            pp.add_argument("--apply", action="store_true", help="demote unhealthy graders to advisory")

    pla = plsub.add_parser("archive", help="retention: move the oldest decisions to a verifiable archive "
                                           "segment (authorized deletion; live log stays tamper-evident)")
    pla.add_argument("--log", required=True)
    pla.add_argument("--domain", default="", help="MAC domain of the evidence (empty for CLI-made logs; "
                      "'<tenant>/pilot' (or '/policy') for data written by `verel serve-pilot`)")
    pla.add_argument("--keep-last", type=int, required=True)
    pla.add_argument("--segment", help="archive file to create (default: <log>.<UTC stamp>.archive)")
    plx = plsub.add_parser("repair", help="resolve an interrupted multi-record write left half-persisted by "
                                          "a power loss (drops only the unacknowledged records)")
    plx.add_argument("--log", required=True)
    plx.add_argument("--domain", default="", help="MAC domain of the evidence (empty for CLI-made logs; "
                      "'<tenant>/pilot' (or '/policy') for data written by `verel serve-pilot`)")
    plv = plsub.add_parser("verify", help="verify the decision log's hash chain (exit 2 if tampered)")
    plv.add_argument("--log", required=True)
    plv.add_argument("--domain", default="", help="MAC domain of the evidence (empty for CLI-made logs; "
                      "'<tenant>/pilot' (or '/policy') for data written by `verel serve-pilot`)")
    plv.add_argument("--segment", action="store_true", help="verify an archive segment (no head ledger)")
    plv.add_argument("--expect-head", default=None,
                     help="head hash recorded elsewhere; also detects tail truncation")

    va = sub.add_parser("verify-access",
                        help="OPT-IN: query what the cloud ACTUALLY grants (needs cloud read creds; "
                             "makes live provider calls — not an offline gate)")
    va.add_argument("--cloud", required=True, choices=("aws", "gcp", "azure"))
    va.add_argument("--policy-file", help="aws: an IAM policy JSON to validate (IAM Access Analyzer)")
    va.add_argument("--principal-arn",
                    help="aws: a role/user ARN to test EFFECTIVE access for (simulate-principal-policy)")
    va.add_argument("--action", nargs="+",
                    help="aws: action names to simulate (default: the privilege-escalation primitives)")
    va.add_argument("--scope", help="gcp: the analyze-iam-policy scope, e.g. projects/<id>")

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
    if args.cmd == "memory":
        return _memory(args)
    if args.cmd == "guard":
        return _guard(args)
    if args.cmd == "pilot":
        return _pilot(args)
    if args.cmd == "media":
        return _media(args)
    if args.cmd == "auth":
        return _auth(args)
    if args.cmd == "worker":
        return _worker(args)
    if args.cmd == "jobs":
        return _jobs(args)
    if args.cmd == "hotfolder":
        return _hotfolder(args)
    if args.cmd == "serve-pilot":
        return _serve_pilot(args)
    if args.cmd == "verify":
        return _verify(args)
    if args.cmd == "mcp":
        return _mcp(args)
    if args.cmd == "rules":
        return _rules(args)
    if args.cmd == "serve":
        return _serve(args)
    if args.cmd == "verify-access":
        return _verify_access(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
