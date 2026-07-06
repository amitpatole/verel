"""`python -m verel.ci` — the CLI agents (and git hooks) invoke for gated CI (§7.4).

Subcommands (see `verel-ci <command> --help`):
  precommit     --repo PATH   run the pre-commit stage; exit non-zero on FAIL (aborts a commit)
  check         --repo PATH   run the inner-loop stage and print the verdict
  iac           --repo PATH   grade a terraform plan / K8s manifests (drift + cloud-IAM sensor), offline
  telecom       --repo PATH   grade 5G PM counters (--kpi) against declared thresholds, offline
  telecom-cfg   --repo PATH   grade a 5G Core+RAN config artifact (--values) against invariants, offline
  telecom-fetch --url URL     scrape Prometheus/PromQL → a metrics file (network-facing acquisition)
  telecom-apply --repo PATH   act-then-verify a config change (dry-run unless --apply), guardrail-gated
  install       --repo PATH   install the pre-commit hook
"""

from __future__ import annotations

import argparse
import sys

from ..verdict.models import Verdict
from .hooks import install_precommit
from .pipeline import inner_loop_stage, precommit_stage, run_stage


def _print(result):
    print(f"[{result.name}] verdict={result.verdict.value}")
    for r in result.reports:
        if r.issues or r.errored:
            tag = "ERRORED" if r.errored else f"{len(r.issues)} issue(s)"
            print(f"  - {r.grader.value}: {tag}")
            # An errored grader has no issues to show — print WHY it errored (tool missing, bad path,
            # no tests) so the user isn't left staring at a bare "ERRORED" (adoption audit P0).
            if r.errored and r.summary:
                print(f"      {r.summary}")
            for i in r.issues[:10]:
                print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:80]}")
    # Surface the gate's overall reason on any non-pass (e.g. "required grader(s) absent/errored: lint").
    gate = getattr(result, "gate", None)
    if gate is not None and getattr(gate, "reason", "") and result.verdict.value != "pass":
        print(f"  → {gate.reason}")
    if result.regressions:
        print(f"  ! {len(result.regressions)} reintroduced failure(s) blocked from memory")


def _telecom_apply(args) -> int:
    """DRY-RUN by default: plan (grade desired + classify change) and print. With --apply: guarded live
    NETCONF apply (confirmed-commit + post-verify + auto-rollback)."""
    from .telecom_actuator import TelecomActuator

    edit = None
    if args.edit_config:
        try:
            with open(args.edit_config, encoding="utf-8") as f:
                edit = f.read()
        except OSError as e:
            print(f"telecom-apply: cannot read --edit-config: {e}", file=sys.stderr)
            return 2
    act = TelecomActuator(args.repo, rules=args.rules)
    try:
        plan = act.plan(current=args.current, desired=args.desired, edit_config=edit or "",
                        confirm_timeout=args.confirm_timeout)
    except (ValueError, FileNotFoundError) as e:
        print(f"telecom-apply: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(f"[telecom-apply] plan: action={plan.action.value} verdict={plan.report.verdict.value}")
    for r in plan.reasons[:20]:
        print(f"  change: {r}")
    if not args.apply:
        print("  dry-run (no --apply) — nothing was changed. Re-run with --apply to execute.")
        return 0 if plan.report.verdict.value != "fail" else 1
    if not (args.host and args.user and edit):
        print("telecom-apply --apply needs --host, --user, and --edit-config", file=sys.stderr)
        return 2
    from .telecom_actuator import ncclient_session
    try:
        session = ncclient_session(args.host, port=args.port, username=args.user)
    except RuntimeError as e:
        print(f"telecom-apply: {e}", file=sys.stderr)
        return 2
    try:
        res = act.act(plan, session=session, approved=args.i_understand)
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    print(f"[telecom-apply] {'OK' if res.ok else 'REFUSED/FAILED'}: {res.detail}"
          + (" (rolled back)" if res.rolled_back else ""))
    return 0 if res.ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="verel-ci",
        description="Verel CI gate — grade a repo/artifact into one signed pass/warn/fail verdict.")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")
    for name, _help in (("precommit", "grade the pre-commit stage (tests/lint/types) over a repo"),
                        ("check", "grade the inner-loop stage over a repo")):
        sp = sub.add_parser(name, help=_help)
        sp.add_argument("--repo", required=True)
        sp.add_argument("--no-lint", action="store_true")
    sp = sub.add_parser("iac", help="grade a Terraform plan / K8s manifests (IaC + cloud-IAM + RBAC)")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--plan", help="a `terraform show -json` plan file (in the repo)")
    sp.add_argument("--manifests", help="Kubernetes manifests as JSON, e.g. `kubectl -o json` (in the repo)")

    sp = sub.add_parser("telecom", help="grade 5G PM-counter KPIs against declared thresholds")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--kpi", help="a metrics artifact in the repo (JSON / CSV / OpenMetrics scrape)")
    sp.add_argument("--thresholds", help="declared KPI thresholds (YAML file in the repo)")
    sp.add_argument("--baseline", help="optional baseline metrics artifact for delta-vs-baseline gating")
    sp.add_argument("--fmt", default="auto", choices=["auto", "json", "csv", "openmetrics", "pmxml"])
    sp.add_argument("--mapping", help="vendor PM-counter mapping: a built-in name ('open5gs') or a "
                    "repo-relative YAML path mapping vendor counter names → canonical TS 28.552")
    sp.add_argument("--attest", default="hmac", choices=["hmac", "ed25519"])

    sp = sub.add_parser("telecom-cfg",
                        help="grade declared 5G Core+RAN config invariants (Helm/NETCONF/bulk-CM)")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--values", help="an Open5GS-shaped Helm-values artifact in the repo")
    sp.add_argument("--rules", help="declared invariants (verel_telecom.yaml); default: all built-ins")
    sp.add_argument("--attest", default="hmac", choices=["hmac", "ed25519"])

    sp = sub.add_parser("telecom-fetch",  # acquisition helper: talks to the network, writes a file
                        help="scrape Prometheus/PromQL → a metrics file (network-facing; grader offline)")
    sp.add_argument("--url", required=True, help="Prometheus /metrics endpoint, or the server base URL "
                    "when --query is given")
    sp.add_argument("--out", required=True, help="write the metrics artifact here (grade with telecom --kpi)")
    sp.add_argument("--query", help="PromQL instant query (uses the HTTP API; output is JSON)")
    sp.add_argument("--timeout", type=float, default=15.0)
    sp.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    sp.add_argument("--insecure", action="store_true", help="disable TLS verification (discouraged)")
    sp.add_argument("--allow-link-local", action="store_true",
                    help="permit link-local targets (169.254/fe80) — bypasses the cloud-metadata SSRF guard")

    sp = sub.add_parser("telecom-apply",  # act-then-verify a config change; DRY-RUN unless --apply
                        help="apply a 5G config change, act-then-verify guardrails (dry-run unless --apply)")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--desired", required=True, help="the target config artifact (graded pre-flight)")
    sp.add_argument("--current", required=True, help="current config artifact (for change classification)")
    sp.add_argument("--edit-config", help="NETCONF edit-config payload file (required for a live --apply)")
    sp.add_argument("--rules", help="declared invariants (verel_telecom.yaml)")
    sp.add_argument("--confirm-timeout", type=int, default=120, help="confirmed-commit rollback window (s)")
    sp.add_argument("--apply", action="store_true", help="LIVE apply (else dry-run/plan only)")
    sp.add_argument("--i-understand", action="store_true", help="approve an IRREVERSIBLE change")
    sp.add_argument("--host", help="NETCONF host (live apply)")
    sp.add_argument("--port", type=int, default=830)
    sp.add_argument("--user", help="NETCONF SSH user (live apply); creds from env/agent, never the repo")

    sp = sub.add_parser("install", help="install the Verel pre-commit hook into a repo")
    sp.add_argument("--repo", required=True)

    args = p.parse_args(argv)
    if args.cmd == "telecom-apply":
        return _telecom_apply(args)
    if args.cmd == "telecom-fetch":
        from .telecom_fetch import FetchError, query_prometheus, scrape
        try:
            kw = {"timeout": args.timeout, "max_bytes": args.max_bytes,
                  "verify_tls": not args.insecure, "allow_link_local": args.allow_link_local}
            out = query_prometheus(args.url, args.query, **kw) if args.query else scrape(args.url, **kw)
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        except FetchError as e:
            print(f"telecom-fetch: {e}", file=sys.stderr)
            return 2
        print(f"telecom-fetch: wrote {args.out} ({len(out)} bytes) — grade with "
              f"`verel-ci telecom --kpi {args.out}`{' --fmt json' if args.query else ' --fmt openmetrics'}")
        return 0
    if args.cmd == "install":
        print(f"installed: {install_precommit(args.repo)}")
        return 0

    if args.cmd == "iac":
        from .k8s import grade_iac
        if not args.plan and not args.manifests:
            print("iac: provide --plan and/or --manifests", file=sys.stderr)
            return 2
        try:
            rep = grade_iac(args.repo, plan=args.plan, manifests=args.manifests)
        except (ValueError, FileNotFoundError, RecursionError, MemoryError) as e:
            print(f"iac: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        print(f"[iac] verdict={rep.verdict.value}")
        for i in rep.issues[:50]:
            print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:80]}")
        return 0 if rep.verdict != Verdict.FAIL else 1

    if args.cmd == "telecom":
        from .telecom_kpi import grade_kpi
        if not args.kpi or not args.thresholds:
            print("telecom: provide --kpi <metrics> and --thresholds <yaml>", file=sys.stderr)
            return 2
        try:
            rep = grade_kpi(args.repo, metrics=args.kpi, thresholds=args.thresholds,
                            baseline=args.baseline, fmt=args.fmt, mapping=args.mapping,
                            attest=args.attest)
        except (ValueError, FileNotFoundError, RecursionError, MemoryError) as e:
            print(f"telecom: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        print(f"[telecom:kpi] verdict={rep.verdict.value}")
        for i in rep.issues[:50]:
            print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:100]}")
        if rep.run_receipt:
            kind = "publicly verifiable" if rep.run_receipt.alg == "ed25519" else "shared-secret"
            print(f"  receipt: alg={rep.run_receipt.alg} ({kind})")
        return 0 if rep.verdict != Verdict.FAIL else 1

    if args.cmd == "telecom-cfg":
        from .telecom_cfg import grade_cfg
        if not args.values:
            print("telecom-cfg: provide --values <helm-values artifact>", file=sys.stderr)
            return 2
        try:
            rep = grade_cfg(args.repo, values=args.values, rules=args.rules, attest=args.attest)
        except (ValueError, FileNotFoundError, RecursionError, MemoryError) as e:
            print(f"telecom-cfg: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        print(f"[telecom:cfg] verdict={rep.verdict.value}")
        for i in rep.issues[:50]:
            print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:110]}")
        return 0 if rep.verdict != Verdict.FAIL else 1

    stage = (precommit_stage(args.repo) if args.cmd == "precommit"
             else inner_loop_stage(args.repo, with_lint=not args.no_lint))
    result = run_stage(stage)
    _print(result)
    return 0 if result.verdict != Verdict.FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
