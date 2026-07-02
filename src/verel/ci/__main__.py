"""`python -m verel.ci` — the CLI agents (and git hooks) invoke for gated CI (§7.4).

Subcommands:
  precommit --repo PATH   run the pre-commit stage; exit non-zero on FAIL (aborts a commit)
  check     --repo PATH   run the inner-loop stage and print the verdict
  iac       --repo PATH   grade a terraform plan / K8s manifests (drift + cloud-IAM sensor), offline
  telecom   --repo PATH   grade 5G PM counters (--kpi) against declared thresholds (--thresholds), offline
  telecom-cfg --repo PATH grade a 5G-Core config artifact (--values) against declared invariants, offline
  install   --repo PATH   install the pre-commit hook
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
            for i in r.issues[:10]:
                print(f"      {i.source.value}:{i.severity.value} {i.locator or ''} {i.message[:80]}")
    if result.regressions:
        print(f"  ! {len(result.regressions)} reintroduced failure(s) blocked from memory")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="verel.ci")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("precommit", "check"):
        sp = sub.add_parser(name)
        sp.add_argument("--repo", required=True)
        sp.add_argument("--no-lint", action="store_true")
    sp = sub.add_parser("iac")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--plan", help="a `terraform show -json` plan file (in the repo)")
    sp.add_argument("--manifests", help="Kubernetes manifests as JSON, e.g. `kubectl -o json` (in the repo)")

    sp = sub.add_parser("telecom")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--kpi", help="a metrics artifact in the repo (JSON / CSV / OpenMetrics scrape)")
    sp.add_argument("--thresholds", help="declared KPI thresholds (YAML file in the repo)")
    sp.add_argument("--baseline", help="optional baseline metrics artifact for delta-vs-baseline gating")
    sp.add_argument("--fmt", default="auto", choices=["auto", "json", "csv", "openmetrics", "pmxml"])
    sp.add_argument("--mapping", help="vendor PM-counter mapping: a built-in name ('open5gs') or a "
                    "repo-relative YAML path mapping vendor counter names → canonical TS 28.552")
    sp.add_argument("--attest", default="hmac", choices=["hmac", "ed25519"])

    sp = sub.add_parser("telecom-cfg")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--values", help="an Open5GS-shaped Helm-values artifact in the repo")
    sp.add_argument("--rules", help="declared invariants (verel_telecom.yaml); default: all built-ins")
    sp.add_argument("--attest", default="hmac", choices=["hmac", "ed25519"])

    sp = sub.add_parser("install")
    sp.add_argument("--repo", required=True)

    args = p.parse_args(argv)
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
