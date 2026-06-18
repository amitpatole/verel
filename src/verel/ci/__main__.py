"""`python -m verel.ci` — the CLI agents (and git hooks) invoke for gated CI (§7.4).

Subcommands:
  precommit --repo PATH   run the pre-commit stage; exit non-zero on FAIL (aborts a commit)
  check     --repo PATH   run the inner-loop stage and print the verdict
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
    sp = sub.add_parser("install")
    sp.add_argument("--repo", required=True)

    args = p.parse_args(argv)
    if args.cmd == "install":
        print(f"installed: {install_precommit(args.repo)}")
        return 0

    stage = (precommit_stage(args.repo) if args.cmd == "precommit"
             else inner_loop_stage(args.repo, with_lint=not args.no_lint))
    result = run_stage(stage)
    _print(result)
    return 0 if result.verdict != Verdict.FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
