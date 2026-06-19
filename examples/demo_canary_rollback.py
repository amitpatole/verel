"""Post-merge canary → automated, safe rollback (§7.4) — real git, no API key.

A 'good' commit, then a 'bad' commit that breaks the smoke test. The canary runs the real
pytest grader; on a PRECISE failure the policy engine authorizes a rollback and the executor
performs a safe `git revert`. Then we show an ADVISORY-only failure being refused — a
destructive action never rides on a vision/LLM opinion.

Run:  python examples/demo_canary_rollback.py
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from verel.ci import RollbackExecutor, RollbackProposal, Stage, canary_rollback
from verel.ci.graders import pytest_spec
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign

SMOKE = "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 1\n"


def git(r, *a):
    subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True)


def head(r):
    return subprocess.run(["git", "-C", str(r), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / "test_smoke.py").write_text(SMOKE)
        (r / "app.py").write_text("VALUE = 1\n")
        git(r, "init", "-q"); git(r, "config", "user.name", "t"); git(r, "config", "user.email", "t@t")
        git(r, "add", "-A"); git(r, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "good")
        (r / "app.py").write_text("VALUE = 999  # regression slipped through\n")
        git(r, "add", "-A"); git(r, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "bad merge")

        stage = Stage("post_merge", [pytest_spec(str(r))], required={GraderKind.TEST})

        print(f"── Canary on the merged code (HEAD={head(r)}, VALUE=999) ──")
        res = canary_rollback(str(r), stage)
        print(f"  canary verdict={res.verdict.value}  rolled_back={res.rolled_back}")
        if res.rollback:
            print(f"  policy: {res.rollback.decision.reason[:70]}")
            print(f"  reverted {res.rollback.reverted_sha[:7]} → new HEAD {head(r)}")
        print(f"  app.py now: {(r / 'app.py').read_text().strip()}")

        print("\n── Re-run canary after the auto-revert ──")
        res2 = canary_rollback(str(r), stage)
        print(f"  canary verdict={res2.verdict.value}  (healthy={res2.healthy})")

        print("\n── An ADVISORY-only failure must NOT trigger a destructive revert ──")
        adv = assign(Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.VISION,
                            issues=[Issue(kind=IssueKind.LAYOUT, severity=Severity.ERROR,
                                          source=GraderKind.VISION, message="looks off", locator="x")]))
        fp = adv.issues[0].fingerprint
        before = head(r)
        out = RollbackExecutor().maybe_rollback(str(r), RollbackProposal("vibes", "HEAD~1", [fp]), [adv])
        print(f"  executed={out.executed}  reason={out.decision.reason[:70]}")
        print(f"  HEAD unchanged: {before == head(r)}")

        ok = res.rolled_back and res2.healthy and not out.executed
        print("\nResult:", "PASS — bad merge auto-reverted on precise evidence; advisory-only "
              "refused" if ok else "NOT MET")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
