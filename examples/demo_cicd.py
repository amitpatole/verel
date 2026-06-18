"""Agent-run CI/CD demo (§7.4) — real graders on the verdict bus, no LLM needed.

Spins a tiny temp project with a failing test, runs Verel's inner-loop stage with the REAL
pytest grader, watches the verdict bus gate it FAIL, "fixes" the code, re-gates to PASS, and
demonstrates the ci-medic classification + the rollback policy engine refusing to act on
advisory evidence. This is CI run by the same verdict bus that gates everything else.

Run:  python examples/demo_cicd.py     (uses your current python+pytest; no API key)
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from verel.ci import (
    RollbackPolicy,
    RollbackProposal,
    inner_loop_stage,
    run_stage,
    triage,
)
from verel.memory import FailureLedger, LocalMemory

SRC = "def add(a, b):\n    return {body}\n"
TEST = "from app import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"


def _run_pytest_stage(repo: Path, ledger):
    stage = inner_loop_stage(str(repo), covers=["app.py"], with_lint=False)
    return run_stage(stage, diff_files={"app.py"}, ledger=ledger, ts=1.0)


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "test_app.py").write_text(TEST)
        mem = LocalMemory(repo / "mem.sqlite")
        ledger = FailureLedger(mem, scope="repo:demo")

        print("── Inner loop (real pytest grader) on a BROKEN implementation ──")
        (repo / "app.py").write_text(SRC.format(body="a - b"))  # bug
        r1 = _run_pytest_stage(repo, ledger)
        print(f"  verdict={r1.verdict.value}")
        for rep in r1.reports:
            for i in rep.issues:
                print(f"    {i.source.value}:{i.severity.value} {i.locator} — {i.message[:60]}")
                d_ = triage(rep)[0]
                print(f"    ci-medic → {d_.action.value} ({d_.rationale})")

        print("\n── Agent fixes app.py, re-gate ──")
        (repo / "app.py").write_text(SRC.format(body="a + b"))  # fixed
        r2 = _run_pytest_stage(repo, ledger)
        print(f"  verdict={r2.verdict.value}")

        print("\n── Rollback policy engine (agent proposes; engine disposes) ──")
        # propose a rollback citing the (now-fixed) precise test failure
        fps = [i.fingerprint for rep in r1.reports for i in rep.issues]
        good = RollbackPolicy().decide(RollbackProposal("test regression", "HEAD~1", fps), r1.reports)
        print(f"  cite precise TEST failure → allow={good.allow} ({good.reason[:70]})")
        # an advisory-only proposal is refused
        from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign
        adv = assign(Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.VISION,
                            issues=[Issue(kind=IssueKind.LAYOUT, severity=Severity.ERROR,
                                          source=GraderKind.VISION, message="looks off", fingerprint="v")]))
        bad = RollbackPolicy().decide(RollbackProposal("vibes", "HEAD~1", ["v"]), [adv])
        print(f"  cite ADVISORY vision only → allow={bad.allow} ({bad.reason[:70]})")

        ok = r1.verdict.value == "fail" and r2.passed and good.allow and not bad.allow
        print("\nResult:", "PASS — CI gated FAIL→PASS on real tests; rollback honored "
              "precise-only evidence" if ok else "NOT MET")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
