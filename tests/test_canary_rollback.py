"""Post-merge canary + verdict-driven rollback (§7.4) — real git, injected graders."""

import subprocess

import pytest

from verel.ci import (
    RollbackExecutor,
    RollbackProposal,
    Stage,
    canary_rollback,
    postmerge_stage,
)
from verel.ci.graders import pytest_spec
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign


def _git(path, *a):
    subprocess.run(["git", "-C", str(path), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "user.email", "t@t")
    (r / "app.py").write_text("VALUE = 1\n")
    _git(r, "add", "-A")
    _git(r, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "good")
    # a 'bad merge' commit on top
    (r / "app.py").write_text("VALUE = 999  # regression\n")
    _git(r, "add", "-A")
    _git(r, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "bad")
    return r


def _precise_fail_report():
    return assign(Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.TEST,
                         issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR,
                                       source=GraderKind.TEST, message="smoke failed", locator="t")]))


def _advisory_fail_report():
    return assign(Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.VISION,
                         issues=[Issue(kind=IssueKind.LAYOUT, severity=Severity.ERROR,
                                       source=GraderKind.VISION, message="looks off", locator="x")]))


# ---- executor ----
def test_executor_reverts_on_precise_evidence(repo):
    rep = _precise_fail_report()
    fp = rep.issues[0].fingerprint
    before = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    out = RollbackExecutor().maybe_rollback(str(repo), RollbackProposal("canary", "HEAD~1", [fp]), [rep])
    assert out.executed and out.reverted_sha == before and out.new_sha != before
    # the revert restored the good value
    assert (repo / "app.py").read_text().strip().startswith("VALUE = 1")


def test_executor_refuses_advisory_only(repo):
    rep = _advisory_fail_report()
    fp = rep.issues[0].fingerprint
    out = RollbackExecutor().maybe_rollback(str(repo), RollbackProposal("vibes", "HEAD~1", [fp]), [rep])
    assert not out.executed and "advisory" in out.decision.reason
    assert (repo / "app.py").read_text().strip().startswith("VALUE = 999")  # unchanged


# ---- canary orchestration (injected runner) ----
SMOKE_FAIL = "FAILED test_smoke.py::test_value - assert 999 == 1\n1 failed\n"


def test_canary_passes_no_rollback(repo):
    stage = Stage("post_merge", [pytest_spec(str(repo))], required={GraderKind.TEST})
    res = canary_rollback(str(repo), stage, runner=lambda c, cwd=None: (0, "", ""))
    assert res.healthy and not res.rolled_back


def test_canary_failure_triggers_rollback(repo):
    stage = Stage("post_merge", [pytest_spec(str(repo))], required={GraderKind.TEST})
    res = canary_rollback(str(repo), stage, runner=lambda c, cwd=None: (1, SMOKE_FAIL, ""))
    assert res.verdict == Verdict.FAIL and res.rolled_back
    assert (repo / "app.py").read_text().strip().startswith("VALUE = 1")  # auto-reverted


def test_postmerge_stage_shape(repo):
    stage = postmerge_stage(str(repo), smoke_paths=["test_smoke.py"])
    assert stage.name.startswith("post_merge") and GraderKind.TEST in stage.required
