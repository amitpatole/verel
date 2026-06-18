"""Agent-run CI/CD (§7.4) — graders, pipeline gating, failure-memory, medic, rollback.
Offline: the command runner is injected with canned tool output."""

from verel.ci import (
    Action,
    GraderSpec,
    RollbackPolicy,
    RollbackProposal,
    Stage,
    classify_issue,
    inner_loop_stage,
    parse_mypy,
    parse_pytest,
    parse_ruff,
    pytest_spec,
    quarantine_severity,
    run_grader,
    run_stage,
    ruff_spec,
    triage,
)
from verel.memory import FailureLedger, LocalMemory
from verel.verdict import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign

PYTEST_OUT = """\
F.F
FAILED tests/test_x.py::test_login - assert 401 == 200
FAILED tests/test_y.py::test_logout - KeyError: 'token'
2 failed, 1 passed
"""
RUFF_OUT = "src/a.py:10:5: F401 `os` imported but unused\nsrc/b.py:3:1: E302 expected 2 blank lines\n"
MYPY_OUT = 'src/a.py:42: error: Incompatible return value type [return-value]\n'


def _runner(rc, out, err=""):
    return lambda cmd, cwd=None: (rc, out, err)


# ---- parsers ----
def test_parse_pytest():
    issues = parse_pytest(PYTEST_OUT)
    assert len(issues) == 2
    assert issues[0].source == GraderKind.TEST and issues[0].detail["test_id"].endswith("test_login")


def test_parse_ruff_and_mypy():
    assert parse_ruff(RUFF_OUT)[0].detail["rule_id"] == "F401"
    assert parse_mypy(MYPY_OUT)[0].source == GraderKind.TYPECHECK


# ---- grader produces an attested report ----
def test_grader_failures_gate_and_are_attested():
    spec = pytest_spec("/repo", covers=["src/a.py"])
    rep = run_grader(spec, _runner(1, PYTEST_OUT))
    assert rep.grader == GraderKind.TEST and rep.verdict == Verdict.FAIL
    assert rep.run_receipt is not None and not rep.errored
    assert all(i.fingerprint for i in rep.issues)  # §7.2 fingerprints assigned


def test_missing_tool_is_errored_not_pass():
    def boom(cmd, cwd=None):
        raise FileNotFoundError("pytest")
    rep = run_grader(pytest_spec("/repo"), boom)
    assert rep.errored and rep.verdict == Verdict.FAIL  # no silent green


def test_clean_run_passes():
    rep = run_grader(ruff_spec("/repo", covers=["src/a.py"]), _runner(0, ""))
    assert rep.verdict == Verdict.PASS and not rep.issues


# ---- stage gating with attestation ----
def test_stage_passes_when_required_grader_attested_and_clean():
    repo = "/repo"
    stage = inner_loop_stage(repo, covers=["src/a.py"], with_lint=False)
    res = run_stage(stage, diff_files={"src/a.py"}, runner=_runner(0, ""))
    assert res.passed


def test_stage_fails_on_test_errors():
    stage = inner_loop_stage("/repo", covers=["src/a.py"], with_lint=False)
    res = run_stage(stage, diff_files={"src/a.py"}, runner=_runner(1, PYTEST_OUT))
    assert res.verdict == Verdict.FAIL


# ---- failure-memory in pre-commit ----
def test_precommit_blocks_reintroduced_failure_from_memory():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    stage = Stage("pre_commit", [pytest_spec("/repo", covers=["src/a.py"])], required={GraderKind.TEST})

    # run 1: failures recorded
    r1 = run_stage(stage, diff_files={"src/a.py"}, runner=_runner(1, PYTEST_OUT), ledger=led)
    fps = [i.fingerprint for rep in r1.reports for i in rep.issues]
    led.mark_fixed(fps)  # the fix landed

    # run 2: the SAME failures come back -> regression guard fires from memory
    r2 = run_stage(stage, diff_files={"src/a.py"}, runner=_runner(1, PYTEST_OUT), ledger=led)
    assert r2.regressions and r2.verdict == Verdict.FAIL


# ---- ci-medic ----
def _issue(msg, fp="fp1"):
    i = Issue(kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TEST, message=msg)
    i.fingerprint = fp
    return i


def test_medic_classifies():
    assert classify_issue(_issue("Connection reset by peer")).action == Action.RETRY
    assert classify_issue(_issue("ModuleNotFoundError: no module named foo")).action == Action.REGEN_LOCKFILE
    assert classify_issue(_issue("assert 1 == 2")).action == Action.FIX_BRANCH
    assert classify_issue(_issue("x", fp="flk"), flaky_signatures={"flk"}).action == Action.QUARANTINE_FLAKY


def test_flaky_quarantine_downgrades_not_deletes():
    assert quarantine_severity(_issue("x")) == Severity.WARNING


# ---- rollback policy engine ----
def _report(source, fp, sev=Severity.ERROR):
    return assign(Report(verdict=Verdict.FAIL, summary="", grader=source,
                         issues=[Issue(kind=IssueKind.OTHER, severity=sev, source=source,
                                       message="m", locator="x", fingerprint=fp)]))


def test_rollback_allowed_on_precise_evidence():
    rep = _report(GraderKind.TEST, "f1")
    fp = rep.issues[0].fingerprint
    d = RollbackPolicy().decide(RollbackProposal("regression", "abc123", [fp]), [rep])
    assert d.allow and fp in d.precise_support


def test_rollback_denied_on_advisory_only():
    rep = _report(GraderKind.VISION, "v1")
    fp = rep.issues[0].fingerprint
    d = RollbackPolicy().decide(RollbackProposal("looks broken", "abc123", [fp]), [rep])
    assert not d.allow and "advisory" in d.reason


def test_rollback_denied_without_evidence():
    d = RollbackPolicy().decide(RollbackProposal("vibes", "abc", ["nope"]), [])
    assert not d.allow
