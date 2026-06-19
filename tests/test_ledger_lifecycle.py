"""Failure-ledger × memory lifecycle: transient/flaky → volatile (self-clean), fixed → pinned."""

from verel.ci import Stage, run_stage
from verel.ci.graders import pytest_spec
from verel.memory import FailureLedger, LocalMemory, MemoryKind, is_pinned, is_volatile
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign

DAY = 24 * 3600.0


def _report(msg, fp_seed, kind=IssueKind.OTHER, source=GraderKind.TEST):
    r = Report(verdict=Verdict.FAIL, summary="", grader=source,
               issues=[Issue(kind=kind, severity=Severity.ERROR, source=source,
                             message=msg, locator=fp_seed)])
    return assign(r)


# ---- ledger.record(volatile_fingerprints=...) marks those volatile ----
def test_transient_failure_recorded_volatile_and_self_cleans():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    rep = _report("connection reset by peer", ".net")
    fps = [i.fingerprint for r in [rep] for i in r.issues]
    led.record(rep, volatile_fingerprints=set(fps))
    rec = mem.get(led.mem_id(fps[0]))
    assert is_volatile(rec)                       # transient → volatile
    assert mem.decay(now=3 * DAY) == 1            # unconfirmed → expires from failure-memory
    assert mem.get(led.mem_id(fps[0])) is None


def test_recurring_transient_is_confirmed_and_kept():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    rep = _report("connection reset by peer", ".net")
    fps = {i.fingerprint for i in rep.issues}
    led.record(rep, volatile_fingerprints=fps)
    led.record(rep, volatile_fingerprints=fps)    # recurrence re-asserts -> confirms (clears volatile)
    rec = mem.get(led.mem_id(next(iter(fps))))
    assert not is_volatile(rec)
    assert mem.decay(now=3 * DAY) == 0 and mem.get(led.mem_id(next(iter(fps)))) is not None


# ---- mark_fixed pins the record (permanent regression-guard knowledge) ----
def test_fixed_failure_is_pinned_and_survives_decay():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    rep = _report("assert 1 == 2", ".bug")
    fps = led.record(rep)
    led.mark_fixed(fps)
    rec = mem.get(led.mem_id(fps[0]))
    assert is_pinned(rec) and rec.detail.get("status") == "fixed"
    # even a decade of decay can't evict it -> regression guard still works later
    assert mem.decay(now=3650 * DAY) == 0
    assert mem.get(led.mem_id(fps[0])) is not None
    # and it still fires the regression guard when reintroduced
    assert led.check_regressions(_report("assert 1 == 2", ".bug"))


# ---- run_stage wires medic classification into volatility ----
def test_run_stage_marks_transient_failures_volatile():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    stage = Stage("inner_loop", [pytest_spec("/repo")], required={GraderKind.TEST})
    # a transient (infra) failure message -> medic RETRY -> volatile
    OUT = "FAILED tests/test_net.py::test_x - ConnectionResetError: connection reset\n1 failed\n"
    run_stage(stage, diff_files={"a.py"}, runner=lambda c, cwd=None: (1, OUT, ""), ledger=led)
    fails = mem.all(kind=MemoryKind.FAILURE)
    assert fails and all(is_volatile(f) for f in fails)  # transient failure stored volatile


def test_run_stage_genuine_failure_not_volatile():
    mem = LocalMemory()
    led = FailureLedger(mem, scope="repo:x")
    stage = Stage("inner_loop", [pytest_spec("/repo")], required={GraderKind.TEST})
    OUT = "FAILED tests/test_logic.py::test_y - assert 401 == 200\n1 failed\n"
    run_stage(stage, diff_files={"a.py"}, runner=lambda c, cwd=None: (1, OUT, ""), ledger=led)
    fails = mem.all(kind=MemoryKind.FAILURE)
    assert fails and not any(is_volatile(f) for f in fails)  # genuine regression persists
