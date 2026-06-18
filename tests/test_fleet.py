"""Fleet control plane (§6) — DAG validation, barriers, retry, budget, WAL resume, fan-out.
All offline with fake workers (no AgentVision / no LLM)."""

import asyncio

from verel.fleet import (
    Barrier,
    BarrierKind,
    BudgetLease,
    DagError,
    FanOut,
    RetryPolicy,
    Scheduler,
    Subtask,
    Task,
    TaskState,
    WorkerResult,
    clamp,
    plan_over_artifacts,
    to_tasks,
    validate_fanout,
)
from verel.verdict import Verdict

NO_SLEEP = lambda *_a, **_k: asyncio.sleep(0)


def _task(tid, deps=(), barrier=None, retry=None, artifact="x"):
    return Task(id=tid, deps=list(deps), barrier=barrier or Barrier(),
                retry=retry or RetryPolicy(max=1), artifact=artifact)


def _const_worker(verdicts):
    """verdicts: dict task_id -> list of verdicts to return across attempts."""
    calls = {}

    async def worker(task):
        i = calls.get(task.id, 0)
        calls[task.id] = i + 1
        seq = verdicts.get(task.id, [Verdict.PASS])
        v = seq[min(i, len(seq) - 1)]
        if v == "raise":
            raise RuntimeError("transient")
        return WorkerResult(verdict=v, tokens=100)

    worker.calls = calls
    return worker


def run(sched, tasks):
    return asyncio.run(sched.run(tasks))


# ---- DAG validation ----
def test_cycle_rejected():
    tasks = [_task("a", deps=["b"]), _task("b", deps=["a"])]
    try:
        Scheduler.validate(tasks)
        assert False, "expected DagError"
    except DagError:
        pass


def test_unknown_dep_rejected():
    try:
        Scheduler.validate([_task("a", deps=["ghost"])])
        assert False
    except DagError:
        pass


# ---- ordering & barriers ----
def test_all_pass_runs_dependents():
    w = _const_worker({"a": [Verdict.PASS], "b": [Verdict.PASS]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    state = run(sched, [_task("a"), _task("b", deps=["a"])])
    assert state["a"] == TaskState.PASSED and state["b"] == TaskState.PASSED


def test_all_barrier_skips_dependent_when_dep_fails():
    w = _const_worker({"a": [Verdict.FAIL], "b": [Verdict.PASS]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    state = run(sched, [_task("a"), _task("b", deps=["a"])])
    assert state["a"] == TaskState.QUARANTINED
    assert state["b"] == TaskState.SKIPPED  # dead dep -> unreachable


def test_optional_barrier_runs_despite_failed_dep():
    w = _const_worker({"a": [Verdict.FAIL], "b": [Verdict.PASS]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    b = _task("b", deps=["a"], barrier=Barrier(kind=BarrierKind.OPTIONAL))
    state = run(sched, [_task("a"), b])
    assert state["b"] == TaskState.PASSED


def test_k_of_n_barrier():
    w = _const_worker({"a": [Verdict.PASS], "b": [Verdict.FAIL], "c": [Verdict.PASS]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    c = _task("c", deps=["a", "b"], barrier=Barrier(kind=BarrierKind.K_OF_N, k=1))
    state = run(sched, [_task("a"), _task("b"), c])
    assert state["c"] == TaskState.PASSED  # 1 of 2 deps passed >= k=1


# ---- retry / quarantine ----
def test_retry_then_success():
    w = _const_worker({"a": ["raise", Verdict.PASS]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    state = run(sched, [_task("a", retry=RetryPolicy(max=3, backoff_s=[0]))])
    assert state["a"] == TaskState.PASSED and w.calls["a"] == 2


def test_persistent_failure_quarantined():
    w = _const_worker({"a": [Verdict.FAIL]})
    sched = Scheduler(w, sleep=NO_SLEEP)
    state = run(sched, [_task("a", retry=RetryPolicy(max=2, backoff_s=[0], on_fail="quarantine"))])
    assert state["a"] == TaskState.QUARANTINED and w.calls["a"] == 2


# ---- budget ----
def test_budget_skips_remaining():
    w = _const_worker({"a": [Verdict.PASS], "b": [Verdict.PASS]})
    sched = Scheduler(w, budget=BudgetLease(max_tokens=100), concurrency=1, sleep=NO_SLEEP)
    state = run(sched, [_task("a"), _task("b")])
    passed = sum(v == TaskState.PASSED for v in state.values())
    skipped = sum(v == TaskState.SKIPPED for v in state.values())
    assert passed == 1 and skipped == 1  # first consumes the lease, second is skipped


# ---- WAL resume ----
def test_wal_resume_memoizes_passed(tmp_path):
    wal = tmp_path / "wal.jsonl"
    w1 = _const_worker({"a": [Verdict.PASS], "b": [Verdict.FAIL]})
    s1 = Scheduler(w1, wal_path=wal, sleep=NO_SLEEP)
    run(s1, [_task("a"), _task("b", retry=RetryPolicy(max=1))])
    # second run: a should be memoized (not re-run); b re-runs and now passes
    w2 = _const_worker({"a": [Verdict.FAIL], "b": [Verdict.PASS]})
    s2 = Scheduler(w2, wal_path=wal, sleep=NO_SLEEP)
    state = run(s2, [_task("a"), _task("b", retry=RetryPolicy(max=1))])
    assert state["a"] == TaskState.PASSED and "a" not in w2.calls  # memoized, not re-run
    assert state["b"] == TaskState.PASSED


# ---- manager fan-out ----
def test_fanout_validation_rejects_dependent_subtasks():
    fo = FanOut(subtasks=[Subtask(id="x"), Subtask(id="y", deps=["x"])])
    ok, reason = validate_fanout(fo)
    assert not ok and "independent" in reason


def test_fanout_accepts_antichain_and_clamps_concurrency():
    fo = clamp(FanOut(subtasks=[Subtask(id="x"), Subtask(id="y")], concurrency_cap=99))
    ok, _ = validate_fanout(fo)
    assert ok and fo.concurrency_cap == 2


def test_plan_over_artifacts_is_independent():
    fo = plan_over_artifacts("fix pages", ["a.html", "b.html", "c.html"])
    ok, _ = validate_fanout(fo)
    tasks = to_tasks(fo)
    assert ok and len(tasks) == 3 and all(not t.deps for t in tasks)
