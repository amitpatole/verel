"""Distributed/fleet hardening (§6.3) — fencing leases + concurrent schedulers + multi-repo.
Offline with fake workers; the sqlite store uses a tmp file."""

import asyncio

import pytest

from verel.fleet import (
    CrossDep,
    FencingError,
    InMemoryLeaseStore,
    Scheduler,
    SqliteLeaseStore,
    Task,
    TaskState,
    WorkerResult,
    plan_multi_repo,
    repo_of,
)
from verel.fleet.task import RetryPolicy
from verel.verdict import Verdict

NO_SLEEP = lambda *_a, **_k: asyncio.sleep(0)  # noqa: E731


def _t(tid, deps=()):
    return Task(id=tid, deps=list(deps), retry=RetryPolicy(max=1, backoff_s=[]))


# ====================================================================== fencing
@pytest.mark.parametrize("store", [InMemoryLeaseStore(), None])
def test_fencing_token_takeover_and_stale_write(store, tmp_path):
    s = store or SqliteLeaseStore(tmp_path / "lease.db")
    a = s.acquire("T", "A", now=0.0, ttl=10.0)
    assert a is not None and a.token == 1
    # a live, different owner cannot acquire
    assert s.acquire("T", "B", now=1.0, ttl=10.0) is None
    # after expiry, B takes over with a HIGHER token
    b = s.acquire("T", "B", now=20.0, ttl=10.0)
    assert b is not None and b.token == 2 and s.current_token("T") == 2
    # the stale leader's terminal write is FENCED
    with pytest.raises(FencingError):
        s.complete(a, "passed")
    # the current holder's write succeeds and is observable
    s.complete(b, "passed")
    assert s.outcome("T") == "passed"


def test_same_owner_reacquire_keeps_token():
    s = InMemoryLeaseStore()
    a = s.acquire("K", "A", now=0.0, ttl=10.0)
    again = s.acquire("K", "A", now=1.0, ttl=10.0)  # still alive, same owner
    assert again.token == a.token  # renew-on-acquire keeps the fencing token


def test_renew_fails_after_takeover():
    s = InMemoryLeaseStore()
    a = s.acquire("K", "A", now=0.0, ttl=5.0)
    s.acquire("K", "B", now=10.0, ttl=5.0)  # B takes over (a expired)
    assert s.renew(a, now=11.0, ttl=5.0) is None  # A can no longer renew — it was superseded


# ============================================================ concurrent schedulers
def test_two_schedulers_share_a_store_each_task_runs_once():
    runs: dict[str, int] = {}

    async def worker(t):
        runs[t.id] = runs.get(t.id, 0) + 1
        await asyncio.sleep(0)
        return WorkerResult(verdict=Verdict.PASS)

    async def go():
        store = InMemoryLeaseStore()
        tasks = lambda: [_t(f"t{i}") for i in range(8)]  # noqa: E731
        s1 = Scheduler(worker, concurrency=3, leases=store, owner="m1", clock=lambda: 0.0, sleep=NO_SLEEP)
        s2 = Scheduler(worker, concurrency=3, leases=store, owner="m2", clock=lambda: 0.0, sleep=NO_SLEEP)
        return await asyncio.gather(s1.run(tasks()), s2.run(tasks()))

    r1, r2 = asyncio.run(go())
    assert all(v == 1 for v in runs.values()) and len(runs) == 8  # no double execution
    # both managers converge on the same terminal view (each adopts the other's outcomes)
    assert all(s == TaskState.PASSED for s in r1.values())
    assert all(s == TaskState.PASSED for s in r2.values())


def test_fenced_scheduler_does_not_double_commit_after_takeover():
    # owner A finishes a task whose lease was already taken over by B -> A's commit is fenced,
    # A adopts B's recorded outcome instead of overwriting it.
    store = InMemoryLeaseStore()
    a = store.acquire("solo", "A", now=0.0, ttl=10.0)
    store.acquire("solo", "B", now=20.0, ttl=10.0)  # B takeover (token 2)
    store.complete(store.acquire("solo", "B", now=21.0, ttl=10.0), "failed")  # B records FAILED

    async def worker(t):
        return WorkerResult(verdict=Verdict.PASS)  # A *thinks* it passed

    sched = Scheduler(worker, leases=store, owner="A", clock=lambda: 22.0, sleep=NO_SLEEP)
    # drive A's commit path directly with its stale lease
    st = sched._commit(_t("solo"), a, TaskState.PASSED)
    assert st == TaskState.FAILED  # adopted B's outcome; did NOT overwrite with PASSED
    assert store.outcome("solo") == "failed"


def test_no_lease_store_preserves_v1_behaviour():
    async def worker(t):
        return WorkerResult(verdict=Verdict.PASS)

    state = asyncio.run(Scheduler(worker, clock=lambda: 0.0, sleep=NO_SLEEP).run([_t("a"), _t("b", ["a"])]))
    assert state == {"a": TaskState.PASSED, "b": TaskState.PASSED}


# ==================================================================== multi-repo
def test_plan_multi_repo_namespaces_and_links():
    api = [_t("build")]
    client = [_t("ship")]
    dag = plan_multi_repo({"api": api, "client": client},
                          [CrossDep(to_repo="client", dependent="ship", from_repo="api", needs="build")])
    by = {t.id: t for t in dag}
    assert set(by) == {"api::build", "client::ship"}
    assert by["client::ship"].deps == ["api::build"]
    assert by["api::build"].repo == "api" and repo_of(by["client::ship"]) == "client"


def test_multi_repo_cross_dep_is_ordered_at_runtime():
    order: list[str] = []

    async def worker(t):
        order.append(t.id)
        await asyncio.sleep(0)
        return WorkerResult(verdict=Verdict.PASS)

    dag = plan_multi_repo(
        {"api": [_t("build")], "client": [_t("ship")]},
        [CrossDep(to_repo="client", dependent="ship", from_repo="api", needs="build")])
    asyncio.run(Scheduler(worker, clock=lambda: 0.0, sleep=NO_SLEEP).run(dag))
    assert order.index("api::build") < order.index("client::ship")


def test_multi_repo_rejects_a_cross_repo_cycle():
    from verel.fleet import DagError

    with pytest.raises(DagError):
        plan_multi_repo(
            {"a": [_t("x")], "b": [_t("y")]},
            [CrossDep(to_repo="a", dependent="x", from_repo="b", needs="y"),
             CrossDep(to_repo="b", dependent="y", from_repo="a", needs="x")])  # a.x↔b.y cycle


def test_multi_repo_unknown_refs_raise():
    with pytest.raises(ValueError):
        plan_multi_repo({"a": [_t("x")]},
                        [CrossDep(to_repo="a", dependent="x", from_repo="a", needs="nope")])
