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


# ================================================================ git fencing sink
def test_validate_push_accepts_current_rejects_stale():
    import tempfile

    from verel.fleet import SqliteLeaseStore, validate_push
    with tempfile.TemporaryDirectory() as d:
        store = SqliteLeaseStore(f"{d}/lease.db")
        store.acquire("main", "A", now=0.0, ttl=10.0)
        store.acquire("main", "B", now=20.0, ttl=10.0)  # token 2 current
        assert validate_push(store, "main", 2).allow            # current holder
        assert not validate_push(store, "main", 1).allow        # stale leader
        assert not validate_push(store, "unknown", 1).allow     # no token issued


def _have_git():
    import shutil
    return shutil.which("git") is not None


@pytest.mark.skipif(not _have_git(), reason="git not installed")
def test_pre_receive_hook_fences_a_stale_push(tmp_path):
    import subprocess

    from verel.fleet import SqliteLeaseStore, push_options, write_pre_receive_hook

    def git(*a):
        return subprocess.run(["git", *a], capture_output=True, text=True)

    db = tmp_path / "lease.db"
    store = SqliteLeaseStore(db)
    store.acquire("main", "A", now=0.0, ttl=10.0)
    store.acquire("main", "B", now=20.0, ttl=10.0)  # current token = 2
    bare = tmp_path / "remote.git"
    git("init", "--bare", "-q", str(bare))
    write_pre_receive_hook(bare, db)
    work = tmp_path / "work"
    git("init", "-q", str(work))
    (work / "f.txt").write_text("hi")
    git("-C", str(work), "add", "-A")
    git("-C", str(work), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c1")
    git("-C", str(work), "remote", "add", "origin", str(bare))
    br = git("-C", str(work), "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()

    stale = git("-C", str(work), "push", *push_options("main", 1), "origin", br)
    assert stale.returncode != 0 and "verel-fence" in stale.stderr  # rejected by the hook
    current = git("-C", str(work), "push", *push_options("main", 2), "origin", br)
    assert current.returncode == 0  # current token accepted


# ===================================================================== saga
def test_saga_all_succeed_commits_everything():
    from verel.fleet import SagaStep, run_saga

    res = run_saga([SagaStep(n, (lambda n=n: n)) for n in ("A", "B", "C")])
    assert res.ok and res.committed == ["A", "B", "C"] and not res.compensated


def test_saga_compensates_completed_in_reverse_on_failure():
    from verel.fleet import SagaStep, run_saga

    log = []

    def fwd(n):
        def f():
            if n == "C":
                raise RuntimeError("C failed")
            log.append(f"do:{n}")
            return n
        return f

    steps = [SagaStep(n, fwd(n), (lambda _r, n=n: log.append(f"undo:{n}"))) for n in ("A", "B", "C", "D")]
    res = run_saga(steps)
    assert not res.ok
    assert res.committed == [] and res.compensated == ["A", "B"] and res.failed == ["C"]
    # forward A,B then C fails -> undo B then A (reverse); D never runs
    assert log == ["do:A", "do:B", "undo:B", "undo:A"]


def test_saga_reports_a_failing_compensation():
    from verel.fleet import SagaStep, run_saga

    def boom(_r):
        raise RuntimeError("cannot undo")

    steps = [SagaStep("A", lambda: "a", boom), SagaStep("B", lambda: (_ for _ in ()).throw(RuntimeError("B")))]
    res = run_saga(steps)
    assert not res.ok and "A" in res.failed  # A's compensation failed and is reported


@pytest.mark.skipif(not _have_git(), reason="git not installed")
def test_git_revert_head_makes_an_inverse_commit(tmp_path):
    import subprocess

    from verel.fleet import git_revert_head

    def git(*a):
        return subprocess.run(["git", "-C", str(tmp_path), *a], capture_output=True, text=True)

    git("init", "-q")
    (tmp_path / "f.txt").write_text("v1\n")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c1")
    (tmp_path / "f.txt").write_text("v2-bad\n")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "bad")
    new = git_revert_head(str(tmp_path))
    assert new and (tmp_path / "f.txt").read_text() == "v1\n"  # reverted to v1, not a reset
    assert len(git("log", "--oneline").stdout.strip().splitlines()) == 3  # revert is a NEW commit


# =========================================================== hosted control plane (HTTP)
def test_control_plane_fences_and_coordinates_over_http(tmp_path):
    import asyncio

    from verel.fleet import (
        ControlPlaneServer,
        FencingError,
        RemoteLeaseStore,
        Scheduler,
        WorkerResult,
    )
    from verel.verdict import Verdict

    srv = ControlPlaneServer(tmp_path / "cp.db", auth_token="secret").start()
    try:
        c1 = RemoteLeaseStore(srv.url, auth_token="secret")
        c2 = RemoteLeaseStore(srv.url, auth_token="secret")
        a = c1.acquire("deploy", "m1", ttl=100.0)
        assert a is not None and a.token == 1
        assert c2.acquire("deploy", "m2", ttl=100.0) is None          # live peer blocked over the wire

        # m1 releases; m2 takes over (token 2). m1's stale complete is fenced over HTTP (409).
        c1.release(a)
        b = c2.acquire("deploy", "m2", ttl=100.0)
        assert b is not None and b.token == 2
        with pytest.raises(FencingError):
            c1.complete(a, "passed")  # a's token (1) is no longer current
        c2.complete(b, "passed")
        assert c1.outcome("deploy") == "passed"

        # bad auth is rejected
        with pytest.raises(Exception):
            RemoteLeaseStore(srv.url, auth_token="wrong").current_token("deploy")

        # two schedulers on the same control plane run each task exactly once
        runs: dict[str, int] = {}

        async def worker(t):
            runs[t.id] = runs.get(t.id, 0) + 1
            await asyncio.sleep(0)
            return WorkerResult(verdict=Verdict.PASS)

        async def go():
            s1 = Scheduler(worker, concurrency=2, leases=RemoteLeaseStore(srv.url, auth_token="secret"), owner="h1")
            s2 = Scheduler(worker, concurrency=2, leases=RemoteLeaseStore(srv.url, auth_token="secret"), owner="h2")
            return await asyncio.gather(s1.run([_t(f"j{i}") for i in range(6)]),
                                        s2.run([_t(f"j{i}") for i in range(6)]))

        r1, r2 = asyncio.run(go())
        assert len(runs) == 6 and all(v == 1 for v in runs.values())
        assert all(s == TaskState.PASSED for s in {**r1, **r2}.values())
    finally:
        srv.stop()
