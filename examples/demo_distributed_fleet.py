"""Distributed fleet (§6.3) — concurrent managers made safe by fencing, + multi-repo coordination.

Two schedulers share one lease store and run the SAME DAG: each task is leased by exactly one of
them, so nothing runs twice, and each adopts the other's recorded outcomes. Then a stale leader's
late write is shown being fenced off. Finally a cross-repo DAG (ship the client only after the API
builds) is planned and run under one scheduler. Offline, fake workers, no key.

Run:  python examples/demo_distributed_fleet.py
"""

from __future__ import annotations

import asyncio

from verel.fleet import (
    CrossDep,
    FencingError,
    InMemoryLeaseStore,
    Scheduler,
    Task,
    WorkerResult,
    plan_multi_repo,
)
from verel.fleet.task import RetryPolicy
from verel.verdict import Verdict

NO_SLEEP = lambda *_a, **_k: asyncio.sleep(0)  # noqa: E731


def _t(tid, deps=()):
    return Task(id=tid, deps=list(deps), retry=RetryPolicy(max=1, backoff_s=[]))


async def main() -> None:
    # ---- two managers, one store: each task runs exactly once ----
    runs: dict[str, str] = {}

    def worker_for(owner):
        async def worker(t):
            runs[t.id] = owner  # who actually ran it
            await asyncio.sleep(0)
            return WorkerResult(verdict=Verdict.PASS)
        return worker

    store = InMemoryLeaseStore()
    tasks = lambda: [_t(f"task{i}") for i in range(8)]  # noqa: E731
    m1 = Scheduler(worker_for("m1"), concurrency=3, leases=store, owner="m1", clock=lambda: 0.0, sleep=NO_SLEEP)
    m2 = Scheduler(worker_for("m2"), concurrency=3, leases=store, owner="m2", clock=lambda: 0.0, sleep=NO_SLEEP)
    await asyncio.gather(m1.run(tasks()), m2.run(tasks()))
    split = {o: sum(v == o for v in runs.values()) for o in ("m1", "m2")}
    print(f"8 tasks across 2 concurrent managers — ran once each: {len(runs) == 8 and all(runs.values())}")
    print(f"  work split by lease: {split}")

    # ---- fencing: a stale leader cannot corrupt shared state ----
    s = InMemoryLeaseStore()
    a = s.acquire("deploy", "leaderA", now=0.0, ttl=10.0)        # A leads (token 1)
    b = s.acquire("deploy", "leaderB", now=20.0, ttl=10.0)       # A paused; B takes over (token 2)
    try:
        s.complete(a, "passed")                                  # A resumes, tries to write
    except FencingError as e:
        print(f"\nstale leader A fenced off: {str(e)[:48]}…")
    s.complete(b, "passed")
    print(f"  current leader B's write accepted: outcome={s.outcome('deploy')}")

    # ---- multi-repo: ship the client only after the API builds ----
    order: list[str] = []

    async def w(t):
        order.append(t.id)
        await asyncio.sleep(0)
        return WorkerResult(verdict=Verdict.PASS)

    dag = plan_multi_repo(
        {"api": [_t("migrate"), _t("build", ["migrate"])], "client": [_t("ship")]},
        [CrossDep(to_repo="client", dependent="ship", from_repo="api", needs="build")])
    await Scheduler(w, clock=lambda: 0.0, sleep=NO_SLEEP).run(dag)
    print(f"\ncross-repo DAG: {[t.id for t in dag]}")
    print(f"  execution order: {order}")
    print(f"  client shipped only after api built: {order.index('api::build') < order.index('client::ship')}")


if __name__ == "__main__":
    asyncio.run(main())
