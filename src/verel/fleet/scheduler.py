"""The control plane — a single-writer scheduler over a Task DAG (§6.1, §6.2).

The SDK runs agents; Verel decides WHICH agents run, why, with what budget, and whether
their output is trustworthy. This scheduler:
- admits only an ACYCLIC DAG; runs ready tasks up to a concurrency cap;
- honors barrier policies (all / k_of_n / optional) on dependencies;
- runs each worker, then GATES its output through the verdict bus — a worker cannot self-
  declare done (the `Stop`-hook verifier generalizes AgentVision's "before claiming done");
- retries with backoff, then quarantines/escalates;
- enforces a hard budget lease (tokens / usd / wallclock / iters);
- appends a WAL so an interrupted run RESUMES without re-doing passed tasks.

Single-writer => the scheduler is the sole authority that declares a task done/dead, so the
split-brain a fencing design fights cannot occur in v1.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..verdict.models import Report, Verdict
from .task import TERMINAL, Barrier, BarrierKind, BudgetLease, Task, TaskState


@dataclass
class WorkerResult:
    verdict: Verdict
    reports: list[Report] = field(default_factory=list)
    tokens: int = 0
    cost_usd: float = 0.0
    detail: object = None


# A worker turns a Task into a graded result (or raises to signal a transient failure).
WorkerFn = Callable[[Task], Awaitable[WorkerResult]]


class DagError(ValueError):
    pass


@dataclass
class _Budget:
    lease: BudgetLease
    started: float
    tokens: int = 0
    usd: float = 0.0

    def exhausted(self, now: float) -> str | None:
        if self.lease.max_tokens is not None and self.tokens >= self.lease.max_tokens:
            return "max_tokens"
        if self.lease.max_usd is not None and self.usd >= self.lease.max_usd:
            return "max_usd"
        if self.lease.max_wallclock_s is not None and (now - self.started) >= self.lease.max_wallclock_s:
            return "max_wallclock_s"
        return None


class Scheduler:
    def __init__(self, worker: WorkerFn, *, concurrency: int = 4,
                 budget: BudgetLease | None = None, wal_path: str | Path | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep=asyncio.sleep):
        self.worker = worker
        self.concurrency = max(1, concurrency)
        self.budget = budget
        self.wal_path = Path(wal_path) if wal_path else None
        self._clock = clock
        self._sleep = sleep

    # ---- DAG validation ----
    @staticmethod
    def validate(tasks: list[Task]) -> dict[str, Task]:
        by_id = {t.id: t for t in tasks}
        if len(by_id) != len(tasks):
            raise DagError("duplicate task ids")
        for t in tasks:
            for d in t.deps:
                if d not in by_id:
                    raise DagError(f"task {t.id!r} depends on unknown {d!r}")
        # cycle check (DFS)
        WHITE, GREY, BLACK = 0, 1, 2
        color = dict.fromkeys(by_id, WHITE)

        def visit(tid: str):
            color[tid] = GREY
            for d in by_id[tid].deps:
                if color[d] == GREY:
                    raise DagError(f"cycle through {tid!r}->{d!r}")
                if color[d] == WHITE:
                    visit(d)
            color[tid] = BLACK

        for tid in by_id:
            if color[tid] == WHITE:
                visit(tid)
        return by_id

    # ---- barrier readiness ----
    @staticmethod
    def _deps_ready(t: Task, state: dict[str, TaskState]) -> bool:
        if not t.deps:
            return True
        dep_states = [state[d] for d in t.deps]
        b: Barrier = t.barrier
        if b.kind == BarrierKind.ALL:
            return all(s == TaskState.PASSED for s in dep_states)
        if b.kind == BarrierKind.K_OF_N:
            return sum(s == TaskState.PASSED for s in dep_states) >= b.k
        # OPTIONAL: every dep terminal (failures don't block)
        return all(s in TERMINAL for s in dep_states)

    @staticmethod
    def _dep_dead(t: Task, state: dict[str, TaskState]) -> bool:
        """A non-optional dep that can never PASS => this task is unreachable -> SKIPPED."""
        if t.barrier.kind == BarrierKind.OPTIONAL:
            return False
        dead = {TaskState.FAILED, TaskState.QUARANTINED, TaskState.SKIPPED}
        bad = sum(state[d] in dead for d in t.deps)
        if t.barrier.kind == BarrierKind.ALL:
            return bad > 0
        # K_OF_N: unreachable once fewer than k deps can still pass
        passable = sum(state[d] not in dead for d in t.deps)
        return passable < t.barrier.k

    # ---- WAL ----
    def _wal(self, **rec):
        if self.wal_path:
            self.wal_path.parent.mkdir(parents=True, exist_ok=True)
            with self.wal_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")

    def _resume_passed(self) -> set[str]:
        if not self.wal_path or not self.wal_path.exists():
            return set()
        passed = set()
        for line in self.wal_path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("phase") == "verdict" and r.get("verdict") == Verdict.PASS.value:
                passed.add(r["task_id"])
        return passed

    # ---- run ----
    async def run(self, tasks: list[Task]) -> dict[str, TaskState]:
        by_id = self.validate(tasks)
        state = dict.fromkeys(by_id, TaskState.PENDING)
        budget = _Budget(self.budget or BudgetLease(), started=self._clock())

        for tid in self._resume_passed():
            if tid in state:
                state[tid] = TaskState.PASSED  # memoized from a prior run

        running: dict[str, asyncio.Task] = {}

        def schedulable() -> list[str]:
            out = []
            for tid, t in by_id.items():
                if state[tid] != TaskState.PENDING:
                    continue
                if self._dep_dead(t, state):
                    state[tid] = TaskState.SKIPPED
                    continue
                if self._deps_ready(t, state):
                    out.append(tid)
            return out

        while True:
            # budget check — skip everything still pending if exhausted
            if (reason := budget.exhausted(self._clock())) is not None:
                for tid in state:
                    if state[tid] == TaskState.PENDING:
                        state[tid] = TaskState.SKIPPED
                        self._wal(phase="skip", task_id=tid, reason=f"budget:{reason}")

            for tid in schedulable():
                if len(running) >= self.concurrency:
                    break
                state[tid] = TaskState.RUNNING
                running[tid] = asyncio.ensure_future(self._run_one(by_id[tid], budget))

            if not running:
                if any(state[t] == TaskState.PENDING for t in state):
                    continue  # something became skippable; re-loop
                break

            done, _ = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                tid = next(k for k, v in running.items() if v is fut)
                del running[tid]
                state[tid] = fut.result()

        return state

    async def _run_one(self, task: Task, budget: _Budget) -> TaskState:
        self._wal(phase="intent", task_id=task.id, role=task.role.value)
        for attempt in range(1, task.retry.max + 1):
            task.attempt = attempt
            if (reason := budget.exhausted(self._clock())) is not None:
                self._wal(phase="skip", task_id=task.id, reason=f"budget:{reason}")
                return TaskState.SKIPPED
            try:
                res = await self.worker(task)
            except Exception as e:  # transient failure -> retry
                last = str(e)
            else:
                budget.tokens += res.tokens
                budget.usd += res.cost_usd
                if res.verdict == Verdict.PASS:
                    self._wal(phase="verdict", task_id=task.id, verdict=Verdict.PASS.value)
                    return TaskState.PASSED
                last = f"verdict={res.verdict.value}"
            if attempt < task.retry.max:
                idx = min(attempt - 1, len(task.retry.backoff_s) - 1)
                await self._sleep(task.retry.backoff_s[idx] if task.retry.backoff_s else 0)
        self._wal(phase="verdict", task_id=task.id, verdict=Verdict.FAIL.value, reason=last)
        return TaskState.QUARANTINED if task.retry.on_fail == "quarantine" else TaskState.FAILED
