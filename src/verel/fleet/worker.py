"""Worker adapter — turns a Task into a graded WorkerResult by running the ultracode loop.

This is the seam where a Verel node == one SDK subagent invocation. Here the worker drives
`ultracode_loop` (agent fix + AgentVision verifier); its verdict is the verdict bus's, so the
scheduler's "done" is never the worker's self-assertion.
"""

from __future__ import annotations

from collections.abc import Callable

from ..agents import make_fix_hook
from ..loop import ultracode_loop
from ..verdict.models import Verdict
from .scheduler import WorkerResult
from .task import Task
from .worktree import Worktree, WorktreeManager


def ultracode_worker(*, backend: str = "local", ledger=None, fix=None, log_dir="./.verel/fleet"):
    """Build a WorkerFn for the Scheduler. `ledger` (optional) shares failure-memory across
    the fleet so one worker's lesson can gate another's regression."""

    async def worker(task: Task) -> WorkerResult:
        if not task.artifact:
            raise ValueError(f"task {task.id!r} has no artifact to drive")
        fixhook = fix or make_fix_hook(verbose=False)
        outcome = await ultracode_loop(
            task.artifact, fixhook, backend=backend, agent_id=task.id,
            log_dir=f"{log_dir}/{task.id}", ledger=ledger,
        )
        reports = outcome.iterations[-1].reports if outcome.iterations else []
        return WorkerResult(
            verdict=Verdict.PASS if outcome.passed else Verdict.FAIL,
            reports=reports,
            detail=outcome,
        )

    return worker


def worktree_ultracode_worker(mgr: WorktreeManager, *, seed: Callable[[Worktree, Task], str],
                              backend: str = "local", ledger=None, fix=None, commit: bool = True):
    """A worker that runs the ultracode loop inside an ISOLATED git worktree (§6.1, §6.3).

    `seed(worktree, task)` materializes the task's starting artifact inside the worktree and
    returns its path. On PASS the fix is committed on the worktree's own branch; the worktree
    (and its advisory lease) is always released. Parallel workers can't stomp each other.
    """

    async def worker(task: Task) -> WorkerResult:
        wt = mgr.create(task.id)
        try:
            artifact = seed(wt, task)
            fixhook = fix or make_fix_hook(verbose=False)
            outcome = await ultracode_loop(
                artifact, fixhook, backend=backend, agent_id=task.id,
                log_dir=str(wt.path / ".verel" / "percepts"), ledger=ledger,
            )
            sha = None
            if commit and outcome.passed:
                sha = wt.commit_all(f"verel: {task.goal or task.id}")
            reports = outcome.iterations[-1].reports if outcome.iterations else []
            return WorkerResult(
                verdict=Verdict.PASS if outcome.passed else Verdict.FAIL,
                reports=reports, detail={"outcome": outcome, "branch": wt.branch, "commit": sha},
            )
        finally:
            wt.release()

    return worker
