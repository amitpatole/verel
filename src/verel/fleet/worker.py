"""Worker adapter — turns a Task into a graded WorkerResult by running the ultracode loop.

This is the seam where a Verel node == one SDK subagent invocation. Here the worker drives
`ultracode_loop` (agent fix + AgentVision verifier); its verdict is the verdict bus's, so the
scheduler's "done" is never the worker's self-assertion.
"""

from __future__ import annotations

from ..agents import make_fix_hook
from ..loop import ultracode_loop
from ..verdict.models import Verdict
from .scheduler import WorkerResult
from .task import Task


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
