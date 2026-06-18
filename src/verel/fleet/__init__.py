"""Verel fleet — agents managing agents (§6).

v1-cut control plane: roles + retry + heartbeat, single-writer scheduler over a Task DAG with
barriers/budget/WAL-resume, manager fan-out with plane validation, and a worker adapter that
gates every node through the verdict bus. Worker fencing + git fencing sink are v3.
"""

from __future__ import annotations

from .manager import FanOut, Subtask, clamp, plan_over_artifacts, to_tasks, validate_fanout
from .scheduler import DagError, Scheduler, WorkerFn, WorkerResult
from .task import (
    Barrier,
    BarrierKind,
    BudgetLease,
    ROLE_DEFAULTS,
    RetryPolicy,
    Role,
    Task,
    TaskState,
)
from .worker import ultracode_worker

__all__ = [
    "FanOut",
    "Subtask",
    "clamp",
    "plan_over_artifacts",
    "to_tasks",
    "validate_fanout",
    "DagError",
    "Scheduler",
    "WorkerFn",
    "WorkerResult",
    "Barrier",
    "BarrierKind",
    "BudgetLease",
    "ROLE_DEFAULTS",
    "RetryPolicy",
    "Role",
    "Task",
    "TaskState",
    "ultracode_worker",
]
