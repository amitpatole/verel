"""Verel fleet — agents managing agents (§6).

v1-cut control plane: roles + retry + heartbeat, single-writer scheduler over a Task DAG with
barriers/budget/WAL-resume, manager fan-out with plane validation, and a worker adapter that
gates every node through the verdict bus. Worker fencing + git fencing sink are v3.
"""

from __future__ import annotations

from .fence_sink import (
    FenceDecision,
    enable_push_options,
    push_options,
    render_pre_receive_hook,
    validate_push,
    write_pre_receive_hook,
)
from .lease import (
    FencingError,
    InMemoryLeaseStore,
    Lease,
    LeaseStore,
    SqliteLeaseStore,
    monotonic_now,
)
from .llm_manager import decide_fanout
from .manager import FanOut, Subtask, clamp, plan_over_artifacts, to_tasks, validate_fanout
from .multirepo import CrossDep, plan_multi_repo, repo_of
from .saga import SagaResult, SagaStep, StepOutcome, git_revert_head, run_saga
from .scheduler import DagError, Scheduler, WorkerFn, WorkerResult
from .task import (
    ROLE_DEFAULTS,
    Barrier,
    BarrierKind,
    BudgetLease,
    RetryPolicy,
    Role,
    Task,
    TaskState,
)
from .worker import ultracode_worker, worktree_ultracode_worker
from .worktree import LeaseHeld, Worktree, WorktreeError, WorktreeManager

__all__ = [
    "FanOut",
    "Subtask",
    "clamp",
    "decide_fanout",
    "plan_over_artifacts",
    "to_tasks",
    "validate_fanout",
    "LeaseHeld",
    "Worktree",
    "WorktreeError",
    "WorktreeManager",
    "DagError",
    "Scheduler",
    "WorkerFn",
    "WorkerResult",
    "Lease",
    "LeaseStore",
    "InMemoryLeaseStore",
    "SqliteLeaseStore",
    "FencingError",
    "monotonic_now",
    "CrossDep",
    "plan_multi_repo",
    "repo_of",
    "FenceDecision",
    "validate_push",
    "push_options",
    "render_pre_receive_hook",
    "write_pre_receive_hook",
    "enable_push_options",
    "SagaStep",
    "SagaResult",
    "StepOutcome",
    "run_saga",
    "git_revert_head",
    "Barrier",
    "BarrierKind",
    "BudgetLease",
    "ROLE_DEFAULTS",
    "RetryPolicy",
    "Role",
    "Task",
    "TaskState",
    "ultracode_worker",
    "worktree_ultracode_worker",
]
