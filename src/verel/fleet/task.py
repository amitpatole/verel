"""Fleet task model, roles, retry, and budget lease (§6.1, §6.2, §6.5).

v1-cut per the design: roles + retry + heartbeat semantics, single-writer scheduler, Task
DAG with deps/barriers, budget leases. NO worker fencing tokens / git fencing sink (those
are v3 — they only matter under concurrent managers, which v1 doesn't have).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Role(str, Enum):
    ORCHESTRATOR = "orchestrator"  # top-level goal/budget/graph; one per run
    MANAGER = "manager"  # a sub-goal; fan-out vs do-it-myself
    WORKER = "worker"  # scoped task in an isolated worktree
    CRITIC = "critic"  # independently grades; never writes product code
    TOOLSMITH = "toolsmith"  # builds missing tools (v2)


class TaskState(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    SKIPPED = "skipped"


TERMINAL = {TaskState.PASSED, TaskState.FAILED, TaskState.QUARANTINED, TaskState.SKIPPED}


class BarrierKind(str, Enum):
    ALL = "all"  # every dep must PASS
    K_OF_N = "k_of_n"  # at least k deps PASS
    OPTIONAL = "optional"  # deps need only be terminal; their failure doesn't block


class Barrier(BaseModel):
    kind: BarrierKind = BarrierKind.ALL
    k: int = 1


class RetryPolicy(BaseModel):
    max: int = 3
    backoff_s: list[float] = Field(default_factory=lambda: [5.0, 30.0, 120.0])
    on_fail: str = "quarantine"  # "quarantine" | "escalate"


class BudgetLease(BaseModel):
    """Per-run budget. The scheduler enforces it as a HARD ceiling (§6.5)."""

    max_tokens: int | None = None
    max_usd: float | None = None
    max_wallclock_s: float | None = None
    max_iters: int | None = None


# Per-role defaults (model is provenance/documentation here; routing is the SDK's job).
ROLE_DEFAULTS: dict[Role, dict] = {
    Role.ORCHESTRATOR: {"model": "opus-4.8", "retry": RetryPolicy(max=1)},
    Role.MANAGER: {"model": "sonnet-4.6", "retry": RetryPolicy(max=2)},
    Role.WORKER: {"model": "sonnet-4.6", "retry": RetryPolicy(max=3)},
    Role.CRITIC: {"model": "haiku-4.5", "retry": RetryPolicy(max=1)},
    Role.TOOLSMITH: {"model": "sonnet-4.6", "retry": RetryPolicy(max=2)},
}


class Task(BaseModel):
    id: str
    role: Role = Role.WORKER
    goal: str = ""
    repo: str = ""
    artifact: str | None = None  # the file a worker drives (Phase-0 worktree stand-in)
    deps: list[str] = Field(default_factory=list)
    barrier: Barrier = Field(default_factory=Barrier)
    verifier: str = "sight"  # "sight" | "tests" | "schema" | "none"
    budget_lease: BudgetLease = Field(default_factory=BudgetLease)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    state: TaskState = TaskState.PENDING
    attempt: int = 0
    fingerprint: str = ""
    last_report_ref: str = ""
    detail_json: str = "{}"
