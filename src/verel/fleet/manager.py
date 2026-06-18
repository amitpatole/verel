"""Manager fan-out decision + plane validation (§6.1).

A manager emits a structured decision; the control plane VALIDATES and CLAMPS it before
admitting tasks. Fan out only when subtasks are independent (deps form an antichain),
individually verifiable, and worth more than doing it inline. The manager may be LLM-driven
(Ollama) or deterministic; either way the plane is the authority, not the model.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .task import Barrier, BudgetLease, RetryPolicy, Role, Task


class Subtask(BaseModel):
    id: str
    goal: str = ""
    repo: str = ""
    artifact: str | None = None
    deps: list[str] = Field(default_factory=list)
    est_tokens: int = 0
    verifier: str = "sight"


class FanOut(BaseModel):
    decision: str = "fan_out"  # "fan_out" | "self"
    rationale: str = ""
    subtasks: list[Subtask] = Field(default_factory=list)
    concurrency_cap: int = 4


def validate_fanout(fo: FanOut) -> tuple[bool, str]:
    """Return (ok, reason). Enforces independence + acyclicity + sane caps."""
    if fo.decision == "self":
        return True, "self"
    if not fo.subtasks:
        return False, "fan_out with no subtasks"
    ids = [s.id for s in fo.subtasks]
    if len(set(ids)) != len(ids):
        return False, "duplicate subtask ids"
    idset = set(ids)
    for s in fo.subtasks:
        for d in s.deps:
            if d not in idset:
                return False, f"subtask {s.id!r} depends on unknown {d!r}"
    # Independence: fan-out subtasks should form an ANTICHAIN (no inter-subtask deps). The
    # design admits dep-carrying DAGs too, but the *fan-out independence* rule is: a batch
    # admitted as parallel work must be mutually independent.
    if any(s.deps for s in fo.subtasks):
        return False, "fan_out subtasks are not independent (deps present) — emit a DAG via deps only when serial"
    return True, "ok"


def clamp(fo: FanOut) -> FanOut:
    fo.concurrency_cap = max(1, min(fo.concurrency_cap, len(fo.subtasks) or 1))
    return fo


def to_tasks(fo: FanOut, *, budget: BudgetLease | None = None,
             retry: RetryPolicy | None = None) -> list[Task]:
    return [
        Task(
            id=s.id, role=Role.WORKER, goal=s.goal, repo=s.repo, artifact=s.artifact,
            deps=s.deps, barrier=Barrier(), verifier=s.verifier,
            budget_lease=budget or BudgetLease(), retry=retry or RetryPolicy(),
        )
        for s in fo.subtasks
    ]


def plan_over_artifacts(goal: str, artifacts: list[str], *, concurrency_cap: int = 4) -> FanOut:
    """Deterministic manager: one independent worker subtask per artifact (the common
    'fix every page in the design system' fan-out). LLM-driven planning is the v2 upgrade
    behind the same FanOut contract."""
    subs = [
        Subtask(id=f"fix-{i}", goal=f"{goal}: {a}", artifact=a, verifier="sight")
        for i, a in enumerate(artifacts)
    ]
    return clamp(FanOut(decision="fan_out", rationale=goal, subtasks=subs,
                        concurrency_cap=concurrency_cap))
