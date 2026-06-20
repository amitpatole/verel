"""Multi-repo coordination (§6.3) — one DAG spanning repositories.

The fleet isolates per-worker edits in git worktrees; coordinating CHANGES THAT CROSS repos (ship
the API in repo A before the client in repo B; migrate a shared schema in both atomically) needs
one DAG whose edges may cross repo boundaries. `plan_multi_repo` builds exactly that:

- every task is namespaced `repo::id` so ids are unique across repos and each task's `.repo` is set;
- intra-repo deps are rewritten to the namespaced ids;
- cross-repo edges are added as ordinary deps (with a barrier), so the existing scheduler enforces
  cross-repo ordering with no new machinery;
- the combined DAG is validated as ACYCLIC including the cross edges — a cycle that only exists
  *between* repos (A waits on B waits on A) is rejected up front, not deadlocked at run time.

Run the result under one fenced `Scheduler` (lease.py) so several managers can share it safely.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .scheduler import Scheduler
from .task import Barrier, Task


def ns_id(repo: str, task_id: str) -> str:
    """The namespaced id for a task in a repo. `repo::id` — stable and collision-free."""
    return f"{repo}::{task_id}"


@dataclass
class CrossDep:
    """`dependent` (in `to_repo`) waits on `needs` (in `from_repo`) under `barrier`."""
    to_repo: str
    dependent: str
    from_repo: str
    needs: str
    barrier: Barrier = field(default_factory=Barrier)


def plan_multi_repo(repos: dict[str, list[Task]], cross_deps: list[CrossDep]) -> list[Task]:
    """Combine per-repo task lists into one namespaced, cross-linked DAG (validated acyclic).

    `repos`: {repo_name: [tasks]} — task ids are local to their repo. `cross_deps`: edges that
    cross repos. Returns the unified task list; run it under a single Scheduler."""
    # 1) namespace every task and set its repo; rewrite intra-repo deps to namespaced ids.
    combined: list[Task] = []
    local_ids: dict[str, set[str]] = {repo: {t.id for t in tasks} for repo, tasks in repos.items()}
    for repo, tasks in repos.items():
        for t in tasks:
            for d in t.deps:
                if d not in local_ids[repo]:
                    raise ValueError(f"task {t.id!r} in {repo!r} depends on unknown local {d!r}")
            nt = t.model_copy(deep=True)
            nt.id = ns_id(repo, t.id)
            nt.repo = repo or t.repo
            nt.deps = [ns_id(repo, d) for d in t.deps]
            combined.append(nt)

    # 2) add the cross-repo edges as ordinary namespaced deps.
    by_ns = {t.id: t for t in combined}
    for c in cross_deps:
        dep_ns, need_ns = ns_id(c.to_repo, c.dependent), ns_id(c.from_repo, c.needs)
        if dep_ns not in by_ns:
            raise ValueError(f"cross-dep dependent {c.dependent!r} not found in repo {c.to_repo!r}")
        if need_ns not in by_ns:
            raise ValueError(f"cross-dep need {c.needs!r} not found in repo {c.from_repo!r}")
        task = by_ns[dep_ns]
        if need_ns not in task.deps:
            task.deps.append(need_ns)
        task.barrier = c.barrier

    # 3) validate the whole thing is acyclic (incl. cross edges) — fail fast, never deadlock.
    Scheduler.validate(combined)
    return combined


def repo_of(task: Task) -> str:
    """The repo a namespaced task belongs to (prefers the explicit field, falls back to the id)."""
    return task.repo or (task.id.split("::", 1)[0] if "::" in task.id else "")
