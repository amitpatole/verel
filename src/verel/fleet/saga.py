"""Cross-repo atomic sagas (§6.3) — all-or-nothing across repositories.

A multi-repo change has no shared transaction: you commit repo A, then repo B fails, and now A is
ahead of a change that never landed. A saga makes the set atomic by **compensation** — each step
has a forward action and an inverse. If any step fails, the saga runs the inverses of the
already-committed steps in REVERSE order (newest first), leaving every repo as if nothing happened.
Compensations are the same safe, non-destructive move the rollback engine uses (a `git revert`,
a new commit that undoes), never a history rewrite — so the audit trail is preserved.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class SagaStep:
    name: str
    forward: Callable[[], object]                       # do the work; RAISE to signal failure
    compensate: Callable[[object], None] = lambda _r: None  # undo, given forward()'s result


@dataclass
class StepOutcome:
    name: str
    status: str  # "committed" | "compensated" | "failed" | "skipped"
    result: object = None
    error: str = ""


@dataclass
class SagaResult:
    ok: bool
    outcomes: list[StepOutcome] = field(default_factory=list)

    @property
    def committed(self) -> list[str]:
        return [o.name for o in self.outcomes if o.status == "committed"]

    @property
    def compensated(self) -> list[str]:
        return [o.name for o in self.outcomes if o.status == "compensated"]

    @property
    def failed(self) -> list[str]:
        return [o.name for o in self.outcomes if o.status == "failed"]


def run_saga(steps: list[SagaStep]) -> SagaResult:
    """Run forward actions in order. On the first failure, compensate every already-committed step
    in REVERSE order and skip the rest — the whole change is all-or-nothing. A compensation that
    itself fails is reported (`failed`) but does not stop the other compensations."""
    steps = list(steps)
    done: list[tuple[int, SagaStep]] = []
    results: dict[str, object] = {}
    fail_idx: int | None = None
    fail_err = ""

    for i, step in enumerate(steps):
        try:
            results[step.name] = step.forward()
        except Exception as e:  # noqa: BLE001 — any forward failure triggers the saga unwind
            fail_idx, fail_err = i, str(e)
            break
        done.append((i, step))

    if fail_idx is None:
        return SagaResult(True, [StepOutcome(s.name, "committed", results.get(s.name)) for s in steps])

    comp: dict[str, tuple[str, str]] = {}
    for _i, step in reversed(done):  # newest committed first
        try:
            step.compensate(results.get(step.name))
            comp[step.name] = ("compensated", "")
        except Exception as ce:  # noqa: BLE001
            comp[step.name] = ("failed", f"compensation failed: {ce}")

    done_idx = {i for i, _ in done}
    outcomes: list[StepOutcome] = []
    for i, step in enumerate(steps):
        if i in done_idx:
            status, err = comp[step.name]
            outcomes.append(StepOutcome(step.name, status, results.get(step.name), err))
        elif i == fail_idx:
            outcomes.append(StepOutcome(step.name, "failed", error=fail_err))
        else:
            outcomes.append(StepOutcome(step.name, "skipped"))
    return SagaResult(False, outcomes)


# --- git-aware compensation: a safe revert of whatever a forward step committed ----------------
def _git(repo: str, *args: str) -> tuple[int, str, str]:
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def git_revert_head(repo: str) -> str:
    """Compensate a commit by REVERTING it (a new inverse commit, never a history rewrite).
    Returns the revert commit sha. Raises on failure so the saga records it."""
    rc, head, err = _git(repo, "rev-parse", "HEAD")
    if rc != 0:
        raise RuntimeError(f"rev-parse: {err}")
    rc, _, err = _git(repo, "-c", "user.name=verel", "-c", "user.email=verel@local",
                      "revert", "--no-edit", head)
    if rc != 0:
        _git(repo, "revert", "--abort")
        raise RuntimeError(f"revert: {err}")
    _, new, _ = _git(repo, "rev-parse", "HEAD")
    return new
