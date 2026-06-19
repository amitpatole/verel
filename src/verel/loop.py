"""The single-worker ultracode loop (§7.3, §8.5) — Phase 0 walking skeleton.

write -> render -> perceive (AgentVision) -> gate (Verel) -> fix -> re-render, terminating
on a verdict Verel computes ITSELF (not a self-asserted "done"), or on Verel-owned stuck.

The "fix" step is a pluggable seam (`FixHook`): in Phase 0 it is a deterministic function
or a human; in v1+ it becomes a coding subagent. Everything else — perception, the gate,
scrubbed fingerprints, progressed/stuck, termination — is real.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from .senses.percept_log import PerceptLog
from .senses.sight import perceive
from .verdict.gate import gate
from .verdict.models import GateResult, GraderKind, Report, Verdict

# A fix hook receives the artifact path + the latest gate result + per-source reports, and
# edits the artifact in place. Returns True if it changed something, False to give up.
FixHook = Callable[[str, GateResult, list[Report]], Awaitable[bool] | bool]


@dataclass
class Iteration:
    n: int
    verdict: Verdict
    gating: list[str]
    progressed: bool
    stuck: bool
    reports: list[Report] = field(repr=False, default_factory=list)


@dataclass
class LoopOutcome:
    terminated_on: str  # "pass" | "stuck" | "max_iter" | "fix_gave_up" | "regression"
    iterations: list[Iteration]
    final_verdict: Verdict
    regressions: list = field(default_factory=list)  # MemoryRecords reintroduced (from memory)

    @property
    def passed(self) -> bool:
        return self.terminated_on == "pass" and self.final_verdict == Verdict.PASS


async def _maybe_await(v):
    if hasattr(v, "__await__"):
        return await v
    return v


async def ultracode_loop(
    artifact: str,
    fix: FixHook,
    *,
    backend: str = "local",
    agent_id: str = "worker-0",
    required: set[GraderKind] | None = None,
    log_dir: str | Path = ".verel/percepts",
    max_iter: int = 6,
    ledger=None,  # optional memory.FailureLedger — turns past fixes into a regression gate
) -> LoopOutcome:
    """Drive one artifact to a self-computed PASS (or honest stuck/handoff).

    When a `ledger` is supplied, every gating failure compounds into long-term memory; a
    reintroduced previously-fixed failure FAILS the gate from memory alone; and reaching PASS
    marks the session's failures `fixed` so the fleet won't repeat them.
    """
    log = PerceptLog(Path(log_dir) / (Path(artifact).name + ".jsonl"))
    iters: list[Iteration] = []
    seen_fps: set[str] = set()

    for n in range(1, max_iter + 1):
        sight = await perceive(artifact, backend=backend, agent_id=agent_id)
        log.append(sight.percept, ts=str(time.time()), backend=backend)

        reports = list(sight.reports)
        regressions = []
        if ledger is not None:
            from .memory.failure_ledger import regression_report

            # Memory gates the build: recall previously-fixed failures that reappeared.
            sight_report = _merge_for_ledger(sight.reports)
            regressions = ledger.check_regressions(sight_report)
            if regressions:
                reports.append(regression_report(regressions))
            seen_fps |= set(ledger.record(sight_report, ts=time.time()))

        result = gate(reports, required=required)
        is_stuck = log.stuck()
        did_progress = log.progressed()
        gating_fps = sorted({o.fingerprint for o in sight.percept.observations})
        iters.append(
            Iteration(n=n, verdict=result.verdict, gating=gating_fps,
                      progressed=did_progress, stuck=is_stuck, reports=reports)
        )

        # Termination authority is Verel's own gate verdict — NOT AgentVision's.
        if result.verdict == Verdict.PASS:
            if ledger is not None and seen_fps:
                ledger.mark_fixed(sorted(seen_fps), ts=time.time())
            return LoopOutcome("pass", iters, result.verdict, regressions)
        if regressions:
            # A reintroduced, memory-known bug: don't waste the lease re-discovering it.
            return LoopOutcome("regression", iters, result.verdict, regressions)
        if is_stuck:
            # v1+: escalate model haiku->sonnet->opus, then human handoff. Phase 0: stop.
            return LoopOutcome("stuck", iters, result.verdict, regressions)

        changed = await _maybe_await(fix(artifact, result, reports))
        if not changed:
            return LoopOutcome("fix_gave_up", iters, result.verdict, regressions)

    final = iters[-1].verdict if iters else Verdict.FAIL
    return LoopOutcome("max_iter", iters, final)


def _merge_for_ledger(reports: list[Report]) -> Report:
    """Flatten per-source perception reports into one Report for the ledger to scan."""
    issues = [i for r in reports for i in r.issues]
    return Report(verdict=Verdict.FAIL, summary="", issues=issues, grader=GraderKind.OTHER)
