"""The single-worker ultracode loop (§7.3, §8.5) — Phase 0 walking skeleton.

write -> render -> perceive (AgentVision) -> gate (Verel) -> fix -> re-render, terminating
on a verdict Verel computes ITSELF (not a self-asserted "done"), or on Verel-owned stuck.

The "fix" step is a pluggable seam (`FixHook`): in Phase 0 it is a deterministic function
or a human; in v1+ it becomes a coding subagent. Everything else — perception, the gate,
scrubbed fingerprints, progressed/stuck, termination — is real.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

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
    terminated_on: str  # "pass" | "stuck" | "max_iter" | "fix_gave_up"
    iterations: list[Iteration]
    final_verdict: Verdict

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
) -> LoopOutcome:
    """Drive one artifact to a self-computed PASS (or honest stuck/handoff)."""
    log = PerceptLog(Path(log_dir) / (Path(artifact).name + ".jsonl"))
    iters: list[Iteration] = []

    for n in range(1, max_iter + 1):
        sight = await perceive(artifact, backend=backend, agent_id=agent_id)
        log.append(sight.percept, ts=str(time.time()), backend=backend)

        result = gate(sight.reports, required=required)
        is_stuck = log.stuck()
        did_progress = log.progressed()
        gating_fps = sorted({o.fingerprint for o in sight.percept.observations})
        iters.append(
            Iteration(
                n=n,
                verdict=result.verdict,
                gating=gating_fps,
                progressed=did_progress,
                stuck=is_stuck,
                reports=sight.reports,
            )
        )

        # Termination authority is Verel's own gate verdict — NOT AgentVision's.
        if result.verdict == Verdict.PASS:
            return LoopOutcome("pass", iters, result.verdict)
        if is_stuck:
            # v1+: escalate model haiku->sonnet->opus, then human handoff. Phase 0: stop.
            return LoopOutcome("stuck", iters, result.verdict)

        changed = await _maybe_await(fix(artifact, result, sight.reports))
        if not changed:
            return LoopOutcome("fix_gave_up", iters, result.verdict)

    final = iters[-1].verdict if iters else Verdict.FAIL
    return LoopOutcome("max_iter", iters, final)
