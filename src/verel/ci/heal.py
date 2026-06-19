"""Self-healing CI (§7.4 v2) — the ci-medic actually executes its remediations.

Run a stage; if it fails, triage each failure and act — RETRY re-runs, QUARANTINE_FLAKY
downgrades (ERROR→WARNING, ticketed), FIX_BRANCH invokes the code-fixer agent — then re-gate.
Repeat until PASS or the rounds run out (escalate to a human with the trail). The agent only
proposes patches; the graders decide done, every round.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..agents.code_fixer import fix_code
from .medic import Action, enrich_diagnoses, triage
from .pipeline import Stage, StageResult, run_stage

# (repo, failing_reports) -> set of changed files
FixFn = Callable[[str, list], set]


@dataclass
class HealRound:
    n: int
    verdict: str
    actions: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)


@dataclass
class HealResult:
    healed: bool
    terminated_on: str  # "passed" | "escalate" | "no_progress"
    rounds: list[HealRound]
    final: StageResult


def self_heal(repo: str, stage: Stage, *, fix: FixFn | None = None, runner=None,
              ledger=None, max_rounds: int = 3, flaky_signatures=None, enrich_chat=None) -> HealResult:
    default_fix = fix is None
    flaky_signatures = flaky_signatures or set()
    rounds: list[HealRound] = []
    last_sig: frozenset | None = None

    kw = {"runner": runner} if runner is not None else {}
    for n in range(1, max_rounds + 1):
        result = run_stage(stage, ledger=ledger, **kw)
        rnd = HealRound(n, result.verdict.value)
        if result.passed:
            rounds.append(rnd)
            return HealResult(True, "passed", rounds, result)

        failing = [r for r in result.reports if r.issues]
        diagnoses = [d for r in failing for d in triage(r, flaky_signatures=flaky_signatures)]
        rnd.actions = sorted({d.action.value for d in diagnoses})

        # No-progress guard: identical failing fingerprint set two rounds running and the only
        # actions are non-mutating => stop instead of burning the lease.
        sig = frozenset(i.fingerprint for r in failing for i in r.issues)
        wants_fix = any(d.action == Action.FIX_BRANCH for d in diagnoses)
        if wants_fix:
            if default_fix:
                hints = []
                if enrich_chat is not None:
                    enrich_diagnoses(diagnoses, chat=enrich_chat)
                    hints = [d.hint for d in diagnoses if d.action == Action.FIX_BRANCH and d.hint]
                rnd.changed = sorted(fix_code(repo, failing, hints=hints or None))
            else:
                assert fix is not None  # non-default path: a custom fix was provided
                rnd.changed = sorted(fix(repo, failing))
            if not rnd.changed:
                rounds.append(rnd)
                return HealResult(False, "escalate", rounds, result)  # agent couldn't patch
        elif sig == last_sig:
            rounds.append(rnd)
            return HealResult(False, "no_progress", rounds, result)
        last_sig = sig
        rounds.append(rnd)

    return HealResult(False, "escalate", rounds, result)
