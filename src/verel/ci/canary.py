"""Post-merge canary → verdict-driven rollback (§7.4, the table's last row).

Run the canary (smoke/E2E) on freshly-merged code. If it PASSES, done. If it FAILS, the
agent *proposes* a rollback citing the precise failing fingerprints, the deterministic policy
engine authorizes it only on precise gating evidence, and the executor performs a safe
`git revert`. Destructive action never rides on an advisory grader — that invariant is
enforced by the policy, not by trust in the agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..verdict.constants import GATING_SEVERITY, SEV_ORDER
from ..verdict.models import Verdict
from .pipeline import Stage, StageResult, run_stage
from .rollback import RollbackExecutor, RollbackOutcome, RollbackPolicy, RollbackProposal


@dataclass
class CanaryResult:
    verdict: Verdict
    canary: StageResult
    rolled_back: bool
    rollback: RollbackOutcome | None = None

    @property
    def healthy(self) -> bool:
        return self.verdict == Verdict.PASS


def _precise_gating_fingerprints(result: StageResult) -> list[str]:
    g = SEV_ORDER.index(GATING_SEVERITY)
    from ..verdict.constants import ADVISORY_GRADERS

    return [
        i.fingerprint for r in result.reports for i in r.issues
        if SEV_ORDER.index(i.severity) >= g and i.source not in ADVISORY_GRADERS
    ]


def canary_rollback(repo: str, stage: Stage, *, target_ref: str = "HEAD~1",
                    policy: RollbackPolicy | None = None, runner=None,
                    ledger=None) -> CanaryResult:
    """Run the canary stage; on a precise-evidence failure, auto-revert the bad commit."""
    kw = {"runner": runner} if runner is not None else {}
    result = run_stage(stage, ledger=ledger, **kw)
    if result.passed:
        return CanaryResult(Verdict.PASS, result, rolled_back=False)

    proposal = RollbackProposal(
        reason=f"canary {stage.name} failed", target_ref=target_ref,
        justifying_fingerprints=_precise_gating_fingerprints(result),
    )
    outcome = RollbackExecutor(policy).maybe_rollback(repo, proposal, result.reports)
    return CanaryResult(result.verdict, result, rolled_back=outcome.executed, rollback=outcome)
