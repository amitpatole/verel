"""Rollback policy engine (§7.4) — the agent PROPOSES, the engine EXECUTES.

The single non-negotiable safety rule: **a destructive action (rollback, revert, redeploy)
NEVER depends on an advisory grader.** An agent may propose a rollback, but the deterministic
policy engine authorizes it only when the justification rests on PRECISE graders
(tests/dom/cv/ocr/security/lint/typecheck) at gating severity — never on a vision/LLM-judge
opinion. This keeps an advisory hallucination from triggering a production revert.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..verdict.constants import ADVISORY_GRADERS, GATING_SEVERITY, SEV_ORDER
from ..verdict.models import GraderKind, Report, Severity


@dataclass
class RollbackProposal:
    reason: str
    target_ref: str  # the ref to roll back to
    justifying_fingerprints: list[str] = field(default_factory=list)


@dataclass
class Decision:
    allow: bool
    reason: str
    precise_support: list[str] = field(default_factory=list)


def _gating(issue) -> bool:
    return SEV_ORDER.index(issue.severity) >= SEV_ORDER.index(GATING_SEVERITY)


class RollbackPolicy:
    """Deterministic authorizer. Construct once; `decide` is a pure function of the evidence."""

    def decide(self, proposal: RollbackProposal, reports: list[Report]) -> Decision:
        # Collect the issues the proposal cites, with the grader that produced them.
        cited = set(proposal.justifying_fingerprints)
        precise_support, advisory_only = [], []
        for r in reports:
            for i in r.issues:
                if i.fingerprint not in cited or not _gating(i):
                    continue
                # per-issue trust keys off Issue.source (§8.3), not Report.backend
                src: GraderKind = i.source
                if src in ADVISORY_GRADERS:
                    advisory_only.append(i.fingerprint)
                else:
                    precise_support.append(i.fingerprint)

        if precise_support:
            return Decision(True, f"authorized: {len(precise_support)} precise gating failure(s) "
                            f"justify rollback to {proposal.target_ref}", precise_support)
        if advisory_only:
            return Decision(False, "denied: only ADVISORY graders support this rollback — "
                            "destructive actions never depend on advisory evidence")
        return Decision(False, "denied: no gating precise evidence supports the proposal")
