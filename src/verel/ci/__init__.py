"""Verel CI — agent-run CI/CD on the verdict bus (§7.4).

Real non-sight graders (tests/lint/types) emit verdict-bus Reports; stages gate them with
attestation + failure-memory; the ci-medic classifies failures into safe gated remediations;
and a deterministic rollback policy engine keeps destructive actions off advisory evidence.
"""

from __future__ import annotations

from .graders import (
    GraderSpec,
    mypy_spec,
    parse_mypy,
    parse_pytest,
    parse_ruff,
    pytest_spec,
    ruff_spec,
    run_grader,
    subprocess_runner,
    suite_sha,
)
from .canary import CanaryResult, canary_rollback
from .heal import HealResult, HealRound, self_heal
from .hooks import install_precommit, is_installed
from .medic import Action, Diagnosis, classify_issue, quarantine_severity, triage
from .pipeline import (
    Stage,
    StageResult,
    inner_loop_stage,
    postmerge_stage,
    precommit_stage,
    premerge_stage,
    run_stage,
)
from .rollback import (
    Decision,
    RollbackExecutor,
    RollbackOutcome,
    RollbackPolicy,
    RollbackProposal,
)

__all__ = [
    "GraderSpec", "run_grader", "subprocess_runner", "suite_sha",
    "pytest_spec", "ruff_spec", "mypy_spec", "parse_pytest", "parse_ruff", "parse_mypy",
    "Stage", "StageResult", "run_stage", "inner_loop_stage", "precommit_stage", "premerge_stage",
    "postmerge_stage",
    "Action", "Diagnosis", "classify_issue", "triage", "quarantine_severity",
    "RollbackPolicy", "RollbackProposal", "Decision", "RollbackExecutor", "RollbackOutcome",
    "canary_rollback", "CanaryResult",
    "self_heal", "HealResult", "HealRound",
    "install_precommit", "is_installed",
]
