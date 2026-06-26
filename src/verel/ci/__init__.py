"""Verel CI — agent-run CI/CD on the verdict bus (§7.4).

Real non-sight graders (tests/lint/types) emit verdict-bus Reports; stages gate them with
attestation + failure-memory; the ci-medic classifies failures into safe gated remediations;
and a deterministic rollback policy engine keeps destructive actions off advisory evidence.
"""

from __future__ import annotations

from .canary import CanaryResult, canary_rollback
from .graders import (
    LANGS,
    GraderSpec,
    LangToolchain,
    bandit_spec,
    eslint_spec,
    gotest_spec,
    govet_spec,
    jstest_spec,
    mutation_spec,
    mypy_spec,
    npm_audit_spec,
    parse_bandit,
    parse_eslint,
    parse_go_test,
    parse_go_vet,
    parse_mutation,
    parse_mypy,
    parse_npm_audit,
    parse_perf,
    parse_pytest,
    parse_ruff,
    parse_tap,
    parse_tsc,
    perf_spec,
    pytest_spec,
    ruff_spec,
    run_grader,
    subprocess_runner,
    suite_sha,
    tsc_spec,
)
from .heal import HealResult, HealRound, self_heal
from .hooks import install_precommit, is_installed
from .iac import (
    IamChange,
    checkov_spec,
    cloudsplaining_spec,
    conftest_spec,
    destructive_changes,
    extract_iam_changes,
    iam_risk_issues,
    infracost_spec,
    is_iam_resource,
    parliament_spec,
    parse_checkov,
    parse_cloudsplaining,
    parse_conftest,
    parse_infracost,
    parse_parliament,
    parse_terraform_plan,
    parse_terraform_validate,
    parse_tflint,
    parse_trivy_config,
    plan_summary,
    terraform_plan_spec,
    terraform_validate_spec,
    tflint_spec,
    trivy_config_spec,
)
from .medic import Action, Diagnosis, classify_issue, enrich_diagnoses, quarantine_severity, triage
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
    "LANGS", "LangToolchain",
    "jstest_spec", "eslint_spec", "tsc_spec", "parse_tap", "parse_eslint", "parse_tsc",
    "gotest_spec", "govet_spec", "parse_go_test", "parse_go_vet",
    "perf_spec", "parse_perf", "bandit_spec", "npm_audit_spec", "parse_bandit", "parse_npm_audit",
    "mutation_spec", "parse_mutation",
    "terraform_validate_spec", "terraform_plan_spec", "trivy_config_spec",
    "parse_terraform_validate", "parse_terraform_plan", "parse_trivy_config",
    "extract_iam_changes", "iam_risk_issues", "is_iam_resource", "IamChange",
    "plan_summary", "destructive_changes",
    "tflint_spec", "checkov_spec", "conftest_spec", "infracost_spec",
    "parliament_spec", "cloudsplaining_spec",
    "parse_tflint", "parse_checkov", "parse_conftest", "parse_infracost",
    "parse_parliament", "parse_cloudsplaining",
    "Stage", "StageResult", "run_stage", "inner_loop_stage", "precommit_stage", "premerge_stage",
    "postmerge_stage",
    "Action", "Diagnosis", "classify_issue", "triage", "quarantine_severity", "enrich_diagnoses",
    "RollbackPolicy", "RollbackProposal", "Decision", "RollbackExecutor", "RollbackOutcome",
    "canary_rollback", "CanaryResult",
    "self_heal", "HealResult", "HealRound",
    "install_precommit", "is_installed",
]
