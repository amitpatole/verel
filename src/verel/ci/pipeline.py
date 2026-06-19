"""Agent-run CI/CD pipeline — inner loop + pre-commit gate (§7.4, v1 stages).

Stages compose graders (any sense) and gate them through the verdict bus with attestation.
The pre-commit stage additionally consults failure-memory: a change that reintroduces a
previously-fixed failure is gated FAIL from memory alone (§7.5), and new gating failures are
recorded so the fleet stops repeating them. This is "CI run by agents" with the same
safety contract as everything else — nothing is green unless a grader said so.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..memory.failure_ledger import FailureLedger, regression_report
from ..verdict.gate import gate
from ..verdict.models import GateResult, GraderKind, Report, Verdict
from .graders import GraderSpec, Runner, run_grader, subprocess_runner, suite_sha


@dataclass
class Stage:
    name: str
    graders: list[GraderSpec]
    required: set[GraderKind] = field(default_factory=set)


@dataclass
class StageResult:
    name: str
    verdict: Verdict
    gate: GateResult
    reports: list[Report]
    regressions: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == Verdict.PASS


def run_stage(stage: Stage, *, diff_files: set[str] | None = None, runner: Runner = subprocess_runner,
              ledger: FailureLedger | None = None, ts: float = 0.0,
              flaky_signatures: set[str] | None = None) -> StageResult:
    """Run all graders in a stage, gate them, and (if a ledger is given) apply the
    failure-memory regression check + record new gating failures."""
    diff_files = diff_files or set()
    flaky_signatures = flaky_signatures or set()
    reports = [run_grader(s, runner) for s in stage.graders]
    # Pin frozen suites from the trusted stage config (not from grader runtime output).
    frozen = {s.grader: suite_sha(s) for s in stage.graders}

    regressions = []
    if ledger is not None:
        from .medic import Action, triage

        flat = Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.OTHER,
                      issues=[i for r in reports for i in r.issues])
        regressions = ledger.check_regressions(flat)
        if regressions:
            reports.append(regression_report(regressions))
        # ci-medic: transient (retry) and flaky failures are written volatile, so they
        # self-clean from failure-memory unless they recur. Genuine regressions persist.
        volatile = {d.issue.fingerprint for d in triage(flat, flaky_signatures=flaky_signatures)
                    if d.action in (Action.RETRY, Action.QUARANTINE_FLAKY)}
        ledger.record(flat, ts=ts, volatile_fingerprints=volatile)

    gr = gate(reports, required=stage.required, frozen_suites=frozen, diff_files=diff_files)
    return StageResult(stage.name, gr.verdict, gr, reports, regressions)


# ---- the two v1 stages, as named in the design table ----
def inner_loop_stage(repo: str, *, covers: list[str] | None = None,
                     with_lint: bool = True, with_types: bool = False) -> Stage:
    from .graders import mypy_spec, pytest_spec, ruff_spec

    graders = [pytest_spec(repo, covers)]
    required = {GraderKind.TEST}
    if with_lint:
        graders.append(ruff_spec(repo, covers))
        required.add(GraderKind.LINT)
    if with_types:
        graders.append(mypy_spec(repo, covers))
        required.add(GraderKind.TYPECHECK)
    return Stage("inner_loop", graders, required)


def precommit_stage(repo: str, *, covers: list[str] | None = None) -> Stage:
    """Unit + affected tests + lint; the failure-memory fingerprint check is applied by
    run_stage when a ledger is passed."""
    from .graders import pytest_spec, ruff_spec

    return Stage("pre_commit", [pytest_spec(repo, covers), ruff_spec(repo, covers)],
                 required={GraderKind.TEST})


def postmerge_stage(repo: str, *, smoke_paths: list[str] | None = None,
                    covers: list[str] | None = None) -> Stage:
    """Smoke/E2E canary on the merged code (§7.4). A failing canary on PRECISE evidence is
    what the rollback policy engine acts on (canary.py)."""
    from .graders import pytest_spec

    return Stage("post_merge", [pytest_spec(repo, covers, paths=smoke_paths)],
                 required={GraderKind.TEST})


def premerge_stage(repo: str, *, covers: list[str] | None = None, with_types: bool = True) -> Stage:
    """Full suite + lint (+types) — the sandbox-CI gate before a merge is allowed (§7.4).
    Pair with a regression-guard by passing a ledger to run_stage."""
    from .graders import mypy_spec, pytest_spec, ruff_spec

    graders = [pytest_spec(repo, covers), ruff_spec(repo, covers)]
    required = {GraderKind.TEST, GraderKind.LINT}
    if with_types:
        graders.append(mypy_spec(repo, covers))
        required.add(GraderKind.TYPECHECK)
    return Stage("pre_merge", graders, required)
