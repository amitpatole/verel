"""Code graders on the verdict bus (§7.4) — tests, lint, typecheck as first-class senses.

So far the only sense was sight (AgentVision). These graders make the verdict bus do what it
was designed for: unify vision + tests + lint + types into ONE schema, ONE stuck/progress
signal, ONE gate. Each grader produces a `Report` with the right `grader` (TEST/LINT/
TYPECHECK), per-issue `source`+`detail` (so §7.2 fingerprints are stable), and a signed
`RunReceipt` attesting it actually ran the frozen suite over the changed files (§7.1).

Parsers are pure functions over tool stdout, so they're tested without invoking the tools;
the command runner is injectable for the same reason.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from hashlib import blake2s
from typing import Callable

from ..verdict.fingerprint import assign
from ..verdict.gate import sign_receipt
from ..verdict.models import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    Report,
    RunReceipt,
    Severity,
    Verdict,
)

# (cmd, cwd) -> (returncode, stdout, stderr)
Runner = Callable[[list[str], "str | None"], tuple[int, str, str]]


def subprocess_runner(cmd: list[str], cwd: str | None = None, *, timeout: int = 300):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


@dataclass
class GraderSpec:
    grader: GraderKind
    command: list[str]
    cwd: str | None = None
    covers: list[str] = field(default_factory=list)  # files this grader scanned (for receipt)


def suite_sha(spec: GraderSpec) -> str:
    """Deterministic identity of the frozen suite — same command => same sha. The pipeline
    pins this independently; if an attacker swaps the suite, the sha (and gate) diverge."""
    return blake2s(json.dumps([spec.grader.value, spec.command]).encode()).hexdigest()[:16]


def _receipt(spec: GraderSpec, runner_identity: str = "ci-runner") -> RunReceipt:
    covered = ",".join(spec.covers) or "(repo)"
    rr = RunReceipt(
        suite_sha=suite_sha(spec),
        inputs_digest=blake2s(covered.encode()).hexdigest()[:16],
        coverage_assertion=f"scanned files: {covered}",
        runner_identity=runner_identity, signature="",
    )
    rr.signature = sign_receipt(rr)
    return rr


# ---------------------------------------------------------------------------
# Parsers (pure).
# ---------------------------------------------------------------------------
_PYTEST_FAIL = re.compile(r"^(?:FAILED|ERROR)\s+(\S+?)(?:\s+-\s+(.*))?$", re.MULTILINE)
_RUFF = re.compile(r"^(.+?):(\d+):(\d+):\s+([A-Z]+\d+)\s+(.*)$", re.MULTILINE)
_MYPY = re.compile(r"^(.+?):(\d+):(?:\d+:)?\s+error:\s+(.*?)(?:\s+\[([a-z-]+)\])?$", re.MULTILINE)


def parse_pytest(out: str, err: str = "") -> list[Issue]:
    issues = []
    for nodeid, reason in _PYTEST_FAIL.findall(out + "\n" + err):
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TEST,
            message=(reason or "test failed").strip(), locator=nodeid,
            detail_json=json.dumps({"test_id": nodeid}),
        ))
    return issues


def parse_ruff(out: str, err: str = "") -> list[Issue]:
    issues = []
    for path, line, col, code, msg in _RUFF.findall(out):
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.LINT,
            message=f"{code} {msg}", locator=f"{path}:{line}",
            detail_json=json.dumps({"rule_id": code}),
        ))
    return issues


def parse_mypy(out: str, err: str = "") -> list[Issue]:
    issues = []
    for path, line, msg, code in _MYPY.findall(out):
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TYPECHECK,
            message=msg.strip(), locator=f"{path}:{line}",
            detail_json=json.dumps({"rule_code": code or "type", "symbol": ""}),
        ))
    return issues


_PARSERS = {
    GraderKind.TEST: parse_pytest,
    GraderKind.LINT: parse_ruff,
    GraderKind.TYPECHECK: parse_mypy,
}


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------
def run_grader(spec: GraderSpec, runner: Runner = subprocess_runner) -> Report:
    """Execute a grader and map its output into an attested verdict-bus Report."""
    parse = _PARSERS[spec.grader]
    try:
        rc, out, err = runner(spec.command, spec.cwd)
    except FileNotFoundError as e:
        # tool not installed => did-NOT-run (errored), NOT a clean pass (no silent green).
        return Report(verdict=Verdict.FAIL, summary=f"{spec.grader.value}: tool missing ({e})",
                      grader=spec.grader, errored=True)
    except subprocess.TimeoutExpired:
        return Report(verdict=Verdict.FAIL, summary=f"{spec.grader.value}: timed out",
                      grader=spec.grader, errored=True)

    issues = parse(out, err)
    report = Report(
        verdict=Verdict.FAIL if issues else (Verdict.PASS if rc == 0 else Verdict.FAIL),
        summary=f"{spec.grader.value}: {len(issues)} issue(s), exit={rc}",
        issues=issues, grader=spec.grader, run_receipt=_receipt(spec),
        # ran-but-no-parseable-issues yet nonzero exit => the tool itself errored, not a clean fail
        errored=(rc != 0 and not issues),
    )
    return assign(report)


# Convenience constructors for the common stdlib-ish toolchain.
def pytest_spec(repo: str, covers: list[str] | None = None, *, paths: list[str] | None = None):
    # `-B`: never write/read .pyc. The ultracode loop edits source in place and re-tests
    # within the same second; same-size edits + 1s mtime granularity make a stale .pyc pass
    # old bytecode (a false verdict). -B forces a fresh compile every run.
    cmd = ["python", "-B", "-m", "pytest", "-q", "--tb=line", "-rfE", "-p", "no:cacheprovider",
           *(paths or [])]
    return GraderSpec(GraderKind.TEST, cmd, cwd=repo, covers=covers or [])


def ruff_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.LINT, ["ruff", "check", "--output-format=concise", "."],
                      cwd=repo, covers=covers or [])


def mypy_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.TYPECHECK, ["mypy", "--no-error-summary", "."],
                      cwd=repo, covers=covers or [])
