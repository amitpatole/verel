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
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import blake2s
from pathlib import Path

from ..verdict.fingerprint import assign
from ..verdict.gate import sign_receipt
from ..verdict.models import (
    GraderKind,
    Issue,
    IssueKind,
    Report,
    RunReceipt,
    Severity,
    Verdict,
    report_result_digest,
)

# (cmd, cwd) -> (returncode, stdout, stderr)
Runner = Callable[[list[str], "str | None"], tuple[int, str, str]]


def subprocess_runner(cmd: list[str], cwd: str | None = None, *, timeout: int = 300):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# A parser is a pure function over (stdout, stderr) -> issues. Keying parse off the GraderSpec
# (not off GraderKind) is what lets pytest, `go test`, and jest — all GraderKind.TEST — be parsed
# by their own format while sharing one bus, one gate, one stuck/progress signal.
Parser = Callable[[str, str], "list[Issue]"]


@dataclass
class GraderSpec:
    grader: GraderKind
    command: list[str]
    cwd: str | None = None
    covers: list[str] = field(default_factory=list)  # files this grader scanned (for receipt)
    parser: Parser | None = None  # defaults to the Python-toolchain parser for `grader`
    lang: str = "python"  # provenance/label only


def suite_sha(spec: GraderSpec) -> str:
    """Deterministic identity of the frozen suite — same command => same sha. The pipeline
    pins this independently; if an attacker swaps the suite, the sha (and gate) diverge."""
    return blake2s(json.dumps([spec.grader.value, spec.command]).encode()).hexdigest()[:16]


def content_digest(cwd: str | None, covers: list[str]) -> str:
    """Digest the ACTUAL bytes the grader scanned (not just the filenames), so a receipt is bound to
    the input it graded — a PASS receipt can't be replayed onto different code with the same paths."""
    h = blake2s()
    for f in sorted(covers):
        h.update(f.encode())
        h.update(b"\0")
        try:
            h.update((Path(cwd or ".") / f).read_bytes())
        except OSError:
            h.update(b"<absent>")
        h.update(b"\0")
    return h.hexdigest()[:16]


def bound_input_digest(cwd: str | None, covers: list[str], nonce: str = "") -> str:
    """The receipt's input binding: the scanned-content digest SALTED with a per-run nonce. The
    content digest alone is vacuous when `covers` is empty (a constant); the nonce makes every run's
    receipt unique, so a PASS receipt can't be replayed into a later run regardless of `covers`."""
    return blake2s(f"{content_digest(cwd, covers)}:{nonce}".encode()).hexdigest()[:16]


def _receipt(spec: GraderSpec, report: Report, runner_identity: str = "ci-runner",
             nonce: str = "", attest: str = "hmac") -> RunReceipt:
    covered = ",".join(spec.covers) or "(repo)"
    rr = RunReceipt(
        suite_sha=suite_sha(spec),
        inputs_digest=bound_input_digest(spec.cwd, spec.covers, nonce),
        coverage_assertion=f"scanned files: {covered}",
        runner_identity=runner_identity,
        result_digest=report_result_digest(report), signature="",
    )
    if attest == "ed25519":
        # Mint a PUBLICLY-verifiable receipt (substrate §11): a second party can confirm this grader
        # ran with only the runner's public key. attest_self stamps the ed25519 identity + signs.
        from ..verdict import keys
        keys.attest_self(rr)
    else:
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
    for path, line, _col, code, msg in _RUFF.findall(out):
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
def run_grader(spec: GraderSpec, runner: Runner = subprocess_runner, *, nonce: str = "",
               attest: str = "hmac") -> Report:
    """Execute a grader and map its output into an attested verdict-bus Report. `nonce` salts the
    receipt's input binding so it can't be replayed into a different run (set by `run_stage`).
    `attest` selects the receipt scheme: "hmac" (default, in-domain) or "ed25519" (publicly verifiable)."""
    parse = spec.parser or _PARSERS.get(spec.grader)
    if parse is None:
        return Report(verdict=Verdict.FAIL, grader=spec.grader, errored=True,
                      summary=f"{spec.grader.value}: no parser configured")
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
        issues=issues, grader=spec.grader,
        # ran-but-no-parseable-issues yet nonzero exit => the tool itself errored, not a clean fail
        errored=(rc != 0 and not issues),
    )
    report = assign(report)                       # populate issue fingerprints BEFORE signing...
    report.run_receipt = _receipt(spec, report, nonce=nonce, attest=attest)  # ...bind result + nonce
    return report


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


# ===========================================================================
# JavaScript / TypeScript senses.
# ===========================================================================
# node:test, tape, and most runners emit TAP; `not ok N - desc` is a failure (skip/todo aren't).
_TAP_NOTOK = re.compile(r"^not ok\s+\d+\s*-?\s*(.*)$", re.MULTILINE)
_TSC = re.compile(r"^(.+?)\((\d+),(\d+)\):\s+error\s+(TS\d+):\s+(.*)$", re.MULTILINE)


def parse_tap(out: str, err: str = "") -> list[Issue]:
    issues = []
    for desc in _TAP_NOTOK.findall(out + "\n" + err):
        d = desc.strip()
        if "# skip" in d.lower() or "# todo" in d.lower():
            continue  # TAP directives — not failures
        name = d.split("#", 1)[0].strip() or "test failed"
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TEST,
            message=name, locator=name, detail_json=json.dumps({"test_id": name}),
        ))
    return issues


def parse_eslint(out: str, err: str = "") -> list[Issue]:
    """ESLint `--format json`: a list of {filePath, messages:[{ruleId,severity,message,line}]}."""
    issues: list[Issue] = []
    try:
        data = json.loads(out or "[]")
    except json.JSONDecodeError:
        return issues
    for f in data if isinstance(data, list) else []:
        path = f.get("filePath", "")
        for m in f.get("messages", []):
            sev = Severity.ERROR if m.get("severity") == 2 else Severity.WARNING
            rule = m.get("ruleId") or "eslint"
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=sev, source=GraderKind.LINT,
                message=f"{rule} {m.get('message', '')}".strip(),
                locator=f"{path}:{m.get('line', '')}", detail_json=json.dumps({"rule_id": rule}),
            ))
    return issues


def parse_tsc(out: str, err: str = "") -> list[Issue]:
    issues = []
    for path, line, _col, code, msg in _TSC.findall(out + "\n" + err):
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TYPECHECK,
            message=f"{code} {msg.strip()}", locator=f"{path}:{line}",
            detail_json=json.dumps({"rule_code": code}),
        ))
    return issues


def jstest_spec(repo: str, covers: list[str] | None = None, *, paths: list[str] | None = None):
    # node's built-in test runner emits TAP; runner-agnostic so vitest/tape/mocha-tap work too.
    return GraderSpec(GraderKind.TEST, ["node", "--test", *(paths or [])],
                      cwd=repo, covers=covers or [], parser=parse_tap, lang="js")


def eslint_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.LINT, ["npx", "--no-install", "eslint", ".", "--format", "json"],
                      cwd=repo, covers=covers or [], parser=parse_eslint, lang="js")


def tsc_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.TYPECHECK,
                      ["npx", "--no-install", "tsc", "--noEmit", "--pretty", "false"],
                      cwd=repo, covers=covers or [], parser=parse_tsc, lang="js")


# ===========================================================================
# Go senses.
# ===========================================================================
_GOVET = re.compile(r"^(.+?\.go):(\d+):(?:\d+:)?\s+(.*)$", re.MULTILINE)


def parse_go_test(out: str, err: str = "") -> list[Issue]:
    """`go test -json`: one JSON event per line; a {"Action":"fail","Test":...} is a failure."""
    issues: list[Issue] = []
    seen: set[str] = set()
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("Action") == "fail" and o.get("Test"):
            loc = f"{o.get('Package', '')}.{o['Test']}"
            if loc in seen:
                continue
            seen.add(loc)
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TEST,
                message=f"{o['Test']} failed", locator=loc, detail_json=json.dumps({"test_id": loc}),
            ))
    return issues


def parse_go_vet(out: str, err: str = "") -> list[Issue]:
    issues = []
    for path, line, msg in _GOVET.findall(out + "\n" + err):
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.LINT,
            message=msg.strip(), locator=f"{path}:{line}", detail_json=json.dumps({"rule_id": "vet"}),
        ))
    return issues


def gotest_spec(repo: str, covers: list[str] | None = None, *, paths: list[str] | None = None):
    return GraderSpec(GraderKind.TEST, ["go", "test", "-json", *(paths or ["./..."])],
                      cwd=repo, covers=covers or [], parser=parse_go_test, lang="go")


def govet_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.LINT, ["go", "vet", "./..."],
                      cwd=repo, covers=covers or [], parser=parse_go_vet, lang="go")


# ===========================================================================
# Perf sense — a PRECISE grader, but only against an EXPLICIT budget (never inferred).
# ===========================================================================
def parse_perf(out: str, err: str = "", budgets: dict[str, float] | None = None) -> list[Issue]:
    """The benchmark command prints JSON `{"metrics": {name: value}}` (or a flat `{name: value}`);
    each metric that exceeds its budget is an ERROR (gating). A regression is precise evidence —
    so a perf failure CAN gate / drive rollback, unlike an advisory opinion."""
    budgets = budgets or {}
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return []
    metrics = data.get("metrics", data) if isinstance(data, dict) else {}
    issues = []
    for name, budget in budgets.items():
        val = metrics.get(name) if isinstance(metrics, dict) else None
        if isinstance(val, (int, float)) and val > budget:
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.PERF,
                message=f"{name} {val} exceeds budget {budget}", locator=name,
                detail_json=json.dumps({"metric": name, "value": val, "budget": budget}),
            ))
    return issues


def perf_spec(repo: str, command: list[str], budgets: dict[str, float],
              covers: list[str] | None = None):
    def parse(out: str, err: str = "") -> list[Issue]:
        return parse_perf(out, err, budgets)

    return GraderSpec(GraderKind.PERF, command, cwd=repo, covers=covers or [],
                      parser=parse, lang="any")


# ===========================================================================
# Security sense — SAST / dependency audit. PRECISE; HIGH/CRITICAL gate, lower advise.
# ===========================================================================
_SEC_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.ERROR, "moderate": Severity.WARNING,
    "medium": Severity.WARNING, "low": Severity.INFO, "info": Severity.INFO,
}


def _sec_severity(s: str) -> Severity:
    return _SEC_SEV.get((s or "low").lower(), Severity.WARNING)


def parse_bandit(out: str, err: str = "") -> list[Issue]:
    """Bandit `-f json`: {"results":[{filename,line_number,issue_severity,issue_text,test_id}]}."""
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return []
    issues = []
    for r in data.get("results", []):
        tid = r.get("test_id", "")
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=_sec_severity(r.get("issue_severity", "low")),
            source=GraderKind.SECURITY, message=f"{tid} {r.get('issue_text', '')}".strip(),
            locator=f"{r.get('filename', '')}:{r.get('line_number', '')}",
            detail_json=json.dumps({"rule_id": tid}),
        ))
    return issues


def parse_npm_audit(out: str, err: str = "") -> list[Issue]:
    """`npm audit --json` (v2): {"vulnerabilities":{name:{severity,via:[{title}]}}}."""
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return []
    vulns = data.get("vulnerabilities", {})
    issues = []
    for name, v in (vulns.items() if isinstance(vulns, dict) else []):
        via = v.get("via", [])
        title = next((x.get("title") for x in via if isinstance(x, dict) and x.get("title")), name)
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=_sec_severity(v.get("severity", "low")),
            source=GraderKind.SECURITY, message=f"{name}: {title}", locator=name,
            detail_json=json.dumps({"rule_id": name}),
        ))
    return issues


# Dirs that are never the shipped attack surface — bandit on a whole repo otherwise drowns the gate in
# test-only patterns (every `assert` is B101) and vendored/third-party code under a local virtualenv.
_BANDIT_EXCLUDE = "./tests,./test,./.venv,./venv,./env,./build,./dist,./.git,./node_modules,./.tox"


def bandit_spec(repo: str, covers: list[str] | None = None, *, paths: list[str] | None = None):
    # Match the documented intent — a HIGH/CRITICAL *gate*, not a lint of every advisory LOW. `bandit`
    # exits non-zero (→ FAIL) only when a finding at/above the floor exists; LOW/MEDIUM stay advisory.
    # `--severity-level high` + `--confidence-level medium` is the floor; tests/vendored dirs excluded.
    return GraderSpec(GraderKind.SECURITY,
                      ["bandit", "-r", "-q", "-f", "json",
                       "--severity-level", "high", "--confidence-level", "medium",
                       "--exclude", _BANDIT_EXCLUDE, *(paths or ["."])],
                      cwd=repo, covers=covers or [], parser=parse_bandit, lang="python")


def npm_audit_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.SECURITY, ["npm", "audit", "--json"],
                      cwd=repo, covers=covers or [], parser=parse_npm_audit, lang="js")


# ===========================================================================
# Language toolchains — pick a test/lint/typecheck triple by language.
# ===========================================================================
@dataclass
class LangToolchain:
    test: Callable[..., GraderSpec]
    lint: Callable[..., GraderSpec] | None
    typecheck: Callable[..., GraderSpec] | None


LANGS: dict[str, LangToolchain] = {
    "python": LangToolchain(pytest_spec, ruff_spec, mypy_spec),
    "js": LangToolchain(jstest_spec, eslint_spec, tsc_spec),
    "go": LangToolchain(gotest_spec, govet_spec, None),
}
