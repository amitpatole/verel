"""Broadened senses (§7.4) — JS/Go/perf/security graders on the same verdict bus.

Parsers are pure over canned tool output, so the whole matrix runs offline with no node/go/
bandit/npm installed — the command runner is injected."""

import json

from verel.ci import (
    LANGS,
    inner_loop_stage,
    jstest_spec,
    parse_bandit,
    parse_eslint,
    parse_go_test,
    parse_go_vet,
    parse_npm_audit,
    parse_perf,
    parse_tap,
    parse_tsc,
    perf_spec,
    premerge_stage,
    run_grader,
    run_stage,
)
from verel.verdict import GraderKind, Severity, Verdict


def _runner(rc, out, err=""):
    return lambda cmd, cwd=None: (rc, out, err)


# ---- JS/TS parsers ----
def test_parse_tap_failures_only():
    out = "TAP version 13\nok 1 - adds\nnot ok 2 - login returns 200\nnot ok 3 - flaky # SKIP\n"
    issues = parse_tap(out)
    assert [i.locator for i in issues] == ["login returns 200"]  # ok + skipped excluded
    assert all(i.source == GraderKind.TEST for i in issues)


def test_parse_eslint_json_severity():
    out = json.dumps([{"filePath": "a.js", "messages": [
        {"ruleId": "no-unused-vars", "severity": 2, "message": "x unused", "line": 3},
        {"ruleId": "eqeqeq", "severity": 1, "message": "use ===", "line": 9}]}])
    issues = parse_eslint(out)
    assert {i.severity for i in issues} == {Severity.ERROR, Severity.WARNING}
    assert issues[0].locator == "a.js:3" and issues[0].source == GraderKind.LINT


def test_parse_tsc():
    issues = parse_tsc("src/a.ts(12,5): error TS2322: Type 'string' is not assignable to 'number'.")
    assert len(issues) == 1 and issues[0].locator == "src/a.ts:12"
    assert issues[0].source == GraderKind.TYPECHECK and "TS2322" in issues[0].message


# ---- Go parsers ----
def test_parse_go_test_json():
    lines = [{"Action": "run", "Test": "TestA"},
             {"Action": "fail", "Package": "pkg/x", "Test": "TestA"},
             {"Action": "fail", "Package": "pkg/x", "Test": "TestA"},  # duplicate event
             {"Action": "pass", "Test": "TestB"}]
    issues = parse_go_test("\n".join(json.dumps(o) for o in lines))
    assert [i.locator for i in issues] == ["pkg/x.TestA"]  # de-duped, only the failure
    assert issues[0].source == GraderKind.TEST


def test_parse_go_vet():
    issues = parse_go_vet("main.go:10:2: unreachable code\nutil.go:3: missing return")
    assert {i.locator for i in issues} == {"main.go:10", "util.go:3"}
    assert all(i.source == GraderKind.LINT for i in issues)


# ---- perf (precise, against an explicit budget) ----
def test_parse_perf_only_flags_over_budget():
    out = json.dumps({"metrics": {"p95_ms": 250, "rps": 1200}})
    issues = parse_perf(out, "", {"p95_ms": 100, "rps": 1000})  # p95 over, rps under (higher=better? no: over)
    flagged = {i.locator for i in issues}
    assert "p95_ms" in flagged and "rps" in flagged  # both exceed their budget
    assert all(i.source == GraderKind.PERF and i.severity == Severity.ERROR for i in issues)


def test_parse_perf_within_budget_is_clean():
    assert parse_perf(json.dumps({"metrics": {"p95_ms": 80}}), "", {"p95_ms": 100}) == []


# ---- security (HIGH/CRITICAL gate, lower advise) ----
def test_parse_bandit_severity_mapping():
    out = json.dumps({"results": [
        {"filename": "a.py", "line_number": 3, "issue_severity": "HIGH",
         "issue_text": "eval used", "test_id": "B307"},
        {"filename": "b.py", "line_number": 9, "issue_severity": "LOW",
         "issue_text": "assert", "test_id": "B101"}]})
    sev = {i.detail["rule_id"]: i.severity for i in parse_bandit(out)}
    assert sev["B307"] == Severity.ERROR and sev["B101"] == Severity.INFO


def test_parse_npm_audit():
    out = json.dumps({"vulnerabilities": {"lodash": {"severity": "critical",
                     "via": [{"title": "Prototype Pollution"}]}}})
    issues = parse_npm_audit(out)
    assert len(issues) == 1 and issues[0].severity == Severity.CRITICAL
    assert issues[0].source == GraderKind.SECURITY


# ---- the graders ride the bus: attested Reports, severity-correct gating ----
def test_js_test_grader_is_attested_and_parses_tap():
    rep = run_grader(jstest_spec("/repo"), runner=_runner(1, "not ok 1 - boom\n"))
    assert rep.verdict == Verdict.FAIL and rep.run_receipt is not None and not rep.errored
    assert rep.issues and rep.issues[0].fingerprint  # fingerprint assigned on the bus


def test_security_low_finding_warns_not_gates():
    # a LOW bandit finding maps to INFO -> the gate does NOT fail on it (severity-based gating)
    out = json.dumps({"results": [{"filename": "b.py", "line_number": 9,
                     "issue_severity": "LOW", "issue_text": "assert", "test_id": "B101"}]})
    stage = premerge_stage("/repo", with_types=False, security=True)
    res = run_stage(stage, runner=lambda cmd, cwd=None: (
        (0, "", "") if "pytest" in cmd or "ruff" in cmd else (1, out, "")))
    # tests+lint clean, security only INFO -> overall not a gating FAIL
    assert res.verdict != Verdict.FAIL


# ---- language presets ----
def test_lang_registry_has_python_js_go():
    assert set(LANGS) == {"python", "js", "go"}
    assert LANGS["go"].typecheck is None  # Go has no separate typecheck sense here


def test_inner_loop_stage_go_uses_go_toolchain():
    stage = inner_loop_stage("/repo", language="go")
    kinds = [(g.grader, g.lang) for g in stage.graders]
    assert (GraderKind.TEST, "go") in kinds and (GraderKind.LINT, "go") in kinds


def test_premerge_js_with_security_and_perf():
    perf = perf_spec("/repo", ["bench"], {"p95_ms": 100})
    stage = premerge_stage("/repo", language="js", security=True, perf=perf)
    langs = {g.grader: g.lang for g in stage.graders}
    assert GraderKind.SECURITY in langs and GraderKind.PERF in langs
    assert GraderKind.TYPECHECK in langs and langs[GraderKind.TEST] == "js"
    assert {GraderKind.TEST, GraderKind.SECURITY, GraderKind.PERF} <= stage.required


def test_unknown_grader_without_parser_errors_cleanly():
    from verel.ci import GraderSpec

    rep = run_grader(GraderSpec(GraderKind.COST, ["true"]), runner=_runner(0, ""))
    assert rep.errored and "no parser" in rep.summary
