"""IaC graders (IAC-KICKOFF.md Phase 1) — validate, plan drift, trivy. Pure over canned output."""

import json

from verel.ci import (
    destructive_changes,
    parse_terraform_plan,
    parse_terraform_validate,
    parse_trivy_config,
    plan_summary,
    run_grader,
    terraform_validate_spec,
)
from verel.verdict import GraderKind, Severity, Verdict
from verel.verdict.constants import PRECISE_GRADERS


def _runner(rc, out, err=""):
    return lambda cmd, cwd=None: (rc, out, err)


def test_iac_kinds_are_precise():
    # IAC/IAM/POLICY/COST gate — they are deterministic evidence, not advisory opinion.
    assert {GraderKind.IAC, GraderKind.IAM, GraderKind.POLICY, GraderKind.COST} <= PRECISE_GRADERS


def test_parse_validate_errors_gate():
    out = json.dumps({"valid": False, "diagnostics": [
        {"severity": "error", "summary": "Missing required argument",
         "range": {"filename": "main.tf", "start": {"line": 12}}},
        {"severity": "warning", "summary": "Deprecated attribute",
         "range": {"filename": "main.tf", "start": {"line": 4}}}]})
    issues = parse_terraform_validate(out)
    assert [i.severity for i in issues] == [Severity.ERROR, Severity.WARNING]
    assert issues[0].locator == "main.tf:12" and issues[0].source == GraderKind.IAC


def test_parse_validate_clean():
    assert parse_terraform_validate(json.dumps({"valid": True, "diagnostics": []})) == []


def _plan(*changes):
    return json.dumps({"resource_changes": list(changes)})


def test_plan_summary_and_destructive():
    plan = json.loads(_plan(
        {"address": "aws_s3_bucket.a", "type": "aws_s3_bucket", "change": {"actions": ["create"]}},
        {"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"actions": ["delete"]}},
        {"address": "aws_instance.c", "type": "aws_instance", "change": {"actions": ["create", "delete"]}},
        {"address": "aws_instance.d", "type": "aws_instance", "change": {"actions": ["no-op"]}}))
    assert plan_summary(plan) == {"create": 1, "update": 0, "delete": 1, "replace": 1, "no-op": 1}
    # destroy + replace are both destructive (both contain "delete")
    assert set(destructive_changes(plan)) == {"aws_s3_bucket.b", "aws_instance.c"}


def test_plan_destroy_is_info_not_gating():
    out = _plan({"address": "aws_db_instance.prod", "type": "aws_db_instance",
                 "change": {"actions": ["delete"]}})
    issues = parse_terraform_plan(out)
    assert len(issues) == 1
    i = issues[0]
    # destroy is surfaced for review + gateway escalation, but INFO so it doesn't hard-fail the gate.
    assert i.severity == Severity.INFO and i.source == GraderKind.IAC
    assert "aws_db_instance.prod" in i.message


def test_parse_trivy_config_misconfig():
    out = json.dumps({"Results": [{"Target": "main.tf", "Misconfigurations": [
        {"ID": "AVD-AWS-0086", "Severity": "HIGH", "Title": "S3 bucket is public",
         "CauseMetadata": {"StartLine": 7}},
        {"ID": "AVD-AWS-0001", "Severity": "LOW", "Title": "Minor", "CauseMetadata": {"StartLine": 2}}]}]})
    issues = parse_trivy_config(out)
    assert {i.severity for i in issues} == {Severity.ERROR, Severity.INFO}
    assert issues[0].source == GraderKind.SECURITY and issues[0].locator == "main.tf:7"


def test_run_grader_wires_iac_kind():
    spec = terraform_validate_spec(".")
    report = run_grader(spec, runner=_runner(1, json.dumps(
        {"valid": False, "diagnostics": [
            {"severity": "error", "summary": "boom", "range": {"filename": "x.tf", "start": {"line": 1}}}]})))
    assert report.verdict == Verdict.FAIL and report.grader == GraderKind.IAC
    assert report.run_receipt is not None  # attested like every other grader


def test_run_grader_clean_plan_passes():
    from verel.ci import terraform_plan_spec
    report = run_grader(terraform_plan_spec("."), runner=_runner(0, _plan(
        {"address": "aws_s3_bucket.a", "type": "aws_s3_bucket", "change": {"actions": ["create"]}})))
    assert report.verdict == Verdict.PASS and report.grader == GraderKind.IAC
