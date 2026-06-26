"""IaC Phase 2 graders (IAC-KICKOFF.md) — tflint, checkov, conftest/OPA, infracost, parliament,
cloudsplaining. Pure parsers over canned tool output; no binaries required."""

import json

from verel.ci import (
    parse_checkov,
    parse_cloudsplaining,
    parse_conftest,
    parse_infracost,
    parse_parliament,
    parse_tflint,
)
from verel.verdict import GraderKind, Severity


# --- tflint --------------------------------------------------------------
def test_parse_tflint_severities():
    out = json.dumps({"issues": [
        {"rule": {"name": "terraform_unused_declarations", "severity": "warning"},
         "message": "variable x is unused", "range": {"filename": "main.tf", "start": {"line": 3}}},
        {"rule": {"name": "aws_instance_invalid_type", "severity": "error"},
         "message": "bad type", "range": {"filename": "ec2.tf", "start": {"line": 9}}}], "errors": []})
    issues = parse_tflint(out)
    assert {i.severity for i in issues} == {Severity.WARNING, Severity.ERROR}
    assert all(i.source == GraderKind.LINT for i in issues)
    assert issues[1].locator == "ec2.tf:9"


def test_parse_tflint_internal_error_surfaces():
    issues = parse_tflint(json.dumps({"issues": [], "errors": [{"message": "config not found"}]}))
    assert len(issues) == 1 and issues[0].severity == Severity.ERROR


# --- checkov -------------------------------------------------------------
def test_parse_checkov_failed_only():
    out = json.dumps({"check_type": "terraform", "results": {"passed_checks": [{"check_id": "OK"}],
        "failed_checks": [
            {"check_id": "CKV_AWS_20", "check_name": "S3 not public", "file_path": "/s3.tf",
             "file_line_range": [1, 5], "severity": "HIGH", "resource": "aws_s3_bucket.x"}]}})
    issues = parse_checkov(out)
    assert len(issues) == 1
    assert issues[0].source == GraderKind.SECURITY and issues[0].severity == Severity.ERROR
    assert issues[0].locator == "/s3.tf:1" and "CKV_AWS_20" in issues[0].message


def test_parse_checkov_list_form():
    out = json.dumps([{"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_1", "check_name": "x", "file_path": "/a.tf", "file_line_range": [2, 2],
         "severity": "CRITICAL"}]}}, {"check_type": "secrets", "results": {"failed_checks": []}}])
    issues = parse_checkov(out)
    assert len(issues) == 1 and issues[0].severity == Severity.CRITICAL


def test_parse_checkov_null_severity_defaults_warning():
    out = json.dumps({"results": {"failed_checks": [
        {"check_id": "CKV_X", "check_name": "y", "file_path": "/a.tf", "file_line_range": [1, 1],
         "severity": None}]}})
    assert parse_checkov(out)[0].severity == Severity.WARNING


# --- conftest ------------------------------------------------------------
def test_parse_conftest_failures_gate_warnings_advise():
    out = json.dumps([{"filename": "deploy.yaml", "namespace": "main", "successes": 2,
                       "failures": [{"msg": "must set resource limits"}],
                       "warnings": [{"msg": "prefer non-root"}]}])
    issues = parse_conftest(out)
    sev_by_msg = {i.message: i.severity for i in issues}
    assert sev_by_msg["must set resource limits"] == Severity.ERROR
    assert sev_by_msg["prefer non-root"] == Severity.WARNING
    assert all(i.source == GraderKind.POLICY for i in issues)


def test_parse_conftest_clean():
    assert parse_conftest(json.dumps([{"filename": "a.yaml", "successes": 3, "failures": []}])) == []


# --- infracost (gates only vs an explicit budget) ------------------------
def test_parse_infracost_over_budget():
    out = json.dumps({"totalMonthlyCost": "1500.00", "diffTotalMonthlyCost": "300.00", "currency": "USD"})
    issues = parse_infracost(out, budgets={"monthly": 1000.0})
    assert len(issues) == 1 and issues[0].source == GraderKind.COST and issues[0].severity == Severity.ERROR


def test_parse_infracost_diff_budget():
    out = json.dumps({"totalMonthlyCost": "200", "diffTotalMonthlyCost": "250", "currency": "USD"})
    assert len(parse_infracost(out, budgets={"diff": 100.0})) == 1


def test_parse_infracost_no_budget_never_gates():
    out = json.dumps({"totalMonthlyCost": "9999", "diffTotalMonthlyCost": "9999"})
    assert parse_infracost(out, budgets={}) == []  # cost is never inferred — no budget, no gate


def test_parse_infracost_under_budget():
    out = json.dumps({"totalMonthlyCost": "50", "diffTotalMonthlyCost": "5"})
    assert parse_infracost(out, budgets={"monthly": 1000.0, "diff": 100.0}) == []


# --- parliament (AWS IAM policy linter) ----------------------------------
def test_parse_parliament_severity_floor():
    out = json.dumps([
        {"issue": "RESOURCE_STAR", "title": "wildcard resource", "severity": "HIGH",
         "location": {"filepath": "policy.json"}},
        {"issue": "CREDENTIALS_EXPOSURE", "title": "creds", "severity": "LOW", "location": {}}])
    issues = parse_parliament(out)
    assert {i.severity for i in issues} == {Severity.ERROR, Severity.INFO}
    assert all(i.source == GraderKind.IAM for i in issues)
    assert issues[0].locator == "policy.json"


# --- cloudsplaining (least-privilege risk buckets) -----------------------
def test_parse_cloudsplaining_buckets():
    out = json.dumps({"AdminPolicy": {
        "PrivilegeEscalation": [{"type": "CreateAccessKey"}],
        "DataExfiltration": ["s3:GetObject"],
        "ResourceExposure": [], "CredentialsExposure": ["iam:CreateAccessKey"]}})
    issues = parse_cloudsplaining(out)
    rules = {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}
    assert rules["PrivilegeEscalation"] == Severity.CRITICAL
    assert rules["DataExfiltration"] == Severity.ERROR
    assert rules["CredentialsExposure"] == Severity.ERROR
    assert "ResourceExposure" not in rules  # empty bucket → no finding
    assert all(i.source == GraderKind.IAM and i.locator == "AdminPolicy" for i in issues)


def test_parsers_tolerate_garbage():
    for p in (parse_tflint, parse_checkov, parse_conftest, parse_parliament, parse_cloudsplaining):
        assert p("not json") == []
    assert parse_infracost("not json", budgets={"monthly": 1.0}) == []
