"""Cloud credential resolution + effective-access verifier (IAC-KICKOFF.md Phase 5).

Resolver is tested against a fake ~/.config tree; verifier parsers are pure over canned cloud-CLI
JSON; the verifier's env-runner is injected (offline). Secret values must never appear in a repr."""

import json

from verel.actuators import (
    CloudCreds,
    EffectiveAccessVerifier,
    parse_aws_simulate,
    parse_aws_validate_policy,
    parse_az_role_assignments,
    parse_gcp_analyze_iam,
    resolve_aws,
    resolve_azure,
    resolve_gcp,
)
from verel.verdict import GraderKind, Severity, Verdict


# --- credential resolution ----------------------------------------------
def test_resolve_aws_from_rootkey_csv(tmp_path):
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    # utf-8-sig BOM + the real column headers from `rootkey.csv`
    (awsd / "rootkey.csv").write_text("﻿Access key ID,Secret access key\nAKIAEXAMPLE,sshhhh\n")
    cc = resolve_aws(config_home=tmp_path)
    assert cc.available and cc.cloud == "aws"
    assert cc.env["AWS_ACCESS_KEY_ID"] == "AKIAEXAMPLE"
    assert cc.env["AWS_SECRET_ACCESS_KEY"] == "sshhhh"


def test_resolve_aws_absent_fails_closed(tmp_path):
    cc = resolve_aws(config_home=tmp_path)
    assert cc.available is False and cc.env == {}


def test_creds_repr_never_leaks_secrets(tmp_path):
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    (awsd / "rootkey.csv").write_text("Access key ID,Secret access key\nAKIA,TOPSECRETVALUE\n")
    cc = resolve_aws(config_home=tmp_path)
    text = repr(cc)
    assert "TOPSECRETVALUE" not in text and "AKIA" not in text
    assert "AWS_SECRET_ACCESS_KEY" in text  # key NAME is fine, value is not


def test_resolve_gcp_service_account(tmp_path):
    gcpd = tmp_path / "gcp"
    gcpd.mkdir()
    (gcpd / "sa.json").write_text(json.dumps({"type": "service_account", "project_id": "proj-x",
                                              "client_email": "x@proj.iam", "private_key": "KEY"}))
    (tmp_path / "gcloud").mkdir()
    cc = resolve_gcp(config_home=tmp_path)
    assert cc.available and cc.project == "proj-x"
    assert cc.env["GOOGLE_APPLICATION_CREDENTIALS"].endswith("sa.json")
    assert cc.env["CLOUDSDK_CONFIG"].endswith("gcloud")


def test_resolve_gcp_no_service_account_fails_closed(tmp_path):
    (tmp_path / "gcloud").mkdir()  # config dir but no SA key → cannot auth non-interactively
    cc = resolve_gcp(config_home=tmp_path)
    assert cc.available is False


def test_resolve_azure_config_dir(tmp_path):
    home = tmp_path / "home"
    (home / ".azure").mkdir(parents=True)
    cc = resolve_azure(config_home=tmp_path, home=home)
    assert cc.available and cc.env["AZURE_CONFIG_DIR"].endswith(".azure")


# --- AWS parsers ---------------------------------------------------------
def test_parse_aws_validate_policy_severities():
    out = json.dumps({"findings": [
        {"findingType": "ERROR", "issueCode": "INVALID_ARN", "findingDetails": "bad arn"},
        {"findingType": "SECURITY_WARNING", "issueCode": "PASS_ROLE_WITH_STAR_RESOURCE",
         "findingDetails": "passrole on *"},
        {"findingType": "SUGGESTION", "issueCode": "REDUNDANT", "findingDetails": "x"}]})
    issues = parse_aws_validate_policy(out)
    sev = {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}
    assert sev["INVALID_ARN"] == Severity.ERROR
    assert sev["PASS_ROLE_WITH_STAR_RESOURCE"] == Severity.ERROR  # security warning gates
    assert sev["REDUNDANT"] == Severity.INFO
    assert all(i.source == GraderKind.IAM for i in issues)


def test_parse_aws_simulate_flags_allowed_sensitive():
    out = json.dumps({"EvaluationResults": [
        {"EvalActionName": "iam:PassRole", "EvalDecision": "allowed", "EvalResourceName": "*"},
        {"EvalActionName": "s3:GetObject", "EvalDecision": "allowed", "EvalResourceName": "arn:x"},
        {"EvalActionName": "iam:PassRole", "EvalDecision": "implicitDeny", "EvalResourceName": "*"}]})
    issues = parse_aws_simulate(out)
    assert len(issues) == 1  # only the ALLOWED sensitive action
    assert "iam:PassRole" in issues[0].message and issues[0].severity == Severity.ERROR


# --- GCP / Azure parsers -------------------------------------------------
def test_parse_gcp_analyze_iam():
    out = json.dumps({"mainAnalysis": {"analysisResults": [
        {"iamBinding": {"role": "roles/owner", "members": ["user:a@x"]}},
        {"iamBinding": {"role": "roles/viewer", "members": ["allUsers"]}}]}})
    issues = parse_gcp_analyze_iam(out)
    rules = {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}
    assert rules["ADMIN_GRANT"] == Severity.ERROR
    assert rules["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_parse_az_role_assignments_broad_admin():
    out = json.dumps([
        {"principalName": "a", "roleDefinitionName": "Owner", "scope": "/subscriptions/abc"},
        {"principalName": "b", "roleDefinitionName": "Reader", "scope": "/subscriptions/abc"},
        {"principalName": "c", "roleDefinitionName": "Owner",
         "scope": "/subscriptions/abc/resourceGroups/rg/providers/x/y/z"}])  # narrow scope → ignored
    issues = parse_az_role_assignments(out)
    assert len(issues) == 1 and issues[0].severity == Severity.ERROR
    assert "/subscriptions/abc" in issues[0].message


def test_parsers_tolerate_garbage():
    for p in (parse_aws_validate_policy, parse_aws_simulate, parse_gcp_analyze_iam,
              parse_az_role_assignments):
        assert p("not json") == []


# --- verifier (env-runner injected) --------------------------------------
def _env_runner(rc, out, err=""):
    captured = {}

    def run(cmd, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return (rc, out, err)

    run.captured = captured  # type: ignore[attr-defined]
    return run


def test_verifier_fails_closed_without_creds():
    v = EffectiveAccessVerifier(runner=_env_runner(0, "{}"))
    rep = v.aws_validate_policy("p.json", CloudCreds("aws", available=False, source="/x"))
    assert rep.errored and rep.verdict == Verdict.FAIL


def test_verifier_passes_creds_env_and_grades():
    runner = _env_runner(0, json.dumps({"findings": [
        {"findingType": "ERROR", "issueCode": "BAD", "findingDetails": "d"}]}))
    creds = CloudCreds("aws", available=True, source="/x", env={"AWS_ACCESS_KEY_ID": "k"})
    rep = EffectiveAccessVerifier(runner=runner).aws_validate_policy("p.json", creds)
    assert rep.verdict == Verdict.FAIL and rep.grader == GraderKind.IAM
    assert runner.captured["env"] == {"AWS_ACCESS_KEY_ID": "k"}  # creds reached the subprocess


def test_verifier_cli_error_fails_closed():
    v = EffectiveAccessVerifier(runner=_env_runner(1, "", "AccessDenied"))
    creds = CloudCreds("azure", available=True, source="/x", env={"AZURE_CONFIG_DIR": "/d"})
    assert v.azure_role_assignments(creds).errored


# --- `verel verify-access` CLI subcommand (opt-in, online) ---------------
def test_cli_verify_access_fails_closed_without_creds(tmp_path, monkeypatch, capsys):
    from verel.cli import main as verel_main
    monkeypatch.setenv("HOME", str(tmp_path))  # empty fake home → no creds anywhere
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    rc = verel_main(["verify-access", "--cloud", "aws", "--policy-file", "p.json"])
    assert rc == 2 and "no aws credentials" in capsys.readouterr().err


def test_cli_verify_access_requires_scope_for_gcp(tmp_path, monkeypatch, capsys):
    # creds present (fake SA), but --scope missing → usage error (return 2), no provider call
    from verel.cli import main as verel_main
    gcpd = tmp_path / ".config" / "gcp"
    gcpd.mkdir(parents=True)
    (gcpd / "sa.json").write_text(json.dumps({"type": "service_account", "project_id": "p"}))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("verel.actuators.cloudcreds._config_home", lambda: tmp_path / ".config")
    rc = verel_main(["verify-access", "--cloud", "gcp"])
    assert rc == 2 and "--scope is required" in capsys.readouterr().err
