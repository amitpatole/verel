"""Cloud credential resolution + effective-access verifier (IAC-KICKOFF.md Phase 5).

Resolver is tested against a fake ~/.config tree; verifier parsers are pure over canned cloud-CLI
JSON; the verifier's env-runner is injected (offline). Secret values must never appear in a repr."""

import json

import pytest

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
_AKID = "AKIAIIIIIIIIIIIIIIII"   # 20-char access-key-id shape (AKIA + 16)
_ASEC = "s" * 40                 # 40-char secret
_FULL_SA = {"type": "service_account", "project_id": "proj-x", "client_email": "x@proj.iam",
            "private_key": "-----KEY-----", "private_key_id": "abc123", "token_uri": "https://oauth2"}


def test_resolve_aws_from_rootkey_csv(tmp_path):
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    # utf-8-sig BOM + the real column headers from `rootkey.csv`
    (awsd / "rootkey.csv").write_text(f"﻿Access key ID,Secret access key\n{_AKID},{_ASEC}\n")
    cc = resolve_aws(config_home=tmp_path)
    assert cc.available and cc.cloud == "aws"
    assert cc.env["AWS_ACCESS_KEY_ID"] == _AKID
    assert cc.env["AWS_SECRET_ACCESS_KEY"] == _ASEC


def test_resolve_aws_rejects_garbage_shape(tmp_path):
    # Hardening: a non-empty but malformed row must NOT report available=True (red-team S3-F2).
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    (awsd / "rootkey.csv").write_text("Access key ID,Secret access key\nnot-a-key,short\n")
    assert resolve_aws(config_home=tmp_path).available is False


def test_resolve_aws_absent_fails_closed(tmp_path):
    cc = resolve_aws(config_home=tmp_path)
    assert cc.available is False and cc.env == {}


def test_creds_repr_never_leaks_secrets(tmp_path):
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    secret = "TOPSECRETVALUE" + "x" * 30
    (awsd / "rootkey.csv").write_text(f"Access key ID,Secret access key\n{_AKID},{secret}\n")
    cc = resolve_aws(config_home=tmp_path)
    assert cc.available
    text = repr(cc)
    assert secret not in text and _AKID not in text   # neither value appears
    assert "AWS_SECRET_ACCESS_KEY" in text            # key NAME is fine, value is not
    assert secret not in str(cc) and secret not in f"{cc}"


def test_source_is_never_a_secret(tmp_path):
    # Guard against a future refactor putting a credential value in `source` (the one printed field).
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    (awsd / "rootkey.csv").write_text(f"Access key ID,Secret access key\n{_AKID},{_ASEC}\n")
    cc = resolve_aws(config_home=tmp_path)
    assert cc.source not in cc.env.values() and _ASEC not in cc.source


def test_resolve_gcp_service_account(tmp_path):
    gcpd = tmp_path / "gcp"
    gcpd.mkdir()
    (gcpd / "sa.json").write_text(json.dumps(_FULL_SA))
    (tmp_path / "gcloud").mkdir()
    cc = resolve_gcp(config_home=tmp_path)
    assert cc.available and cc.project == "proj-x"
    assert cc.env["GOOGLE_APPLICATION_CREDENTIALS"].endswith("sa.json")
    assert cc.env["CLOUDSDK_CONFIG"].endswith("gcloud")


def test_resolve_gcp_no_service_account_fails_closed(tmp_path):
    (tmp_path / "gcloud").mkdir()  # config dir but no SA key → cannot auth non-interactively
    cc = resolve_gcp(config_home=tmp_path)
    assert cc.available is False


def test_resolve_gcp_stub_sa_rejected(tmp_path):
    # Hardening: a {"type":"service_account"} stub WITHOUT a real key must not report available
    # (red-team S3-F3 — plant-able first-match / shallow validation).
    gcpd = tmp_path / "gcp"
    gcpd.mkdir()
    (gcpd / "sa.json").write_text(json.dumps({"type": "service_account", "project_id": "p"}))
    assert resolve_gcp(config_home=tmp_path).available is False


def test_resolve_azure_requires_token_material(tmp_path):
    home = tmp_path / "home"
    (home / ".azure").mkdir(parents=True)
    # Empty ~/.azure (persists after `az logout`) must NOT report creds (red-team S3-F4).
    assert resolve_azure(config_home=tmp_path, home=home).available is False
    # azureProfile.json is a subscription list that ALSO persists after `az logout` — it is NOT token
    # material and must not report creds-present (round-7 R7-5).
    (home / ".azure" / "azureProfile.json").write_text("{}")
    assert resolve_azure(config_home=tmp_path, home=home).available is False
    # An actual token cache → creds present.
    (home / ".azure" / "msal_token_cache.json").write_text("{}")
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


def test_parsers_tolerate_nondict_elements():
    # Round-15 R15-1: a non-dict element in the cloud analyzer's result array must not crash the
    # parser (mirrors the R14-1 fail-closed contract; parity with parse_gcp_analyze_iam).
    assert parse_aws_validate_policy(json.dumps({"findings": ["x"]})) == []
    assert parse_aws_simulate(json.dumps({"EvaluationResults": ["x"]})) == []
    assert parse_aws_simulate(json.dumps({"EvaluationResults": "abc"})) == []
    assert parse_az_role_assignments(json.dumps(["x"])) == []
    assert parse_gcp_analyze_iam(json.dumps({"mainAnalysis": {"analysisResults": ["x"]}})) == []


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


def test_verifier_rc0_garbage_output_errors_not_pass():
    # Red-team S2-F5: rc==0 but non-JSON output must be errored, NOT a silent PASS (zero findings).
    v = EffectiveAccessVerifier(runner=_env_runner(0, "not json at all"))
    creds = CloudCreds("azure", available=True, source="/x", env={})
    rep = v.azure_role_assignments(creds)
    assert rep.errored and rep.verdict == Verdict.FAIL


def test_verifier_rejects_injected_scope():
    # Red-team S2-F2: a scope/policy_file that could inject a gcloud/aws option is refused.
    v = EffectiveAccessVerifier(runner=_env_runner(0, "{}"))
    creds = CloudCreds("gcp", available=True, source="/x", env={})
    with pytest.raises(ValueError):
        v.gcp_analyze_iam("--billing-project=evil", creds)


def test_verifier_runner_timeout_is_errored():
    import subprocess

    def hanging(_cmd, _env=None):
        raise subprocess.TimeoutExpired(cmd=_cmd, timeout=1)

    creds = CloudCreds("azure", available=True, source="/x", env={})
    assert EffectiveAccessVerifier(runner=hanging).azure_role_assignments(creds).errored


def test_verifier_rc0_empty_output_errors_not_pass():
    # Red-team R3-F5: rc==0 with empty stdout must be errored, not a silent PASS (these analyzers
    # always emit a JSON envelope on success — empty == soft-failure).
    creds = CloudCreds("gcp", available=True, source="/x", env={})
    rep = EffectiveAccessVerifier(runner=_env_runner(0, "")).gcp_analyze_iam("projects/p", creds)
    assert rep.errored and rep.verdict == Verdict.FAIL


def test_fifo_at_cred_path_does_not_hang(tmp_path):
    # Red-team R3-F3: a planted FIFO must not block resolve_* (O_NONBLOCK) → available False, no hang.
    import os
    if not hasattr(os, "mkfifo"):
        pytest.skip("no mkfifo")
    awsd = tmp_path / "AWS"
    awsd.mkdir()
    os.mkfifo(awsd / "rootkey.csv")
    assert resolve_aws(config_home=tmp_path).available is False  # returns promptly, no hang


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
    (gcpd / "sa.json").write_text(json.dumps(_FULL_SA))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("verel.actuators.cloudcreds._config_home", lambda: tmp_path / ".config")
    rc = verel_main(["verify-access", "--cloud", "gcp"])
    assert rc == 2 and "--scope is required" in capsys.readouterr().err
