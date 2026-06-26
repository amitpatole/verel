"""Security-cadence regression pins (IAC-KICKOFF.md) — each test corresponds to a confirmed red-team
finding, so a refactor can't silently reopen it. Three clusters: IAM false-negatives, argv
option-injection, and untrusted-JSON DoS."""

import json

import pytest

from verel.ci import (
    checkov_spec,
    conftest_spec,
    extract_iam_changes,
    grade_iac,
    helm_template_spec,
    iam_risk_issues,
    kube_score_spec,
    parse_terraform_plan,
    polaris_spec,
    trivy_config_spec,
)
from verel.verdict import Severity


def _rules(*resource_changes) -> dict[str, Severity]:
    issues = iam_risk_issues(extract_iam_changes({"resource_changes": list(resource_changes)}))
    return {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}


def _rc(address, rtype, after, actions=("create",)):
    return {"address": address, "type": rtype, "change": {"actions": list(actions), "after": after}}


def _doc(*statements):
    return json.dumps({"Statement": list(statements)})


# === Cluster 1: IAM false-negatives (the gate silently passing danger) ===
def test_not_action_admin_by_exclusion_flagged():
    after = {"policy": _doc({"Effect": "Allow", "NotAction": "iam:DeleteUser", "Resource": "*"})}
    assert "ALLOW_BY_EXCLUSION" in _rules(_rc("aws_iam_policy.x", "aws_iam_policy", after))


def test_not_resource_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:x"})}
    assert "ALLOW_BY_EXCLUSION" in _rules(_rc("aws_iam_policy.x", "aws_iam_policy", after))


def test_prefix_wildcard_action_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:x"})}
    assert _rules(_rc("aws_iam_policy.x", "aws_iam_policy", after))["WILDCARD_ACTION"] == Severity.ERROR


def test_prefix_wildcard_privesc_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Action": "iam:Put*", "Resource": "*"})}
    assert _rules(_rc("aws_iam_policy.x", "aws_iam_policy", after))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_scoped_passrole_still_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Action": "iam:PassRole",
                            "Resource": "arn:aws:iam::1:role/admin"})}
    # scoped → ERROR (not skipped); wildcard would be CRITICAL
    assert _rules(_rc("aws_iam_role_policy.x", "aws_iam_role_policy", after))["PRIVILEGE_ESCALATION"] == Severity.ERROR


def test_inline_policy_document_parsed():
    # The doc lives under inline_policy[].policy, not `policy` — must still be scanned.
    after = {"inline_policy": [{"name": "p", "policy": _doc(
        {"Effect": "Allow", "Action": "*", "Resource": "*"})}]}
    assert "WILDCARD_ACTION" in _rules(_rc("aws_iam_role.r", "aws_iam_role", after))


def test_kms_key_policy_parsed():
    after = {"policy": _doc({"Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"})}
    rules = _rules(_rc("aws_kms_key.k", "aws_kms_key", after))
    assert rules.get("PUBLIC_PRINCIPAL") == Severity.CRITICAL


def test_wildcard_account_principal_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::*:root"},
                            "Action": "s3:GetObject", "Resource": "arn:x"})}
    assert _rules(_rc("aws_s3_bucket_policy.b", "aws_s3_bucket_policy", after))["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_ipv6_open_ingress_flagged():
    after = {"type": "ingress", "ipv6_cidr_blocks": ["::/0"]}
    assert "OPEN_INGRESS" in _rules(_rc("aws_security_group_rule.x", "aws_security_group_rule", after))


def test_new_ingress_rule_resource_flagged():
    after = {"cidr_ipv4": "0.0.0.0/0"}  # aws_vpc_security_group_ingress_rule has no `type` field
    assert "OPEN_INGRESS" in _rules(
        _rc("aws_vpc_security_group_ingress_rule.x", "aws_vpc_security_group_ingress_rule", after))


def test_terraform_rbac_path_has_parity():
    # The terraform-provider RBAC path must catch escalate/secrets, not just */* (was weaker).
    after = {"rule": [{"verbs": ["escalate"], "resources": ["clusterroles"],
                       "api_groups": ["rbac.authorization.k8s.io"]}]}
    assert _rules(_rc("kubernetes_cluster_role.x", "kubernetes_cluster_role", after))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


# === Round 2: bypasses of the round-1 fixes ===
def test_gcp_iam_policy_policy_data_bindings_flagged():
    # google_project_iam_policy carries bindings in a policy_data JSON string (no Statement key).
    after = {"policy_data": json.dumps({"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]})}
    rules = _rules(_rc("google_project_iam_policy.p", "google_project_iam_policy", after))
    assert rules["ADMIN_GRANT"] == Severity.ERROR and rules["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_azure_custom_role_wildcard_action_flagged():
    after = {"name": "superrole", "permissions": [{"actions": ["*"], "not_actions": []}]}
    assert "ADMIN_GRANT" in _rules(_rc("azurerm_role_definition.r", "azurerm_role_definition", after))


def test_mid_string_wildcard_action_flagged():
    after = {"policy": _doc({"Effect": "Allow", "Action": "iam:*Policy", "Resource": "*"})}
    rules = _rules(_rc("aws_iam_policy.x", "aws_iam_policy", after))
    assert rules["WILDCARD_ACTION"] == Severity.ERROR
    assert rules["PRIVILEGE_ESCALATION"] == Severity.CRITICAL  # iam:*Policy covers PutRolePolicy etc.


def test_power_user_and_iam_full_access_flagged():
    for arn in ("arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/IAMFullAccess"):
        after = {"policy_arn": arn}
        assert "ADMIN_GRANT" in _rules(_rc("aws_iam_role_policy_attachment.a",
                                           "aws_iam_role_policy_attachment", after))


def test_url_path_rejected_ssrf():
    # safe_path must reject remote URLs (kubectl -f / helm template FETCH them) — red-team R2-F1.
    from verel.ci import helm_template_spec, kubectl_dryrun_spec
    with pytest.raises(ValueError):
        kubectl_dryrun_spec(".", path="https://attacker.example/x.yaml")
    with pytest.raises(ValueError):
        helm_template_spec(".", "oci://attacker/chart")


def test_path_traversal_rejected():
    with pytest.raises(ValueError):
        trivy_config_spec(".", paths=["../../../../etc"])
    with pytest.raises(ValueError):
        checkov_spec(".", directory="../../secrets")


# === Cluster 2: argv option-injection (incl. helm --post-renderer RCE) ===
def test_helm_post_renderer_rejected():
    with pytest.raises(ValueError):
        helm_template_spec(".", "--post-renderer=/tmp/evil.sh")
    with pytest.raises(ValueError):
        helm_template_spec(".", "chart", values=["--set=x=y"])


def test_grader_path_option_injection_rejected():
    with pytest.raises(ValueError):
        trivy_config_spec(".", paths=["--config=/tmp/attacker.yaml"])
    with pytest.raises(ValueError):
        checkov_spec(".", directory="--skip-check")
    with pytest.raises(ValueError):
        conftest_spec(".", paths=["x"], policy_dir="--policy")
    with pytest.raises(ValueError):
        kube_score_spec(".", paths=["-flag"])
    with pytest.raises(ValueError):
        polaris_spec(".", audit_path="--audit-path=/etc")


def test_safe_paths_still_allowed():
    # Legitimate relative/sub-dir paths must NOT be rejected.
    trivy_config_spec(".", paths=["./infra", "modules/vpc"])
    conftest_spec(".", paths=["deploy.yaml"], policy_dir="policy")
    helm_template_spec(".", "./charts/app", values=["values.yaml"])


# === Cluster 3: untrusted-JSON DoS (deep nesting) ===
def _deep_json(depth: int) -> str:
    return '{"a":' * depth + "1" + "}" * depth


def test_deep_json_does_not_crash_parser():
    # A deeply-nested plan makes json.loads raise RecursionError (not JSONDecodeError) — must be
    # swallowed, not propagated, or it crashes the grader/MCP server.
    assert parse_terraform_plan(_deep_json(6000)) == []


def test_grade_iac_handles_deep_json(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text(_deep_json(6000))
    rep = grade_iac(str(tmp_path), plan="plan.json")  # must not raise
    assert rep.verdict.value in ("pass", "warn", "fail")


def test_grade_iac_rejects_oversize_artifact(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text("{}" + " " * (26 * 1024 * 1024))  # > 25 MiB cap
    with pytest.raises(ValueError):
        grade_iac(str(tmp_path), plan="plan.json")
