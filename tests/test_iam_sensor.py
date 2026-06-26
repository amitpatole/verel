"""The cloud-IAM change sensor (IAC-KICKOFF.md Phase 1) — catch dangerous IAM before apply.

Pure rules over a normalized `terraform show -json` plan: wildcard / privilege-escalation /
public-principal / admin-grant / open-ingress, across AWS, GCP, Azure, and Kubernetes RBAC.
"""

import json

from verel.ci import extract_iam_changes, iam_risk_issues, is_iam_resource
from verel.verdict import GraderKind, Severity


def _rules(*resource_changes) -> dict[str, Severity]:
    """Run the sensor over a plan and return {rule_id: severity}."""
    plan = {"resource_changes": list(resource_changes)}
    issues = iam_risk_issues(extract_iam_changes(plan))
    assert all(i.source == GraderKind.IAM for i in issues)
    return {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}


def _rc(address, rtype, after, actions=("create",)):
    return {"address": address, "type": rtype, "change": {"actions": list(actions), "after": after}}


def test_iam_resource_detection():
    assert is_iam_resource("aws_iam_role_policy")
    assert is_iam_resource("google_project_iam_member")
    assert is_iam_resource("azurerm_role_assignment")
    assert is_iam_resource("kubernetes_cluster_role_binding")
    assert is_iam_resource("aws_security_group")
    assert not is_iam_resource("aws_s3_bucket")
    assert not is_iam_resource("aws_instance")


def test_noop_and_non_iam_yield_nothing():
    assert _rules(_rc("aws_s3_bucket.a", "aws_s3_bucket", {"acl": "private"})) == {}
    assert _rules(_rc("aws_iam_policy.a", "aws_iam_policy", {}, actions=["no-op"])) == {}


def test_aws_wildcard_action():
    doc = {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}
    rules = _rules(_rc("aws_iam_policy.god", "aws_iam_policy", doc))
    assert rules["WILDCARD_ACTION"] == Severity.ERROR
    assert rules["WILDCARD_RESOURCE"] == Severity.ERROR


def test_aws_service_wildcard_action():
    doc = {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:x"}]})}
    assert _rules(_rc("aws_iam_policy.s3", "aws_iam_policy", doc))["WILDCARD_ACTION"] == Severity.ERROR


def test_aws_privilege_escalation():
    doc = {"policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]})}
    assert _rules(_rc("aws_iam_role_policy.p", "aws_iam_role_policy", doc))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_aws_public_principal_bucket_policy():
    doc = {"policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:x/*"}]})}
    assert _rules(_rc("aws_s3_bucket_policy.pub", "aws_s3_bucket_policy", doc))["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_aws_public_principal_dict_form():
    doc = {"policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["sts:AssumeRole"], "Resource": "*"}]})}
    rules = _rules(_rc("aws_iam_role.r", "aws_iam_role", {"assume_role_policy": doc["policy"]}))
    assert rules["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_aws_admin_managed_policy_attachment():
    after = {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    assert _rules(_rc("aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment", after))["ADMIN_GRANT"] == Severity.ERROR


def test_deny_statement_does_not_trip_allow_rules():
    doc = {"policy": json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})}
    assert _rules(_rc("aws_iam_policy.deny", "aws_iam_policy", doc)) == {}


def test_gcp_owner_role():
    rules = _rules(_rc("google_project_iam_member.o", "google_project_iam_member",
                       {"role": "roles/owner", "member": "user:dev@example.com"}))
    assert rules["ADMIN_GRANT"] == Severity.ERROR


def test_gcp_public_member():
    rules = _rules(_rc("google_storage_bucket_iam_member.p", "google_storage_bucket_iam_member",
                       {"role": "roles/storage.objectViewer", "member": "allUsers"}))
    assert rules["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_azure_owner_assignment():
    rules = _rules(_rc("azurerm_role_assignment.o", "azurerm_role_assignment",
                       {"role_definition_name": "Owner", "principal_id": "abc"}))
    assert rules["ADMIN_GRANT"] == Severity.ERROR


def test_security_group_open_ingress():
    after = {"type": "ingress", "cidr_blocks": ["0.0.0.0/0"]}
    assert _rules(_rc("aws_security_group_rule.open", "aws_security_group_rule", after))["OPEN_INGRESS"] == Severity.ERROR


def test_security_group_inline_ingress():
    after = {"ingress": [{"from_port": 22, "cidr_blocks": ["10.0.0.0/8"]},
                         {"from_port": 0, "cidr_blocks": ["0.0.0.0/0"]}]}
    assert _rules(_rc("aws_security_group.sg", "aws_security_group", after))["OPEN_INGRESS"] == Severity.ERROR


def test_k8s_wildcard_rbac_and_cluster_admin():
    role = {"rule": [{"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]}]}
    assert _rules(_rc("kubernetes_cluster_role.x", "kubernetes_cluster_role", role))["WILDCARD_RBAC"] == Severity.ERROR
    binding = {"role_ref": [{"name": "cluster-admin", "kind": "ClusterRole"}]}
    assert _rules(_rc("kubernetes_cluster_role_binding.b", "kubernetes_cluster_role_binding", binding))["ADMIN_GRANT"] == Severity.ERROR


def test_k8s_anonymous_subject():
    binding = {"subject": [{"kind": "User", "name": "system:anonymous"}]}
    assert _rules(_rc("kubernetes_role_binding.anon", "kubernetes_role_binding", binding))["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_issue_grounding_carries_address_and_rule():
    doc = {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}
    issues = iam_risk_issues(extract_iam_changes({"resource_changes": [
        _rc("aws_iam_policy.god", "aws_iam_policy", doc)]}))
    detail = json.loads(issues[0].detail_json)
    assert detail["address"] == "aws_iam_policy.god" and detail["cloud"] == "aws"
    assert issues[0].locator == "aws_iam_policy.god" and issues[0].locator_precise
