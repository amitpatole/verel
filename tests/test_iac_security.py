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


# === Round 3: bypasses of the round-2 fixes ===
def test_gcp_impersonation_role_flagged():
    # roles/iam.serviceAccountTokenCreator = full impersonation (GCP's iam:PassRole analogue).
    after = {"role": "roles/iam.serviceAccountTokenCreator", "member": "user:evil@x"}
    assert _rules(_rc("google_service_account_iam_member.m", "google_service_account_iam_member",
                      after))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_azure_roleassignments_write_flagged():
    after = {"permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"]}]}
    assert _rules(_rc("azurerm_role_definition.r", "azurerm_role_definition",
                      after))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_s3_public_access_block_disable_flagged():
    after = {"block_public_acls": False, "block_public_policy": False,
             "ignore_public_acls": False, "restrict_public_buckets": False}
    assert _rules(_rc("aws_s3_bucket_public_access_block.pab", "aws_s3_bucket_public_access_block",
                      after))["PUBLIC_ACCESS_BLOCK_DISABLED"] == Severity.ERROR


def test_s3_public_access_block_enabled_is_clean():
    after = {"block_public_acls": True, "block_public_policy": True,
             "ignore_public_acls": True, "restrict_public_buckets": True}
    assert _rules(_rc("aws_s3_bucket_public_access_block.pab", "aws_s3_bucket_public_access_block",
                      after)) == {}


def test_absolute_path_rejected():
    with pytest.raises(ValueError):
        trivy_config_spec(".", paths=["/home/victim/.aws"])
    with pytest.raises(ValueError):
        kube_score_spec(".", paths=["/etc"])


# === Round 4: bypasses of the round-3 fixes (IAM-coverage long tail) ===
def test_azure_admin_by_role_definition_id_guid():
    after = {"scope": "/subscriptions/SUB", "principal_id": "x",
             "role_definition_id": "/subscriptions/SUB/providers/Microsoft.Authorization/"
                                   "roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}  # Owner GUID
    assert "ADMIN_GRANT" in _rules(_rc("azurerm_role_assignment.x", "azurerm_role_assignment", after))


def test_inline_policy_resource_outside_typelist_flagged():
    # aws_api_gateway_rest_api isn't in the IAM type substrings, but its inline policy with Principal:*
    # must still be extracted (generic: any `after` carrying a Statement) and flagged.
    after = {"policy": _doc({"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke",
                            "Resource": "*"})}
    assert "PUBLIC_PRINCIPAL" in _rules(_rc("aws_api_gateway_rest_api.p", "aws_api_gateway_rest_api",
                                            after))


def test_service_account_key_creation_flagged():
    assert "CREDENTIAL_EXPOSURE" in _rules(_rc("google_service_account_key.k",
                                               "google_service_account_key", {"public_key_type": "x"}))


def test_tf_rbac_token_mint_flagged():
    after = {"rule": [{"verbs": ["create"], "resources": ["serviceaccounts/token"], "api_groups": [""]}]}
    assert _rules(_rc("kubernetes_cluster_role.t", "kubernetes_cluster_role",
                      after))["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_native_rbac_token_mint_and_nonresource_wildcard():
    from verel.ci import extract_rbac_risks
    tok = {"kind": "ClusterRole", "metadata": {"name": "m"},
           "rules": [{"verbs": ["create"], "resources": ["serviceaccounts/token"]}]}
    nr = {"kind": "ClusterRole", "metadata": {"name": "nr"},
          "rules": [{"verbs": ["*"], "nonResourceURLs": ["*"]}]}
    rules = {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([tok, nr])}
    assert "PRIVILEGE_ESCALATION" in rules and "WILDCARD_RBAC" in rules


# === Round 5: engine bypass — kind: List wrapper must not hide RBAC ===
def test_kind_list_wrapper_is_unwrapped():
    from verel.ci import extract_rbac_risks
    wrapped = {"kind": "List", "items": [
        {"kind": "ClusterRoleBinding", "metadata": {"name": "pwn"},
         "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
         "subjects": [{"kind": "Group", "name": "system:masters"}]}]}
    rules = {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([wrapped])}
    assert "ADMIN_GRANT" in rules  # cluster-admin binding inside a List must still be caught


def test_nested_list_wrapper_unwrapped():
    from verel.ci import extract_rbac_risks
    nested = {"kind": "List", "items": [{"kind": "List", "items": [
        {"kind": "ClusterRole", "metadata": {"name": "x"},
         "rules": [{"verbs": ["*"], "resources": ["*"]}]}]}]}
    assert any(json.loads(i.detail_json)["rule_id"] == "WILDCARD_RBAC"
               for i in extract_rbac_risks([nested]))


def test_cluster_wide_read_all_flagged():
    from verel.ci import extract_rbac_risks
    cr = {"kind": "ClusterRole", "metadata": {"name": "reader"},
          "rules": [{"verbs": ["get", "list", "watch"], "resources": ["*"]}]}
    assert any(json.loads(i.detail_json)["rule_id"] == "SECRETS_ACCESS"
               for i in extract_rbac_risks([cr]))
    # parity: terraform-provider path
    after = {"rule": [{"verbs": ["get", "list", "watch"], "resources": ["*"]}]}
    assert "SECRETS_ACCESS" in _rules(_rc("kubernetes_cluster_role.r", "kubernetes_cluster_role", after))


def test_namespaced_read_all_warns_not_gates():
    # Round-6 R4: a namespaced Role reading ALL resources in its namespace still reads every secret in
    # that namespace (e.g. kube-system SA tokens). It must WARN (advisory) — not pass clean, but not
    # gate like the cluster-wide case either.
    from verel.ci import extract_rbac_risks
    role = {"kind": "Role", "metadata": {"name": "r", "namespace": "kube-system"},
            "rules": [{"verbs": ["get", "list", "watch"], "resources": ["*"]}]}
    issues = extract_rbac_risks([role])
    secrets = [i for i in issues if json.loads(i.detail_json)["rule_id"] == "SECRETS_ACCESS"]
    assert len(secrets) == 1 and secrets[0].severity == Severity.WARNING
    # parity: terraform-provider namespaced Role
    after = {"rule": [{"verbs": ["get"], "resources": ["*"]}]}
    tf = _rules(_rc("kubernetes_role.r", "kubernetes_role", after))
    assert tf.get("SECRETS_ACCESS") == Severity.WARNING


# === Round 6: "the plan is not reality" + RBAC evasion + live-verifier parity ===
def test_provisioner_local_exec_gates_and_escalates():
    # P1: a null_resource local-exec that grants admin is INVISIBLE to resource_changes — must GATE
    # (grader FAIL) and class the apply IRREVERSIBLE (human approval), not verdict-gated CONSEQUENTIAL.
    from verel.actuators.terraform import escalate
    from verel.ci import parse_terraform_plan
    from verel.gateway import ActionClass
    plan = {
        "resource_changes": [{"address": "null_resource.grant", "type": "null_resource",
                              "change": {"actions": ["create"], "after": {"triggers": None}}}],
        "configuration": {"root_module": {"resources": [
            {"address": "null_resource.grant", "type": "null_resource",
             "provisioners": [{"type": "local-exec",
                               "expressions": {"command": {"constant_value": "aws iam attach-role-policy"}}}]}]}},
    }
    rules = {json.loads(i.detail_json)["rule_id"] for i in parse_terraform_plan(json.dumps(plan))}
    assert "UNAUDITABLE_PROVISIONER" in rules
    cls, reasons = escalate(plan)
    assert cls == ActionClass.IRREVERSIBLE and any("provisioner" in r for r in reasons)


def test_provisioner_in_module_detected():
    from verel.ci.iac import provisioner_resources
    plan = {"configuration": {"root_module": {"module_calls": {"app": {"module": {"resources": [
        {"address": "null_resource.x", "type": "null_resource",
         "provisioners": [{"type": "remote-exec"}]}]}}}}}}
    assert provisioner_resources(plan) == ["module.app.null_resource.x"]


def test_unknown_computed_iam_policy_fails_closed():
    # P2: policy is "(known after apply)" → null in `after`, true in after_unknown. Must GATE, not pass.
    rc = {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy",
          "change": {"actions": ["create"], "after": {"name": "x", "role": "app"},
                     "after_unknown": {"policy": True}}}
    assert _rules(rc)["UNKNOWN_IAM_CONTENT"] == Severity.ERROR


def test_unknown_computed_policy_on_non_iam_typed_resource_fails_closed():
    # P2 double-blind: a non-IAM-typed resource with a computed inline policy is invisible to both the
    # type list AND `after` — the after_unknown clause must still extract + gate it.
    rc = {"address": "aws_s3_bucket.b", "type": "aws_s3_bucket",
          "change": {"actions": ["create"], "after": {"bucket": "b"},
                     "after_unknown": {"policy": True}}}
    assert "UNKNOWN_IAM_CONTENT" in _rules(rc)


def test_known_iam_policy_not_falsely_unknown():
    # False-positive guard: a fully-known least-privilege policy must NOT trip UNKNOWN_IAM_CONTENT.
    after = {"policy": _doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"})}
    rc = _rc("aws_iam_role_policy.lp", "aws_iam_role_policy", after)
    rc["change"]["after_unknown"] = {"policy": False}
    assert "UNKNOWN_IAM_CONTENT" not in _rules(rc)


def test_builtin_admin_edit_binding_flagged_both_paths():
    # R1: binding to the built-in `admin`/`edit` ClusterRole (not just cluster-admin) is an admin grant.
    from verel.ci import extract_rbac_risks
    for builtin in ("admin", "edit"):
        crb = {"kind": "ClusterRoleBinding", "metadata": {"name": "x"},
               "roleRef": {"kind": "ClusterRole", "name": builtin},
               "subjects": [{"kind": "User", "name": "mallory"}]}
        rules = {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([crb])}
        assert "ADMIN_GRANT" in rules, builtin
        after = {"role_ref": [{"name": builtin}]}
        assert "ADMIN_GRANT" in _rules(_rc("kubernetes_cluster_role_binding.b",
                                           "kubernetes_cluster_role_binding", after)), builtin


def test_system_authenticated_group_subject_flagged_tf_path():
    # R2 parity: the terraform path must flag a Group subject system:authenticated (effectively public).
    after = {"role_ref": [{"name": "view"}],
             "subject": [{"kind": "Group", "name": "system:authenticated"}]}
    assert _rules(_rc("kubernetes_cluster_role_binding.b", "kubernetes_cluster_role_binding",
                      after))["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_resource_scoped_privesc_primitives_flagged():
    # R3: webhook configs / CSR approval / node mutation are cluster-takeover even without a wildcard.
    from verel.ci import extract_rbac_risks
    cases = [
        {"verbs": ["create"], "resources": ["mutatingwebhookconfigurations"]},
        {"verbs": ["approve"], "resources": ["certificatesigningrequests"]},
        {"verbs": ["update"], "resources": ["nodes"]},
    ]
    for rule in cases:
        cr = {"kind": "ClusterRole", "metadata": {"name": "x"}, "rules": [rule]}
        rules = {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([cr])}
        assert "PRIVILEGE_ESCALATION" in rules, rule
        assert "PRIVILEGE_ESCALATION" in _rules(
            _rc("kubernetes_cluster_role.x", "kubernetes_cluster_role", {"rule": [rule]})), rule


def test_aggregation_rule_clusterrole_advised():
    # R5: an aggregating ClusterRole with empty rules grows silently → advisory, not silent green.
    from verel.ci import extract_rbac_risks
    cr = {"kind": "ClusterRole", "metadata": {"name": "agg"},
          "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"x": "y"}}]}, "rules": []}
    rules = {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([cr])}
    assert "AGGREGATION_RULE" in rules


def test_live_verifier_privesc_sets_superset_of_offline():
    # E1 drift-guard: the live effective-access verifier must NEVER be blinder than the offline plan
    # grader, or it would silently pass grants the plan grader catches. Pin the superset relationship.
    from verel.actuators import access_verify
    from verel.ci import iac
    assert iac._PRIVESC_ACTIONS <= access_verify._SENSITIVE_ACTIONS
    assert (iac._ADMIN_GCP_ROLES | iac._PRIVESC_GCP_ROLES) <= access_verify._GCP_GATING_ROLES
    assert (iac._ADMIN_AZURE_GUIDS | iac._PRIVESC_AZURE_GUIDS) <= access_verify._AZURE_GATING_GUIDS


def test_live_verifier_catches_login_profile_and_token_creator():
    # E1: concrete grants the OLD hand-rolled sets dropped — now flagged.
    from verel.actuators.access_verify import parse_aws_simulate, parse_gcp_analyze_iam
    aws = json.dumps({"EvaluationResults": [
        {"EvalActionName": "iam:CreateLoginProfile", "EvalDecision": "allowed",
         "EvalResourceName": "arn:aws:iam::1:user/admin"}]})
    assert any(json.loads(i.detail_json)["rule_id"] == "EFFECTIVE_ALLOW"
               for i in parse_aws_simulate(aws))
    gcp = json.dumps({"mainAnalysis": {"analysisResults": [
        {"iamBinding": {"role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:attacker@evil.com"]}}]}})
    assert any(json.loads(i.detail_json)["rule_id"] == "ADMIN_GRANT"
               for i in parse_gcp_analyze_iam(gcp))


def test_aws_simulate_resource_specific_allow_flagged():
    # E2: a per-resource ALLOW hidden under a top-level implicitDeny must still be caught.
    from verel.actuators.access_verify import parse_aws_simulate
    out = json.dumps({"EvaluationResults": [
        {"EvalActionName": "iam:PassRole", "EvalDecision": "implicitDeny",
         "ResourceSpecificResults": [
             {"EvalResourceName": "arn:aws:iam::1:role/admin", "EvalResourceDecision": "allowed"}]}]})
    assert any(json.loads(i.detail_json)["rule_id"] == "EFFECTIVE_ALLOW"
               for i in parse_aws_simulate(out))


def test_gcp_cred_project_mismatch_fails_closed():
    # E3: a cred for a DIFFERENT project must not produce a falsely-scoped green for the target.
    from verel.actuators.access_verify import EffectiveAccessVerifier
    from verel.actuators.cloudcreds import CloudCreds
    creds = CloudCreds("gcp", True, "/x", project="prod-account", env={"X": "1"})
    rep = EffectiveAccessVerifier(runner=lambda *a, **k: (0, "{}", "")).gcp_analyze_iam(
        "projects/sandbox-account", creds)
    assert rep.errored and rep.verdict.name == "FAIL"


def test_azure_guid_only_admin_assignment_flagged():
    # E4: an Owner assignment surfaced only via roleDefinitionId GUID (empty name) is still flagged.
    from verel.actuators.access_verify import parse_az_role_assignments
    out = json.dumps([{"roleDefinitionName": "",
                       "roleDefinitionId": "/subscriptions/x/.../8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                       "scope": "/subscriptions/abc"}])
    assert any(json.loads(i.detail_json)["rule_id"] == "ADMIN_GRANT"
               for i in parse_az_role_assignments(out))


def test_least_privilege_inline_policy_is_clean():
    # Round-4 generic extraction must NOT cry wolf on a scoped least-privilege policy (false-positive check).
    after = {"policy": _doc({"Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::mybucket/data.csv"})}
    assert _rules(_rc("aws_iam_role_policy.lp", "aws_iam_role_policy", after)) == {}


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
