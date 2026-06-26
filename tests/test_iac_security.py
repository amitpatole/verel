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
    # Round-6 R4: a namespaced Role reading ALL resources in an ORDINARY namespace reads every secret
    # there → WARN (advisory), not clean, not gating.
    from verel.ci import extract_rbac_risks
    role = {"kind": "Role", "metadata": {"name": "r", "namespace": "team"},
            "rules": [{"verbs": ["get", "list", "watch"], "resources": ["*"]}]}
    issues = extract_rbac_risks([role])
    secrets = [i for i in issues if json.loads(i.detail_json)["rule_id"] == "SECRETS_ACCESS"]
    assert len(secrets) == 1 and secrets[0].severity == Severity.WARNING
    # parity: terraform-provider namespaced Role (metadata block carries the namespace)
    after = {"metadata": [{"namespace": "team"}], "rule": [{"verbs": ["get"], "resources": ["*"]}]}
    tf = _rules(_rc("kubernetes_role.r", "kubernetes_role", after))
    assert tf.get("SECRETS_ACCESS") == Severity.WARNING


def test_privileged_namespace_role_gates_not_warns():
    # Round-7 F4: a Role in kube-system/kube-public reads bootstrap/controller tokens = cluster-admin
    # equivalent → must GATE (ERROR), not merely warn.
    from verel.ci import extract_rbac_risks
    role = {"kind": "Role", "metadata": {"name": "r", "namespace": "kube-system"},
            "rules": [{"verbs": ["get", "list"], "resources": ["secrets"]}]}
    secrets = [i for i in extract_rbac_risks([role])
               if json.loads(i.detail_json)["rule_id"] == "SECRETS_ACCESS"]
    assert len(secrets) == 1 and secrets[0].severity == Severity.ERROR


def test_write_all_resources_flagged_both_paths():
    # Round-7 F1 (HIGH): create/write over resources:["*"] = create rolebindings/webhooks → takeover.
    from verel.ci import extract_rbac_risks
    cr = {"kind": "ClusterRole", "metadata": {"name": "pwn"},
          "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["create"]}]}
    assert "PRIVILEGE_ESCALATION" in {json.loads(i.detail_json)["rule_id"]
                                      for i in extract_rbac_risks([cr])}
    after = {"rule": [{"resources": ["*"], "verbs": ["create"]}]}
    assert "PRIVILEGE_ESCALATION" in _rules(_rc("kubernetes_cluster_role.x", "kubernetes_cluster_role", after))


def test_proxy_subresource_privesc_flagged():
    # Round-7 F3: nodes/proxy reaches the kubelet API (exec into any pod) — a distinct string from nodes.
    from verel.ci import extract_rbac_risks
    cr = {"kind": "ClusterRole", "metadata": {"name": "x"},
          "rules": [{"resources": ["nodes/proxy"], "verbs": ["get", "create"]}]}
    assert "PRIVILEGE_ESCALATION" in {json.loads(i.detail_json)["rule_id"]
                                      for i in extract_rbac_risks([cr])}


def test_user_owned_namespaced_role_named_edit_not_flagged():
    # Round-7 F6 (false-positive regression): a user's OWN namespaced Role named `edit` (roleRef.kind
    # == Role) is harmless and must NOT be flagged as the built-in admin ClusterRole.
    from verel.ci import extract_rbac_risks
    rb = {"kind": "RoleBinding", "metadata": {"name": "x", "namespace": "team"},
          "roleRef": {"kind": "Role", "name": "edit"}, "subjects": [{"kind": "User", "name": "dev"}]}
    assert extract_rbac_risks([rb]) == []
    # but a ClusterRole ref to built-in `edit` IS flagged
    rb2 = {"kind": "RoleBinding", "metadata": {"name": "y", "namespace": "team"},
           "roleRef": {"kind": "ClusterRole", "name": "edit"}, "subjects": [{"kind": "User", "name": "dev"}]}
    assert "ADMIN_GRANT" in {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([rb2])}


def test_unknown_computed_rolebinding_ref_fails_closed():
    # Round-7 F2: a computed role_ref (resolves to cluster-admin at apply) must fail closed.
    rc = {"address": "b", "type": "kubernetes_cluster_role_binding",
          "change": {"actions": ["create"], "after": {"role_ref": [{"name": None}]},
                     "after_unknown": {"role_ref": [{"name": True}]}}}
    assert "UNKNOWN_IAM_CONTENT" in _rules(rc)


def test_s3_public_access_block_delete_gates():
    # Round-7 L2-F1: DELETING a PAB re-exposes the bucket exactly like flipping a flag false — gate it.
    rc = {"address": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block",
          "change": {"actions": ["delete"], "after": None,
                     "before": {"block_public_acls": True}}}
    assert _rules(rc)["PUBLIC_ACCESS_BLOCK_DISABLED"] == Severity.ERROR


def test_pab_absent_flags_gates():
    # Round-8 F1: a PAB create/update where the four flags are ABSENT (each defaults to false) gives
    # zero protection — must gate exactly like an explicit-false flag.
    rc = {"address": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block",
          "change": {"actions": ["create"], "after": {"bucket": "b"}}}
    assert _rules(rc)["PUBLIC_ACCESS_BLOCK_DISABLED"] == Severity.ERROR
    # all four True → clean (false-positive guard)
    ok = {"address": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block",
          "change": {"actions": ["create"], "after": {"block_public_acls": True, "block_public_policy": True,
                     "ignore_public_acls": True, "restrict_public_buckets": True}}}
    assert "PUBLIC_ACCESS_BLOCK_DISABLED" not in _rules(ok)


def test_data_http_advisory():
    # Round-8 F2: a data.http fetches a URL every refresh (exfil/SSRF) — advisory WARNING.
    from verel.ci import parse_terraform_plan
    plan = {"configuration": {"root_module": {"resources": [
        {"address": "data.http.x", "mode": "data", "type": "http"}]}}}
    issues = parse_terraform_plan(json.dumps(plan))
    http = [i for i in issues if json.loads(i.detail_json)["rule_id"] == "HTTP_DATA_SOURCE"]
    assert len(http) == 1 and http[0].severity == Severity.WARNING


def test_all_tool_parsers_tolerate_nondict_shapes():
    # Round-16: every tool/scanner parser must FAIL CLOSED (return a list, never crash) on a hostile
    # non-dict element or nested field — parity with the untrusted-sensor R14-1/R15-1 contract.
    from verel.ci.iac import (
        parse_checkov,
        parse_parliament,
        parse_terraform_validate,
        parse_tflint,
        parse_trivy_config,
    )
    from verel.ci.k8s import parse_kube_linter, parse_kube_score, parse_polaris
    cases = [
        (parse_terraform_validate, [
            {"diagnostics": ["x"]}, {"diagnostics": [{"range": "x"}]},
            {"diagnostics": [{"range": {"start": "x"}}]}]),
        (parse_trivy_config, [
            {"Results": ["x"]}, {"Results": [{"Misconfigurations": ["x"]}]},
            {"Results": [{"Misconfigurations": [{"CauseMetadata": "x"}]}]}]),
        (parse_tflint, [{"issues": ["x"]}, {"issues": [{"rule": "x", "range": "x"}]}]),
        (parse_checkov, [{"results": {"failed_checks": ["x"]}}, {"results": "x"}]),
        (parse_parliament, [[{"location": "x"}]]),
        (parse_kube_score, [["x"], [{"checks": ["x"]}], [{"checks": "x"}]]),
        (parse_kube_linter, [
            {"Reports": ["x"]}, {"Reports": [{"Object": "x"}]},
            {"Reports": [{"Object": {"K8sObject": "x"}}]}]),
        (parse_polaris, [{"Results": ["x"]}]),
    ]
    for parser, payloads in cases:
        for payload in payloads:
            assert isinstance(parser(json.dumps(payload)), list), (parser.__name__, payload)


def test_parsers_tolerate_noniterable_and_nonstr_leaves():
    # Round-17 R17-1/R17-2: a present-but-NON-ITERABLE scalar field (int/null/bool — the `.get("F",[])`
    # default only fires when ABSENT) and a non-string LEAF reaching Issue()/.strip() must not crash.
    from verel.actuators.terraform import escalate, escalation_override
    from verel.ci import parse_terraform_plan
    from verel.ci.iac import parse_terraform_validate
    from verel.ci.k8s import parse_kube_score
    for scalar in (1, None, True):
        assert isinstance(parse_terraform_plan(json.dumps({"resource_changes": scalar})), list)
    escalate({"resource_changes": 1})            # must not raise (TypeError on non-iterable)
    escalation_override({"resource_changes": 1})
    # R17-2: non-string leaves → coerced, no pydantic ValidationError / AttributeError
    assert isinstance(parse_terraform_plan(json.dumps(
        {"resource_changes": [{"type": "aws_iam_policy", "address": 5,
         "change": {"actions": ["create"],
                    "after": {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}}}]})), list)
    assert isinstance(parse_terraform_validate(json.dumps({"diagnostics": [{"summary": 5}]})), list)
    assert isinstance(parse_kube_score(json.dumps([{"object_name": 5, "checks": [
        {"grade": 1, "check": {"name": "x"}}]}])), list)


def test_actions_and_severity_leaves_tolerate_garbage():
    # Round-18: `change.actions` fed to set() (non-iterable scalar / unhashable list elements),
    # `(x or [])` iterations, and severity leaves used with .lower()/.get() must not crash.
    from verel.actuators.access_verify import parse_aws_validate_policy
    from verel.ci import parse_terraform_plan
    from verel.ci.iac import parse_checkov, parse_conftest, parse_tflint, parse_trivy_config
    rc = lambda a: json.dumps({"resource_changes": [{"type": "aws_iam_role", "change": {"actions": a}}]})
    for a in (1, None, [{}], [[]]):  # non-iterable + unhashable elements
        assert isinstance(parse_terraform_plan(rc(a)), list)
    assert isinstance(parse_terraform_plan(json.dumps(
        {"configuration": {"root_module": {"resources": 1}}})), list)
    assert isinstance(parse_terraform_plan(json.dumps(
        {"configuration": {"root_module": {"resources": [{"provisioners": 1}]}}})), list)
    assert isinstance(parse_conftest(json.dumps([{"failures": 1, "warnings": True}])), list)
    # severity leaves: non-str (.lower) and unhashable (.get key)
    assert isinstance(parse_trivy_config(json.dumps({"Results": [{"Misconfigurations": [{"Severity": 1}]}]})), list)
    assert isinstance(parse_checkov(json.dumps({"results": {"failed_checks": [{"severity": 1}]}})), list)
    assert isinstance(parse_tflint(json.dumps({"issues": [{"rule": {"severity": [1]}}]})), list)
    assert isinstance(parse_aws_validate_policy(json.dumps({"findings": [{"findingType": [1]}]})), list)


def test_malformed_nondict_fields_do_not_crash():
    # Round-14 R14-1: a hostile truthy NON-dict `change`/`metadata`/`roleRef` must not crash the
    # grader (the `x or {}` idiom only guards None/falsy) — skip it and return a verdict.
    from verel.actuators.terraform import escalate
    from verel.ci import extract_rbac_risks, parse_terraform_plan
    assert isinstance(parse_terraform_plan(json.dumps(
        {"resource_changes": [{"type": "aws_iam_role", "change": [1, 2]}]})), list)
    assert isinstance(parse_terraform_plan(json.dumps(
        {"resource_changes": [], "resource_drift": [{"change": [1]}]})), list)
    escalate({"resource_changes": [{"change": [1]}]})  # must not raise
    assert extract_rbac_risks([{"kind": "Role", "metadata": [1], "rules": []}]) == []
    assert extract_rbac_risks([{"kind": "RoleBinding", "metadata": {"name": "x"}, "roleRef": [1]}]) == []


def test_malformed_resource_drift_does_not_crash():
    # Round-8 F3: a hostile `resource_drift: [null]` / non-list must not crash the grader.
    from verel.ci import parse_terraform_plan
    assert isinstance(parse_terraform_plan(json.dumps(
        {"resource_changes": [None, "x"], "resource_drift": [None]})), list)
    assert isinstance(parse_terraform_plan(json.dumps({"resource_drift": "x"})), list)


def test_clusterrole_ref_case_insensitive_kind():
    # Round-8 (lens 1 hardening): a lowercase `clusterrole` roleRef kind is still the built-in admin.
    from verel.ci import extract_rbac_risks
    rb = {"kind": "ClusterRoleBinding", "metadata": {"name": "x"},
          "roleRef": {"kind": "clusterrole", "name": "cluster-admin"},
          "subjects": [{"kind": "User", "name": "m"}]}
    assert "ADMIN_GRANT" in {json.loads(i.detail_json)["rule_id"] for i in extract_rbac_risks([rb])}


def test_gcp_project_derived_from_appspot_email(tmp_path):
    # Round-8 lens 3 F1: a project_id-less SA key with an appspot client_email must still derive the
    # project so the cred↔scope binding stays active.
    from verel.actuators.cloudcreds import resolve_gcp
    gcp = tmp_path / "gcp"
    gcp.mkdir()
    (gcp / "sa.json").write_text(json.dumps({
        "type": "service_account", "private_key": "k", "private_key_id": "id",
        "client_email": "myproj@appspot.gserviceaccount.com", "token_uri": "https://x"}))
    assert resolve_gcp(config_home=tmp_path).project == "myproj"


def test_gcp_firewall_world_ingress_flagged():
    # Round-9 F1: cross-cloud parity — a GCP firewall open to 0.0.0.0/0 must gate like an AWS SG.
    after = {"source_ranges": ["0.0.0.0/0"], "direction": "INGRESS",
             "allow": [{"protocol": "tcp", "ports": ["22"]}]}
    assert _rules(_rc("google_compute_firewall.x", "google_compute_firewall", after))["OPEN_INGRESS"] \
        == Severity.ERROR


def test_azure_nsg_world_inbound_flagged():
    # Round-9 F2: an Azure NSG inbound Allow from */Internet/0.0.0.0/0 must gate.
    for prefix in ("*", "Internet", "0.0.0.0/0"):
        after = {"access": "Allow", "direction": "Inbound", "source_address_prefix": prefix,
                 "destination_port_range": "22"}
        assert "OPEN_INGRESS" in _rules(_rc("azurerm_network_security_rule.x",
                                            "azurerm_network_security_rule", after)), prefix


def test_s3_public_acl_flagged():
    # Round-9 F3: the non-policy public-bucket path (canned ACL) must gate.
    assert _rules(_rc("aws_s3_bucket_acl.b", "aws_s3_bucket_acl",
                      {"acl": "public-read"}))["PUBLIC_ACL"] == Severity.ERROR
    # a private ACL is clean
    assert "PUBLIC_ACL" not in _rules(_rc("aws_s3_bucket_acl.b", "aws_s3_bucket_acl", {"acl": "private"}))


def test_s3_public_acl_grant_block_flagged():
    # Round-10: the grant-block form (no canned `acl`) with a global AllUsers grantee must also gate.
    after = {"access_control_policy": {"grant": [{"permission": "READ", "grantee": {
        "type": "Group", "uri": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}}
    assert _rules(_rc("aws_s3_bucket_acl.b", "aws_s3_bucket_acl", after))["PUBLIC_ACL"] == Severity.ERROR


def test_split_cidr_world_open_flagged():
    # Round-10 F10-2: the internet split into two /1 halves is still world-open — must gate, all clouds.
    aws = {"type": "ingress", "cidr_blocks": ["0.0.0.0/1", "128.0.0.0/1"]}
    assert "OPEN_INGRESS" in _rules(_rc("aws_security_group_rule.x", "aws_security_group_rule", aws))
    gcp = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/1", "128.0.0.0/1"]}
    assert "OPEN_INGRESS" in _rules(_rc("google_compute_firewall.x", "google_compute_firewall", gcp))
    az = {"access": "Allow", "direction": "Inbound", "source_address_prefixes": ["0.0.0.0/1", "128.0.0.0/1"]}
    assert "OPEN_INGRESS" in _rules(_rc("azurerm_network_security_rule.x", "azurerm_network_security_rule", az))


def test_azure_nsg_absent_direction_fails_closed():
    # Round-10 F10-3: an Allow rule from 0.0.0.0/0 with direction ABSENT must still gate (fail closed).
    after = {"access": "Allow", "source_address_prefix": "0.0.0.0/0"}
    assert "OPEN_INGRESS" in _rules(_rc("azurerm_network_security_rule.x",
                                        "azurerm_network_security_rule", after))


def test_publicly_accessible_db_flagged():
    # Round-9 F4: an RDS/Redshift instance with a public endpoint must gate.
    assert _rules(_rc("aws_db_instance.d", "aws_db_instance",
                      {"publicly_accessible": True, "engine": "postgres"}))["PUBLIC_DB_ENDPOINT"] \
        == Severity.ERROR
    assert "PUBLIC_DB_ENDPOINT" not in _rules(
        _rc("aws_db_instance.d", "aws_db_instance", {"publicly_accessible": False}))


def test_azure_public_blob_access_flagged():
    # Round-10 F10-1: the Azure leg of the public-exposure triad (anonymous public blob).
    assert _rules(_rc("azurerm_storage_account.x", "azurerm_storage_account",
                      {"allow_blob_public_access": True}))["PUBLIC_BLOB_ACCESS"] == Severity.ERROR
    # azurerm >=3.0 rename
    assert "PUBLIC_BLOB_ACCESS" in _rules(_rc("azurerm_storage_account.x", "azurerm_storage_account",
                                              {"allow_nested_items_to_be_public": True}))
    # a locked-down account is clean
    assert "PUBLIC_BLOB_ACCESS" not in _rules(_rc("azurerm_storage_account.x", "azurerm_storage_account",
                                                  {"allow_blob_public_access": False}))


def test_ordinary_role_trust_policy_is_clean():
    # Round-12 (HIGH false-positive): a normal service-trust role (assume_role_policy with
    # sts:AssumeRole + a Service principal, no permissions) must PASS — sts:AssumeRole in a TRUST
    # policy is "who may assume me", not a privesc the role gains.
    after = {"assume_role_policy": _doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                         "Principal": {"Service": "ec2.amazonaws.com"}})}
    assert _rules(_rc("aws_iam_role.app", "aws_iam_role", after)) == {}


def test_cross_account_trust_advisory_not_gating():
    # Round-13 F13-1: trust to a CONCRETE external account is a confused-deputy advisory (WARNING),
    # not a hard gate (re-gating would resurrect the round-12 service-trust false positive).
    after = {"assume_role_policy": _doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                         "Principal": {"AWS": "arn:aws:iam::999999999999:root"}})}
    rules = _rules(_rc("aws_iam_role.app", "aws_iam_role", after))
    assert rules.get("CROSS_ACCOUNT_TRUST") == Severity.WARNING
    # WARNING only — no gating issue, so grade_iac would WARN not FAIL
    assert all(sev not in (Severity.ERROR, Severity.CRITICAL) for sev in rules.values())
    # a plain Service trust must NOT trip the cross-account advisory
    svc = {"assume_role_policy": _doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                       "Principal": {"Service": "ec2.amazonaws.com"}})}
    assert _rules(_rc("aws_iam_role.app", "aws_iam_role", svc)) == {}


def test_publicly_accessible_string_true_gates():
    # Round-13 F13-2: a hostile-plan string "true" for publicly_accessible must still gate.
    assert _rules(_rc("aws_db_instance.d", "aws_db_instance",
                      {"publicly_accessible": "true"}))["PUBLIC_DB_ENDPOINT"] == Severity.ERROR


def test_wildcard_principal_trust_policy_still_flagged():
    # ...but a role ANYONE may assume (wildcard principal) is still CRITICAL via PUBLIC_PRINCIPAL.
    after = {"assume_role_policy": _doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                         "Principal": {"AWS": "*"}})}
    assert _rules(_rc("aws_iam_role.app", "aws_iam_role", after))["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_assumerole_in_identity_policy_still_flagged():
    # sts:AssumeRole in an IDENTITY policy (no Principal) IS a privesc concern — must still gate.
    after = {"policy": _doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::1:role/admin"})}
    assert "PRIVILEGE_ESCALATION" in _rules(_rc("aws_iam_role_policy.x", "aws_iam_role_policy", after))


def test_publicly_accessible_on_noncurated_type_flagged():
    # Round-12 F12-1: the generic PUBLIC_DB_ENDPOINT rule must be reachable for ANY routable type, not
    # only the curated db/redshift list — e.g. a DMS replication instance with a public IP.
    assert _rules(_rc("aws_dms_replication_instance.x", "aws_dms_replication_instance",
                      {"publicly_accessible": True}))["PUBLIC_DB_ENDPOINT"] == Severity.ERROR
    # a non-IAM resource that does NOT flag public exposure is still ignored (no over-extraction)
    assert _rules(_rc("aws_dms_replication_instance.x", "aws_dms_replication_instance",
                      {"publicly_accessible": False})) == {}


def test_computed_publicly_accessible_fails_closed():
    # Round-9: a computed publicly_accessible / acl / source_ranges must fail closed.
    rc = {"address": "aws_db_instance.d", "type": "aws_db_instance",
          "change": {"actions": ["create"], "after": {"engine": "postgres"},
                     "after_unknown": {"publicly_accessible": True}}}
    assert "UNKNOWN_IAM_CONTENT" in _rules(rc)


def test_deeply_nested_unknown_fails_closed():
    # Round-11 F1: a pathologically deep after_unknown must FAIL CLOSED (assume computed), not silently
    # report 'known' past the recursion bound.
    from verel.ci.iac import _has_unknown
    node = True
    for _ in range(40):
        node = {"x": node}
    assert _has_unknown(node) is True


def test_data_external_gated_as_unauditable():
    # Round-7 F5: a data.external source runs an arbitrary program at refresh — gate like a provisioner.
    from verel.ci import parse_terraform_plan
    plan = {"configuration": {"root_module": {"resources": [
        {"address": "data.external.x", "mode": "data", "type": "external",
         "expressions": {"program": {"constant_value": ["bash", "-c", "aws iam attach-role-policy"]}}}]}}}
    rules = {json.loads(i.detail_json)["rule_id"] for i in parse_terraform_plan(json.dumps(plan))}
    assert "UNAUDITABLE_PROVISIONER" in rules


def _drift_plan(changes, drift):
    return json.dumps({"resource_changes": changes, "resource_drift": drift})


_DRIFT_ADMIN = {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy",
                "change": {"actions": ["update"]}}


def test_resource_drift_persistent_admin_gates():
    # Round-8 F4: an out-of-band admin grant in resource_drift with NO planned change → config matches
    # reality, the apply won't revert it → it GATES at real severity (the thunderstorm scenario).
    from verel.ci import parse_terraform_plan
    d = dict(_DRIFT_ADMIN, change={"actions": ["update"],
             "after": {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}})
    issues = parse_terraform_plan(_drift_plan([], [d]))
    drift = [i for i in issues if json.loads(i.detail_json).get("drift")]
    assert drift and any(i.severity == Severity.CRITICAL and json.loads(i.detail_json)["persists"]
                         for i in drift)


def test_resource_drift_noop_shadow_still_gates():
    # Round-9 F9-1 (CRITICAL): a no-op resource_changes entry for the drifted address must NOT
    # downgrade the persistent admin grant — a no-op doesn't overwrite it, and the genuine persistent
    # case is EXACTLY when terraform emits a no-op. (My round-8 F4 fix was inert/gameable without this.)
    from verel.ci import parse_terraform_plan
    d = dict(_DRIFT_ADMIN, change={"actions": ["update"],
             "after": {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}})
    shadow = {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy",
              "change": {"actions": ["no-op"], "after": {}}}
    issues = parse_terraform_plan(_drift_plan([shadow], [d]))
    drift = [i for i in issues if json.loads(i.detail_json).get("drift")]
    assert drift and any(i.severity == Severity.CRITICAL and json.loads(i.detail_json)["persists"]
                         for i in drift)


def test_no_iam_rule_emits_low_confidence():
    # Round-9 (integration guard): grade_iac uses its own inline reducer that does NOT apply gate()'s
    # LOW-confidence clamp. As long as no IAM/IAC rule emits Confidence.LOW the two agree. Pin it so a
    # future rule can't silently introduce a grade_iac/gate() divergence.
    from verel.ci import extract_rbac_risks, parse_terraform_plan
    from verel.verdict import Confidence
    plan = {"resource_changes": [
        _rc("aws_iam_policy.x", "aws_iam_policy",
            {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*", "Principal": "*"})}),
        _rc("aws_s3_bucket_public_access_block.b", "aws_s3_bucket_public_access_block", {})],
        "resource_drift": [dict(_DRIFT_ADMIN, change={"actions": ["update"],
            "after": {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}})]}
    cr = {"kind": "ClusterRole", "metadata": {"name": "x"},
          "rules": [{"resources": ["*"], "verbs": ["*"]}]}
    issues = parse_terraform_plan(json.dumps(plan)) + extract_rbac_risks([cr])
    assert issues and all(i.confidence != Confidence.LOW for i in issues)


def test_resource_drift_revertable_is_advisory():
    # Round-7/8: the SAME grant when the resource also has a planned change (apply may revert it) stays
    # advisory (WARNING) — only the persistent case gates.
    from verel.ci import parse_terraform_plan
    d = dict(_DRIFT_ADMIN, change={"actions": ["update"],
             "after": {"policy": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}})
    planned = {"address": "aws_iam_role_policy.x", "type": "aws_iam_role_policy",
               "change": {"actions": ["update"], "after": {"policy": _doc(
                   {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"})}}}
    issues = parse_terraform_plan(_drift_plan([planned], [d]))
    drift = [i for i in issues if json.loads(i.detail_json).get("drift")]
    assert drift and all(i.severity == Severity.WARNING for i in drift)


def test_aws_simulate_effective_allow_via_method():
    # Round-7 R7-1: the live AWS effective-access method must consume parse_aws_simulate (not dead code).
    from verel.actuators.access_verify import EffectiveAccessVerifier
    from verel.actuators.cloudcreds import CloudCreds
    creds = CloudCreds("aws", True, "/x", env={"AWS_ACCESS_KEY_ID": "x"})
    out = json.dumps({"EvaluationResults": [
        {"EvalActionName": "iam:PassRole", "EvalDecision": "allowed",
         "EvalResourceName": "arn:aws:iam::1:role/admin"}]})
    v = EffectiveAccessVerifier(runner=lambda cmd, env: (0, out, ""))
    rep = v.aws_simulate_principal("arn:aws:iam::1:role/app", ["iam:PassRole"], creds)
    assert rep.verdict.name == "FAIL" and any(
        json.loads(i.detail_json)["rule_id"] == "EFFECTIVE_ALLOW" for i in rep.issues)


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
        after = {"role_ref": [{"kind": "ClusterRole", "name": builtin}]}
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
