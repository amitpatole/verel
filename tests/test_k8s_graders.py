"""Kubernetes graders + native RBAC sensor (IAC-KICKOFF.md Phase 3). Pure over canned tool output."""

import json

import pytest

from verel.ci import (
    extract_rbac_risks,
    parse_helm_template,
    parse_kube_linter,
    parse_kube_objects,
    parse_kube_score,
    parse_polaris,
)
from verel.verdict import GraderKind, Severity


def _rules(*manifests) -> dict[str, Severity]:
    issues = extract_rbac_risks(list(manifests))
    assert all(i.source == GraderKind.IAM for i in issues)
    return {json.loads(i.detail_json)["rule_id"]: i.severity for i in issues}


def _role(kind, name, rules, ns=None):
    md = {"name": name}
    if ns:
        md["namespace"] = ns
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": md, "rules": rules}


def _binding(kind, name, role_ref_name, subjects):
    return {"kind": kind, "metadata": {"name": name},
            "roleRef": {"kind": "ClusterRole", "name": role_ref_name}, "subjects": subjects}


# --- RBAC sensor ---------------------------------------------------------
def test_wildcard_clusterrole():
    r = _role("ClusterRole", "god", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
    assert _rules(r)["WILDCARD_RBAC"] == Severity.ERROR


def test_rbac_privilege_escalation_verbs():
    r = _role("ClusterRole", "esc", [{"apiGroups": ["rbac.authorization.k8s.io"],
                                      "resources": ["clusterroles"], "verbs": ["escalate", "bind"]}])
    assert _rules(r)["PRIVILEGE_ESCALATION"] == Severity.CRITICAL


def test_cluster_secret_read_is_error_namespaced_is_warning():
    cr = _role("ClusterRole", "cs", [{"resources": ["secrets"], "verbs": ["get", "list"]}])
    ns = _role("Role", "ns", [{"resources": ["secrets"], "verbs": ["get"]}], ns="default")
    assert _rules(cr)["SECRETS_ACCESS"] == Severity.ERROR
    assert _rules(ns)["SECRETS_ACCESS"] == Severity.WARNING


def test_binding_cluster_admin():
    b = _binding("ClusterRoleBinding", "b", "cluster-admin", [{"kind": "User", "name": "dev"}])
    assert _rules(b)["ADMIN_GRANT"] == Severity.ERROR


def test_binding_system_masters():
    b = _binding("ClusterRoleBinding", "b", "viewer", [{"kind": "Group", "name": "system:masters"}])
    assert _rules(b)["ADMIN_GRANT"] == Severity.ERROR


def test_binding_anonymous_subject():
    b = _binding("ClusterRoleBinding", "b", "viewer", [{"kind": "User", "name": "system:anonymous"}])
    assert _rules(b)["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_binding_unauthenticated_group():
    b = _binding("ClusterRoleBinding", "b", "viewer",
                 [{"kind": "Group", "name": "system:unauthenticated"}])
    assert _rules(b)["PUBLIC_PRINCIPAL"] == Severity.CRITICAL


def test_non_rbac_and_safe_role_yield_nothing():
    pod = {"kind": "Pod", "metadata": {"name": "p"}}
    safe = _role("Role", "safe", [{"resources": ["pods"], "verbs": ["get"]}], ns="default")
    assert _rules(pod, safe) == {}


# --- parse_kube_objects (JSON shapes) ------------------------------------
def test_parse_kube_objects_list_object():
    out = json.dumps({"apiVersion": "v1", "kind": "List", "items": [
        _role("ClusterRole", "god", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])]})
    assert len(parse_kube_objects(out)) == 1


def test_parse_kube_objects_single_and_ndjson():
    single = json.dumps(_binding("ClusterRoleBinding", "b", "cluster-admin",
                                 [{"kind": "User", "name": "x"}]))
    assert len(parse_kube_objects(single)) == 1
    ndjson = single + "\n" + json.dumps({"kind": "Pod", "metadata": {"name": "p"}})
    assert len(parse_kube_objects(ndjson)) == 1


def test_parse_kube_objects_garbage():
    assert parse_kube_objects("not json at all") == []


# --- parse_helm_template (YAML, needs pyyaml) ----------------------------
def test_parse_helm_template_yaml():
    pytest.importorskip("yaml")
    yaml_out = (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n  name: b\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"
        "subjects:\n- kind: ServiceAccount\n  name: sa\n"
        "---\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n")
    issues = parse_helm_template(yaml_out)
    assert len(issues) == 1 and json.loads(issues[0].detail_json)["rule_id"] == "ADMIN_GRANT"


# --- config posture scanners --------------------------------------------
def test_parse_kube_score_grades():
    out = json.dumps([{"object_name": "Deployment/foo", "checks": [
        {"check": {"id": "pod-probes", "name": "Pod Probes"}, "grade": 1,
         "comments": [{"summary": "no readiness probe"}]},
        {"check": {"id": "x", "name": "X"}, "grade": 5, "comments": []},
        {"check": {"id": "ok", "name": "OK"}, "grade": 10, "comments": []}]}])
    issues = parse_kube_score(out)
    assert {i.severity for i in issues} == {Severity.ERROR, Severity.WARNING}  # grade 10 skipped
    assert all(i.source == GraderKind.SECURITY for i in issues)
    assert issues[0].locator == "Deployment/foo"


def test_parse_kube_linter():
    out = json.dumps({"Reports": [{"Check": "run-as-non-root",
        "Diagnostic": {"Message": "container runs as root"},
        "Object": {"K8sObject": {"Namespace": "default", "Name": "foo",
                                 "GroupVersionKind": {"Kind": "Deployment"}}}}]})
    issues = parse_kube_linter(out)
    assert len(issues) == 1 and issues[0].source == GraderKind.SECURITY
    assert issues[0].locator == "Deployment/default/foo" and "run-as-non-root" in issues[0].message


def test_parse_polaris_nested():
    out = json.dumps({"Results": [{"Name": "foo", "Namespace": "default", "Kind": "Deployment",
        "PodResult": {"ContainerResults": [{"Name": "c", "Results": {
            "runAsNonRoot": {"ID": "runAsNonRoot", "Success": False, "Severity": "danger",
                             "Message": "Should run as non-root"},
            "cpuLimits": {"ID": "cpuLimits", "Success": True, "Severity": "warning",
                          "Message": "ok"}}}]}}]})
    issues = parse_polaris(out)
    assert len(issues) == 1  # only the failed check
    assert issues[0].severity == Severity.ERROR and issues[0].locator == "Deployment/default/foo"


def test_scanners_tolerate_garbage():
    for p in (parse_kube_score, parse_kube_linter, parse_polaris):
        assert p("not json") == []
