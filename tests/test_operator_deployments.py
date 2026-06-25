"""GatewayService / VerelFleet deployment builders — hardening + fail-closed wiring."""

import pytest

pytest.importorskip("kopf", reason="operator tests need verel[operator]")

from verel.operator.deployments import (
    build_fleet_deployment,
    build_gateway_deployment,
    build_service,
)


def _pod(dep):
    return dep["spec"]["template"]["spec"]


def test_gateway_is_hardened_and_tls_by_default():
    dep = build_gateway_deployment("gw", "verel", {})
    pod = _pod(dep)
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    c = pod["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert "--certfile" in c["args"] and c["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"
    # confused-deputy defense: the token/TLS Secrets are operator-DERIVED from the CR name, not
    # author-supplied, so a CR author can't redirect the operator at an arbitrary in-namespace Secret.
    assert any(e.get("valueFrom", {}).get("secretKeyRef", {}).get("name") == "gw-auth" for e in c["env"])
    assert any(v.get("secret", {}).get("secretName") == "gw-tls" for v in pod["volumes"])


def test_gateway_image_is_operator_controlled_not_from_spec():
    dep = build_gateway_deployment("gw", "verel", {"image": "attacker/evil:latest"}, image="trusted:1")
    assert _pod(dep)["containers"][0]["image"] == "trusted:1"


def test_gateway_insecure_path_sets_env_and_http_probe():
    dep = build_gateway_deployment("gw", "verel", {"insecure": True})
    c = _pod(dep)["containers"][0]
    assert {"name": "VEREL_GATE_INSECURE", "value": "1"} in c["env"]
    assert "--certfile" not in c["args"] and c["readinessProbe"]["httpGet"]["scheme"] == "HTTP"


def test_multi_replica_workloads_have_anti_affinity_and_ephemeral_storage():
    # kube-linter no-anti-affinity + kube-score ephemeral-storage: best-practice on managed workloads.
    for dep in (build_gateway_deployment("gw", "verel", {}),
                build_fleet_deployment("fl", "verel", {"brain": "main"})):
        pod = _pod(dep)
        term = pod["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]
        assert term["podAffinityTerm"]["topologyKey"] == "kubernetes.io/hostname"
        res = pod["containers"][0]["resources"]
        assert res["requests"]["ephemeral-storage"] and res["limits"]["ephemeral-storage"]
        assert pod["containers"][0]["livenessProbe"]["httpGet"]["path"] == "/health"


def test_fleet_validates_brain_name_and_is_hardened():
    with pytest.raises(ValueError, match="brain"):
        build_fleet_deployment("f", "verel", {})
    with pytest.raises(ValueError, match="brain"):           # not a DNS label → can't steer the secretRef
        build_fleet_deployment("f", "verel", {"brain": "../other-conn"})
    dep = build_fleet_deployment("f", "verel", {"workers": 3, "brain": "main"}, image="trusted:1")
    assert dep["spec"]["replicas"] == 3 and _pod(dep)["containers"][0]["image"] == "trusted:1"
    pod = _pod(dep)
    assert pod["automountServiceAccountToken"] is False
    assert pod["containers"][0]["envFrom"][0]["secretRef"]["name"] == "main-conn"  # derived from the validated name


def test_service_selects_owner():
    svc = build_service("gw", "verel")
    assert svc["spec"]["selector"] == {"verel.dev/owner": "gw"}
    assert svc["spec"]["ports"][0]["port"] == 8443
