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
    dep = build_gateway_deployment("gw", "verel", {"tlsSecret": "tls", "authSecret": "auth"})
    pod = _pod(dep)
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    c = pod["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert "--certfile" in c["args"] and c["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"
    # the token comes from a Secret, never inline
    assert any(e.get("valueFrom", {}).get("secretKeyRef", {}).get("name") == "auth" for e in c["env"])


def test_gateway_fails_closed_without_tls_or_insecure():
    with pytest.raises(ValueError, match="tlsSecret"):
        build_gateway_deployment("gw", "verel", {"authSecret": "auth"})


def test_gateway_requires_auth_secret():
    with pytest.raises(ValueError, match="authSecret"):
        build_gateway_deployment("gw", "verel", {"tlsSecret": "tls"})


def test_gateway_insecure_path_sets_env_and_http_probe():
    dep = build_gateway_deployment("gw", "verel", {"insecure": True, "authSecret": "auth"})
    c = _pod(dep)["containers"][0]
    assert {"name": "VEREL_GATE_INSECURE", "value": "1"} in c["env"]
    assert "--certfile" not in c["args"] and c["readinessProbe"]["httpGet"]["scheme"] == "HTTP"


def test_fleet_requires_brain_and_is_hardened():
    with pytest.raises(ValueError, match="brain"):
        build_fleet_deployment("f", "verel", {})
    dep = build_fleet_deployment("f", "verel", {"workers": 3, "brain": "main"})
    assert dep["spec"]["replicas"] == 3
    pod = _pod(dep)
    assert pod["automountServiceAccountToken"] is False
    # shares the Brain's connection Secret
    assert pod["containers"][0]["envFrom"][0]["secretRef"]["name"] == "main-conn"


def test_service_selects_owner():
    svc = build_service("gw", "verel")
    assert svc["spec"]["selector"] == {"verel.dev/owner": "gw"}
    assert svc["spec"]["ports"][0]["port"] == 8443
