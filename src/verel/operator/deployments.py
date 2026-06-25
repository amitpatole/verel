"""Pure manifest builders for the long-running CRDs (GatewayService, VerelFleet). Like the GateRun Job
builder, these are deterministic functions so the security/wiring is unit-asserted without a cluster.
Both run the hardened Verel image with the same pod hardening (nonroot, RO-rootfs, drop-ALL, no SA
token, seccomp)."""

from __future__ import annotations

from .jobs import _CONTAINER_SECURITY, _DEFAULT_IMAGE, _POD_SECURITY

_LABELS = "app.kubernetes.io/managed-by"


def _labels(name: str, component: str) -> dict:
    return {_LABELS: "verel-operator", "app.kubernetes.io/name": name,
            "app.kubernetes.io/component": component, "verel.dev/owner": name}


def _hardened_pod(containers: list, volumes: list | None = None) -> dict:
    return {
        "automountServiceAccountToken": False,
        "securityContext": dict(_POD_SECURITY),
        "containers": containers,
        "volumes": volumes or [{"name": "tmp", "emptyDir": {}}],
    }


def build_gateway_deployment(name: str, namespace: str, spec: dict, *, owner: dict | None = None) -> dict:
    """A `verel serve` Deployment (the GatewayService). Fail-closed like the chart: a routable bind
    needs auth + TLS (tlsSecret) or the explicit insecure opt-out behind an ingress."""
    image = spec.get("image") or _DEFAULT_IMAGE
    replicas = int(spec.get("replicas", 1))
    insecure = bool(spec.get("insecure", False))
    tls_secret = spec.get("tlsSecret")
    auth_secret = spec.get("authSecret")
    if not auth_secret:
        raise ValueError("GatewayService.spec.authSecret is required (a Secret with key 'token')")
    if not insecure and not tls_secret:
        raise ValueError("GatewayService needs spec.tlsSecret (in-pod TLS) or spec.insecure=true "
                         "(behind a TLS-terminating ingress)")
    mount = spec.get("repoMountPath", "/workspace")
    args = ["serve", "--host", "0.0.0.0", "--port", "8443", "--repo", mount, "--no-lint"]
    vmounts = [{"name": "tmp", "mountPath": "/tmp"}, {"name": "repo", "mountPath": mount}]
    volumes = [{"name": "tmp", "emptyDir": {}}, {"name": "repo", "emptyDir": {}}]
    env = [{"name": "VEREL_GATE_TOKEN",
            "valueFrom": {"secretKeyRef": {"name": auth_secret, "key": "token"}}},
           {"name": "VEREL_GATE_WEBHOOK_SECRET",
            "valueFrom": {"secretKeyRef": {"name": auth_secret, "key": "webhookSecret", "optional": True}}}]
    if insecure:
        env.append({"name": "VEREL_GATE_INSECURE", "value": "1"})
    else:
        args += ["--certfile", "/tls/tls.crt", "--keyfile", "/tls/tls.key"]
        vmounts.append({"name": "tls", "mountPath": "/tls", "readOnly": True})
        volumes.append({"name": "tls", "secret": {"secretName": tls_secret}})
    scheme = "HTTP" if insecure else "HTTPS"
    container = {
        "name": "gateway", "image": image, "args": args, "env": env,
        "securityContext": dict(_CONTAINER_SECURITY),
        "ports": [{"name": "https", "containerPort": 8443}],
        "livenessProbe": {"httpGet": {"path": "/health", "port": "https", "scheme": scheme}},
        "readinessProbe": {"httpGet": {"path": "/ready", "port": "https", "scheme": scheme}},
        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                      "limits": {"cpu": "1", "memory": "512Mi"}},
        "volumeMounts": vmounts,
    }
    return _deployment(name, namespace, "gateway", replicas, _hardened_pod([container], volumes), owner)


def build_service(name: str, namespace: str, *, owner: dict | None = None, port: int = 8443) -> dict:
    meta = {"name": name, "namespace": namespace, "labels": _labels(name, "gateway")}
    if owner:
        meta["ownerReferences"] = [owner]
    return {"apiVersion": "v1", "kind": "Service", "metadata": meta,
            "spec": {"selector": {"verel.dev/owner": name},
                     "ports": [{"name": "https", "port": port, "targetPort": "https"}]}}


def build_fleet_deployment(name: str, namespace: str, spec: dict, *, owner: dict | None = None) -> dict:
    """A pool of gate workers sharing one Brain (the Brain CR's connection Secret supplies the backend
    env). Hardened like the gateway; horizontally scalable."""
    image = spec.get("image") or _DEFAULT_IMAGE
    workers = int(spec.get("workers", 2))
    brain = spec.get("brain")
    if not brain:
        raise ValueError("VerelFleet.spec.brain (a Brain CR name) is required")
    container = {
        "name": "worker", "image": image,
        "args": ["serve", "--host", "0.0.0.0", "--port", "8443", "--repo", "/workspace", "--no-lint"],
        "securityContext": dict(_CONTAINER_SECURITY),
        "env": [{"name": "VEREL_GATE_INSECURE", "value": "1"},   # in-cluster pool behind the fleet svc
                {"name": "VEREL_GATE_TOKEN",
                 "valueFrom": {"secretKeyRef": {"name": f"{name}-auth", "key": "token"}}}],
        # the shared brain: the Brain CR's connection Secret (VEREL_MEMORY_BACKEND + URL) as envFrom.
        "envFrom": [{"secretRef": {"name": f"{brain}-conn", "optional": True}}],
        "ports": [{"name": "https", "containerPort": 8443}],
        "readinessProbe": {"httpGet": {"path": "/ready", "port": "https", "scheme": "HTTP"}},
        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                      "limits": {"cpu": "1", "memory": "512Mi"}},
        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}, {"name": "repo", "mountPath": "/workspace"}],
    }
    pod = _hardened_pod([container], [{"name": "tmp", "emptyDir": {}}, {"name": "repo", "emptyDir": {}}])
    return _deployment(name, namespace, "fleet-worker", workers, pod, owner)


def _deployment(name: str, namespace: str, component: str, replicas: int, pod: dict,
                owner: dict | None) -> dict:
    meta = {"name": name, "namespace": namespace, "labels": _labels(name, component)}
    if owner:
        meta["ownerReferences"] = [owner]
    return {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta,
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"verel.dev/owner": name}},
            "template": {"metadata": {"labels": _labels(name, component)}, "spec": pod},
        },
    }
