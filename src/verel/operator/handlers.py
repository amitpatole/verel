"""Kopf reconcile handlers for the Verel CRDs. Thin glue over the Kubernetes API — the security-
critical logic (the hardened GateRun Job) lives in `jobs.build_gaterun_job` and is unit-tested there.

These handlers require a cluster; they're exercised by the operator e2e (k3d/kind) in CI, not unit
tests. Import is lazy/guarded so `verel[operator]` is only needed to actually run the operator."""

from __future__ import annotations

import kopf

from . import API_GROUP, API_VERSION
from .jobs import build_gaterun_job

_GV = (API_GROUP, API_VERSION)


@kopf.on.startup()
def _configure(settings, **_):
    # Standalone: no peering CRD / lease needed (single operator replica). Bound watch backoff so a
    # transient API error doesn't hot-loop.
    settings.peering.standalone = True
    settings.watching.server_timeout = 600


def _k8s():
    from kubernetes import client, config
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client


def _owner(body) -> dict:
    return {"apiVersion": f"{API_GROUP}/{API_VERSION}", "kind": body["kind"],
            "name": body["metadata"]["name"], "uid": body["metadata"]["uid"],
            "controller": True, "blockOwnerDeletion": True}


# ---- GateRun: one-shot grade → hardened Job → verdict in .status ----
@kopf.on.create(*_GV, "gateruns")
def gaterun_create(spec, name, namespace, body, patch, logger, **_):
    job = build_gaterun_job(name, namespace, dict(spec), owner=_owner(body))
    batch = _k8s().BatchV1Api()
    try:
        batch.create_namespaced_job(namespace, job)
    except Exception as e:  # already exists on a retry → idempotent
        if "already exists" not in str(e):
            raise
    logger.info("GateRun %s: created hardened Job %s", name, name)
    patch.status["phase"] = "Running"
    patch.status["jobName"] = name


@kopf.on.event("batch", "v1", "jobs",
               labels={"verel.dev/gaterun": kopf.PRESENT})
def gaterun_job_event(meta, status, namespace, logger, **_):
    """Mirror the owning GateRun's status from its Job's completion (exit code → verdict)."""
    gr = meta["labels"]["verel.dev/gaterun"]
    succeeded = (status or {}).get("succeeded", 0)
    failed = (status or {}).get("failed", 0)
    if not succeeded and not failed:
        return
    api = _k8s().CustomObjectsApi()
    phase, verdict = ("Passed", "pass") if succeeded else ("Failed", "fail")
    body = {"status": {"phase": phase, "verdict": verdict,
                       "message": f"job {phase.lower()}"}}
    try:
        api.patch_namespaced_custom_object_status(
            API_GROUP, API_VERSION, namespace, "gateruns", gr, body)
        logger.info("GateRun %s -> %s (%s)", gr, phase, verdict)
    except Exception as e:
        logger.warning("GateRun %s status patch failed: %s", gr, e)


# ---- Brain: validate the connection Secret exists; (optional) bootstrap; mark ready ----
@kopf.on.create(*_GV, "brains")
def brain_create(spec, name, namespace, patch, logger, **_):
    secret = spec.get("connectionSecret")
    core = _k8s().CoreV1Api()
    try:
        core.read_namespaced_secret(secret, namespace)
    except Exception as e:
        patch.status["ready"] = "False"
        patch.status["message"] = f"connectionSecret {secret!r} not found"
        raise kopf.TemporaryError(f"waiting for Secret {secret!r}", delay=15) from e
    patch.status["ready"] = "True"
    patch.status["message"] = f"{spec.get('backend')} brain wired to {secret}"
    logger.info("Brain %s ready (backend=%s)", name, spec.get("backend"))


# ---- GatewayService: a managed `verel serve` Deployment + Service ----
@kopf.on.create(*_GV, "gatewayservices")
@kopf.on.update(*_GV, "gatewayservices")
def gatewayservice_apply(spec, name, namespace, body, patch, logger, **_):
    from .deployments import build_gateway_deployment, build_service
    apps, core = _k8s().AppsV1Api(), _k8s().CoreV1Api()
    owner = _owner(body)
    dep = build_gateway_deployment(name, namespace, dict(spec), owner=owner)
    svc = build_service(name, namespace, owner=owner)
    _apply(apps.create_namespaced_deployment, apps.patch_namespaced_deployment, namespace, name, dep)
    _apply(core.create_namespaced_service, core.patch_namespaced_service, namespace, name, svc)
    patch.status["replicas"] = spec.get("replicas", 1)
    logger.info("GatewayService %s applied (replicas=%s)", name, spec.get("replicas", 1))


# ---- VerelFleet: N workers sharing a Brain ----
@kopf.on.create(*_GV, "verelfleets")
@kopf.on.update(*_GV, "verelfleets")
def verelfleet_apply(spec, name, namespace, body, patch, logger, **_):
    from .deployments import build_fleet_deployment
    apps = _k8s().AppsV1Api()
    dep = build_fleet_deployment(name, namespace, dict(spec), owner=_owner(body))
    _apply(apps.create_namespaced_deployment, apps.patch_namespaced_deployment, namespace, name, dep)
    patch.status["workers"] = spec.get("workers", 2)
    logger.info("VerelFleet %s applied (workers=%s, brain=%s)", name, spec.get("workers", 2),
                spec.get("brain"))


def _apply(create, replace, namespace, name, manifest):
    """Create the object, or patch it if it already exists (idempotent reconcile)."""
    try:
        create(namespace, manifest)
    except Exception as e:
        if "already exists" in str(e):
            replace(name, namespace, manifest)
        else:
            raise
