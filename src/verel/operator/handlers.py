"""Kopf reconcile handlers for the Verel CRDs. Thin glue over the Kubernetes API — the security-
critical logic (the hardened GateRun Job + its NetworkPolicy) lives in `jobs` and is unit-tested
there. These handlers require a cluster; they're exercised by the operator e2e (k3d/kind) in CI."""

from __future__ import annotations

import os

import kopf

from . import API_GROUP, API_VERSION
from .jobs import _DEFAULT_IMAGE, build_gaterun_job, build_gaterun_netpol

_GV = (API_GROUP, API_VERSION)


def _trusted_image() -> str:
    """The image the operator runs for ALL managed workloads — operator-controlled, never from a CR
    spec (closes the confused-deputy: an author can't make the operator run an attacker image)."""
    return os.environ.get("VEREL_GATERUN_IMAGE", _DEFAULT_IMAGE)


@kopf.on.startup()
def _configure(settings, **_):
    settings.peering.standalone = True          # single replica; no peering CRD/lease needed
    settings.watching.server_timeout = 600


def _k8s():
    from kubernetes import client, config
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client


def _owner(body) -> dict:
    # controller:true wires garbage collection; we deliberately DON'T set blockOwnerDeletion (that
    # needs an `update` on the owner's /finalizers, which the least-privilege RBAC omits).
    return {"apiVersion": f"{API_GROUP}/{API_VERSION}", "kind": body["kind"],
            "name": body["metadata"]["name"], "uid": body["metadata"]["uid"], "controller": True}


def _conflict(exc) -> bool:
    return getattr(exc, "status", None) == 409 or "already exists" in str(exc)


# ---- GateRun: one-shot grade → hardened Job + deny-egress NetworkPolicy → verdict in .status ----
@kopf.on.create(*_GV, "gateruns")
def gaterun_create(spec, name, namespace, body, patch, logger, **_):
    owner = _owner(body)
    netpol = build_gaterun_netpol(name, namespace, owner=owner)
    job = build_gaterun_job(name, namespace, dict(spec), owner=owner, image=_trusted_image())
    net, batch = _k8s().NetworkingV1Api(), _k8s().BatchV1Api()
    # NetworkPolicy FIRST, so the untrusted pod is fenced before it can run.
    try:
        net.create_namespaced_network_policy(namespace, netpol)
    except Exception as e:
        if not _conflict(e):
            raise
    try:
        batch.create_namespaced_job(namespace, job)
    except Exception as e:
        if not _conflict(e):
            raise
    logger.info("GateRun %s: created deny-egress NetworkPolicy + hardened Job", name)
    patch.status["phase"] = "Running"
    patch.status["jobName"] = name


@kopf.on.event("batch", "v1", "jobs", labels={"verel.dev/gaterun": kopf.PRESENT})
def gaterun_job_event(meta, status, namespace, logger, **_):
    """Mirror the owning GateRun's status from ITS Job. Verdict forgery guard: only act on a Job that
    is actually OWNED by the GateRun (ownerReference uid), never merely carrying the label — else a
    user could create a labelled Job to forge another GateRun's verdict."""
    gr = meta.get("labels", {}).get("verel.dev/gaterun")
    owned = any(o.get("kind") == "GateRun" and o.get("name") == gr and o.get("controller")
                for o in meta.get("ownerReferences", []))
    if not gr or not owned:
        return  # unowned/forged Job carrying the label → ignore
    succeeded = (status or {}).get("succeeded", 0)
    failed = (status or {}).get("failed", 0)
    if not succeeded and not failed:
        return
    phase, verdict = ("Passed", "pass") if succeeded else ("Failed", "fail")
    body = {"status": {"phase": phase, "verdict": verdict,
                       "message": f"job {phase.lower()} (verdict from exit status; warn not distinguished)"}}
    try:
        _k8s().CustomObjectsApi().patch_namespaced_custom_object_status(
            API_GROUP, API_VERSION, namespace, "gateruns", gr, body)
        logger.info("GateRun %s -> %s (%s)", gr, phase, verdict)
    except Exception as e:
        logger.warning("GateRun %s status patch failed: %s", gr, e)


# ---- Brain: validate the connection Secret exists; mark ready ----
@kopf.on.create(*_GV, "brains")
def brain_create(spec, name, namespace, patch, logger, **_):
    secret = spec.get("connectionSecret")
    try:
        _k8s().CoreV1Api().read_namespaced_secret(secret, namespace)
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
    dep = build_gateway_deployment(name, namespace, dict(spec), owner=owner, image=_trusted_image())
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
    dep = build_fleet_deployment(name, namespace, dict(spec), owner=_owner(body), image=_trusted_image())
    _apply(apps.create_namespaced_deployment, apps.patch_namespaced_deployment, namespace, name, dep)
    patch.status["workers"] = spec.get("workers", 2)
    logger.info("VerelFleet %s applied (workers=%s, brain=%s)", name, spec.get("workers", 2),
                spec.get("brain"))


def _apply(create, replace, namespace, name, manifest):
    """Create the object, or patch it if it already exists (409) — idempotent reconcile."""
    try:
        create(namespace, manifest)
    except Exception as e:
        if _conflict(e):
            replace(name, namespace, manifest)
        else:
            raise
