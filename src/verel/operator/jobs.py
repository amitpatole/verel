"""Build the GateRun Job — the security-critical artifact of the operator.

A GateRun grades an arbitrary repo/PR, so its Job **executes untrusted code** (the repo's test suite,
build, etc.) inside the cluster. The whole point of this module is defense-in-depth isolation, applied
as a PURE function so every control is unit-asserted without a cluster:

  Pod / container hardening (the always-on floor, every cluster):
   - runAsNonRoot + a non-root UID/GID, fsGroup; seccompProfile RuntimeDefault
   - allowPrivilegeEscalation: false, readOnlyRootFilesystem, drop ALL capabilities
   - automountServiceAccountToken: false (the untrusted Job gets NO Kubernetes API credential)
   - resource limits + activeDeadlineSeconds (no runaway); restartPolicy Never, backoffLimit 0
  Stronger isolation when the cluster offers it:
   - runtimeClassName (gVisor/Kata) — kernel-level sandbox, used when spec.runtimeClassName is set
  In-container, the gate itself runs each generated check under Verel's bwrap `--unshare-all` +
  seccomp runner, so even the gate's own subprocesses are network/PID/mount-isolated REGARDLESS of the
  pod's egress (which the clone step needs).

The clone runs in a separate initContainer (a git image) into a shared emptyDir; the gate container is
distroless verel and never has git/network tooling. The result (verdict + receipt JSON on stdout) is
read back by the operator from the Job's pod and written to GateRun.status — the Job needs no API token.
"""

from __future__ import annotations

_DEFAULT_IMAGE = "ghcr.io/amitpatole/verel:latest"
_DEFAULT_GIT_IMAGE = "cgr.dev/chainguard/git:latest"
_UID = 65532

_POD_SECURITY = {
    "runAsNonRoot": True,
    "runAsUser": _UID,
    "runAsGroup": _UID,
    "fsGroup": _UID,
    "seccompProfile": {"type": "RuntimeDefault"},
}
_CONTAINER_SECURITY = {
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
    "runAsNonRoot": True,
}


def build_gaterun_job(name: str, namespace: str, spec: dict, *, owner: dict | None = None,
                      image: str | None = None, git_image: str | None = None) -> dict:
    """Pure: a GateRun CR `spec` → a hardened batch/v1 Job manifest.

    spec keys: repo (required, a git URL), ref (optional git ref), stage (default 'pre_merge'),
    image (override), runtimeClassName (gVisor/Kata), timeoutSeconds (default 600),
    resources (override the limits)."""
    repo = spec.get("repo")
    if not repo or not isinstance(repo, str):
        raise ValueError("GateRun.spec.repo (a git URL) is required")
    ref = spec.get("ref")
    stage = spec.get("stage", "pre_merge")
    img = spec.get("image") or image or _DEFAULT_IMAGE
    gimg = git_image or _DEFAULT_GIT_IMAGE
    timeout = int(spec.get("timeoutSeconds", 600))
    resources = spec.get("resources") or {
        "requests": {"cpu": "250m", "memory": "512Mi"},
        "limits": {"cpu": "2", "memory": "2Gi"},
    }

    # The clone command — `ref` is passed as an argv element to `git`, never shell-interpolated.
    clone_args = ["clone", "--depth", "1"]
    if ref:
        clone_args += ["--branch", ref]
    clone_args += [repo, "/workspace"]

    pod_spec: dict = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,   # untrusted Job → no API credential
        "securityContext": dict(_POD_SECURITY),
        "initContainers": [{
            "name": "clone",
            "image": gimg,
            "args": clone_args,
            "securityContext": dict(_CONTAINER_SECURITY),
            "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"},
                             {"name": "tmp", "mountPath": "/tmp"}],
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                          "limits": {"cpu": "500m", "memory": "256Mi"}},
        }],
        "containers": [{
            "name": "gate",
            "image": img,
            # run the gate over the cloned repo; the gate isolates its own checks with bwrap+seccomp.
            "args": ["ci", "check", "--repo", "/workspace", "--stage", stage],
            "securityContext": dict(_CONTAINER_SECURITY),
            "env": [{"name": "VEREL_GATERUN", "value": name}],
            "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"},
                             {"name": "tmp", "mountPath": "/tmp"}],
            "resources": resources,
        }],
        "volumes": [
            {"name": "workspace", "emptyDir": {}},
            {"name": "tmp", "emptyDir": {}},
        ],
    }
    # Stronger, kernel-level isolation when the cluster provides a sandbox RuntimeClass.
    if spec.get("runtimeClassName"):
        pod_spec["runtimeClassName"] = spec["runtimeClassName"]

    meta: dict = {"name": name, "namespace": namespace,
                  "labels": {"app.kubernetes.io/managed-by": "verel-operator",
                             "verel.dev/gaterun": name}}
    if owner:
        meta["ownerReferences"] = [owner]

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": meta,
        "spec": {
            "backoffLimit": 0,                 # never retry untrusted execution
            "activeDeadlineSeconds": timeout,  # hard wall-clock cap
            "ttlSecondsAfterFinished": 3600,
            "template": {
                "metadata": {"labels": {"verel.dev/gaterun": name}},
                "spec": pod_spec,
            },
        },
    }
