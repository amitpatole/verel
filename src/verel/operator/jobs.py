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

import re

_DEFAULT_IMAGE = "ghcr.io/amitpatole/verel:latest"
_DEFAULT_GIT_IMAGE = "cgr.dev/chainguard/git:latest"
_UID = 65532

# repo must be an https:// git URL — NOT ext::/file:///ssh:// (git transports that run commands /
# read local files), and NOT a `-`-prefixed string (git option injection).
_REPO_RE = re.compile(r"\Ahttps://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{3,512}\Z")
# RFC1918 + link-local: the untrusted gate must not reach the cloud metadata endpoint
# (169.254.169.254) or in-cluster API/pods/services. Public https (the clone) + DNS stay allowed.
_BLOCKED_EGRESS = ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def _safe_repo(repo: object) -> str:
    if not isinstance(repo, str) or repo.startswith("-") or "ext::" in repo or not _REPO_RE.match(repo):
        raise ValueError("GateRun.spec.repo must be an https:// git URL (no ext::/file:///ssh://)")
    return repo


def _safe_ref(ref: object) -> str:
    if not isinstance(ref, str) or ref.startswith("-") or any(c.isspace() for c in ref) or len(ref) > 256:
        raise ValueError("GateRun.spec.ref must be a plain git ref (no leading '-', no whitespace)")
    return ref

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
    repo = _safe_repo(spec.get("repo"))
    ref = _safe_ref(spec["ref"]) if spec.get("ref") else None
    stage = spec.get("stage", "pre_merge")
    # The gate image is the OPERATOR's trusted image — NOT author-supplied. Honouring spec.image would
    # let a GateRun author run an arbitrary image (and, combined with secret projection elsewhere, a
    # confused-deputy). The trusted gate is exactly what you want grading the repo.
    img = image or _DEFAULT_IMAGE
    gimg = git_image or _DEFAULT_GIT_IMAGE
    timeout = int(spec.get("timeoutSeconds", 600))
    resources = {  # fixed operator limits — author cannot remove/inflate them (bounded by the cluster)
        "requests": {"cpu": "250m", "memory": "512Mi"},
        "limits": {"cpu": "2", "memory": "2Gi"},
    }

    # Clone: disable the command-executing/local-file git transports; `--` ends options so a hostile
    # repo/ref (already shape-validated) can never be read as a git flag. argv form, never a shell.
    clone_args = ["-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
                  "clone", "--depth", "1"]
    if ref:
        clone_args += ["--branch", ref]
    clone_args += ["--", repo, "/workspace"]

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
                             {"name": "tmp", "mountPath": "/tmp"}],  # nosec B108 — emptyDir mount path
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
                             {"name": "tmp", "mountPath": "/tmp"}],  # nosec B108 — emptyDir mount path
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


def build_gaterun_netpol(name: str, namespace: str, *, owner: dict | None = None) -> dict:
    """A default-deny-egress NetworkPolicy for the GateRun pod (untrusted code). Allows ONLY DNS and
    public HTTPS (the clone) — and **blocks the cloud metadata endpoint + all in-cluster ranges**
    (RFC1918), so the gate can't steal node IAM creds or pivot to the API server / other pods. (NP
    enforcement depends on the CNI; it layers under the in-container bwrap and the no-SA-token Job.)"""
    meta: dict = {"name": f"{name}-deny", "namespace": namespace,
                  "labels": {"app.kubernetes.io/managed-by": "verel-operator"}}
    if owner:
        meta["ownerReferences"] = [owner]
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": meta,
        "spec": {
            "podSelector": {"matchLabels": {"verel.dev/gaterun": name}},
            "policyTypes": ["Egress"],
            "egress": [
                {"ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},  # DNS
                {"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": list(_BLOCKED_EGRESS)}}],
                 "ports": [{"protocol": "TCP", "port": 443}]},  # public https clone only
            ],
        },
    }
