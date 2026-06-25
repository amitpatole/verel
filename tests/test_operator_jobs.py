"""The GateRun Job builder runs UNTRUSTED repo code in-cluster — pin every isolation control."""

import pytest

pytest.importorskip("kopf", reason="operator tests need verel[operator]")

from verel.operator import build_gaterun_job


def _job(spec=None, **kw):
    return build_gaterun_job("pr-1", "verel", {"repo": "https://github.com/o/r", **(spec or {})}, **kw)


def test_pod_and_container_are_hardened():
    job = _job()
    pod = job["spec"]["template"]["spec"]
    # untrusted Job gets NO Kubernetes API credential
    assert pod["automountServiceAccountToken"] is False
    assert pod["restartPolicy"] == "Never"
    psc = pod["securityContext"]
    assert psc["runAsNonRoot"] is True and psc["runAsUser"] == 65532
    assert psc["seccompProfile"] == {"type": "RuntimeDefault"}
    for c in pod["containers"] + pod["initContainers"]:
        sc = c["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False
        assert sc["readOnlyRootFilesystem"] is True
        assert sc["capabilities"]["drop"] == ["ALL"]
        assert sc["runAsNonRoot"] is True


def test_job_is_bounded_and_non_retrying():
    job = _job({"timeoutSeconds": 120})["spec"]
    assert job["backoffLimit"] == 0                  # never retry untrusted execution
    assert job["activeDeadlineSeconds"] == 120       # hard wall-clock cap
    gate = job["template"]["spec"]["containers"][0]
    assert gate["resources"]["limits"]["memory"]     # resource-capped


def test_repo_is_required():
    with pytest.raises(ValueError, match="repo"):
        build_gaterun_job("x", "verel", {})


def test_ref_is_argv_not_shell():
    # a crafted ref must be a discrete git argv element, never concatenated into a shell string
    job = _job({"ref": "; rm -rf /"})
    clone = job["spec"]["template"]["spec"]["initContainers"][0]
    assert "; rm -rf /" in clone["args"]             # present as ONE argv element
    assert all("sh" not in a and "bash" not in a for a in clone["args"])  # no shell wrapper
    assert clone["args"][0] == "clone"


def test_runtimeclass_opt_in_for_stronger_isolation():
    assert "runtimeClassName" not in _job()["spec"]["template"]["spec"]          # not by default
    assert _job({"runtimeClassName": "gvisor"})["spec"]["template"]["spec"]["runtimeClassName"] == "gvisor"


def test_owner_reference_wires_gc():
    owner = {"apiVersion": "verel.dev/v1alpha1", "kind": "GateRun", "name": "pr-1", "uid": "abc",
             "controller": True}
    job = _job(owner=owner)
    assert job["metadata"]["ownerReferences"] == [owner]


def test_image_override_precedence():
    # spec.image wins over the operator default image arg
    assert _job({"image": "x:1"}, image="y:2")["spec"]["template"]["spec"]["containers"][0]["image"] == "x:1"
    assert _job(image="y:2")["spec"]["template"]["spec"]["containers"][0]["image"] == "y:2"
