"""The GateRun Job builder runs UNTRUSTED repo code in-cluster — pin every isolation control."""

import pytest

pytest.importorskip("kopf", reason="operator tests need verel[operator]")

from verel.operator import build_gaterun_job, build_gaterun_netpol


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


def test_disk_is_bounded_no_node_exhaustion():
    # readOnlyRootFilesystem forces untrusted writes into the emptyDirs — they MUST be size-capped, and
    # the gate container MUST have an ephemeral-storage limit, or a repo can `dd` the node disk full.
    pod = _job()["spec"]["template"]["spec"]
    vols = {v["name"]: v for v in pod["volumes"]}
    assert vols["workspace"]["emptyDir"]["sizeLimit"] == "1Gi"
    assert vols["tmp"]["emptyDir"]["sizeLimit"] == "256Mi"
    for c in pod["containers"] + pod["initContainers"]:
        assert c["resources"]["limits"]["ephemeral-storage"]
        assert c["resources"]["requests"]["ephemeral-storage"]


def test_repo_must_be_validated_https():
    with pytest.raises(ValueError, match="repo"):
        build_gaterun_job("x", "verel", {})
    for bad in ["ext::sh -c id", "file:///etc/passwd", "ssh://x/y", "-oProxyCommand=id",
                "git://x/y", "https:// x"]:
        with pytest.raises(ValueError, match="repo"):
            build_gaterun_job("x", "verel", {"repo": bad})


def test_ref_rejects_option_injection_and_whitespace():
    for bad in ["--upload-pack=touch x", "-x", "a b", "a\nb"]:
        with pytest.raises(ValueError, match="ref"):
            _job({"ref": bad})
    # a clean ref is a discrete argv element after a `--` separator; ext/file transports disabled
    clone = _job({"ref": "refs/pull/9/head"})["spec"]["template"]["spec"]["initContainers"][0]["args"]
    assert "protocol.ext.allow=never" in clone and "protocol.file.allow=never" in clone
    assert "--" in clone and clone[clone.index("--") + 1] == "https://github.com/o/r"
    assert "refs/pull/9/head" in clone


def test_image_is_operator_controlled_not_from_spec():
    # confused-deputy defense: spec.image is IGNORED — the operator's trusted image always runs.
    c = _job({"image": "attacker/evil:latest"}, image="ghcr.io/amitpatole/verel:1")
    assert c["spec"]["template"]["spec"]["containers"][0]["image"] == "ghcr.io/amitpatole/verel:1"


def test_resources_are_fixed_not_author_controlled():
    c = _job({"resources": {"limits": {"memory": "999Gi"}}})["spec"]["template"]["spec"]["containers"][0]
    assert c["resources"]["limits"]["memory"] == "2Gi"   # operator ceiling, author value ignored


def test_images_are_pinned_never_latest():
    # config scanners (kube-linter/kube-score/polaris) reject :latest — pins must be version/digest.
    job = _job()["spec"]["template"]["spec"]
    gate = job["containers"][0]["image"]
    clone = job["initContainers"][0]["image"]
    assert gate.startswith("ghcr.io/amitpatole/verel:") and not gate.endswith(":latest")
    assert "@sha256:" in clone and ":latest" not in clone   # git clone image digest-pinned


def test_runtimeclass_opt_in_for_stronger_isolation():
    assert "runtimeClassName" not in _job()["spec"]["template"]["spec"]
    assert _job({"runtimeClassName": "gvisor"})["spec"]["template"]["spec"]["runtimeClassName"] == "gvisor"


def test_owner_reference_wires_gc_without_blockownerdeletion():
    owner = {"apiVersion": "verel.dev/v1alpha1", "kind": "GateRun", "name": "pr-1", "uid": "abc",
             "controller": True}
    job = _job(owner=owner)
    assert job["metadata"]["ownerReferences"] == [owner]


def test_netpol_fences_untrusted_egress():
    np = build_gaterun_netpol("pr-1", "verel")
    spec = np["spec"]
    assert np["kind"] == "NetworkPolicy"
    assert spec["podSelector"]["matchLabels"] == {"verel.dev/gaterun": "pr-1"}   # matches the Job pod
    assert spec["policyTypes"] == ["Egress"]
    # the 443 egress rule blocks cloud metadata + all private ranges (cluster API/pods/metadata),
    # including RFC6598 CGNAT (100.64/10) used for ClusterIP/Pod CIDRs on GKE/EKS
    https = next(r for r in spec["egress"] if any(p["port"] == 443 for p in r.get("ports", [])))
    blocked = https["to"][0]["ipBlock"]["except"]
    for cidr in ("169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
        assert cidr in blocked
