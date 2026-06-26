"""Terraform actuator + gateway integration (IAC-KICKOFF.md Phase 4) — act-then-verify, plan-binding,
dynamic escalation, Capture-C IAM interception. Includes the security-cadence adversarial cases
(TOCTOU / plan substitution / fail-closed). All offline: runner + reader injected."""

import json

import pytest

from verel.actuators import (
    ActResult,
    TerraformActuator,
    escalate,
    escalation_override,
    iam_action_class,
    iam_tool_overrides,
    plan_digest,
)
from verel.gateway import ActionClass, Decision, Gateway, Policy
from verel.verdict import Verdict


# --- helpers -------------------------------------------------------------
def _plan_json(*changes):
    return {"resource_changes": list(changes)}


def _rc(address, rtype, actions, after=None):
    return {"address": address, "type": rtype,
            "change": {"actions": list(actions), "after": after or {}}}


class FakeTf:
    """Dispatch a terraform argv to canned (rc, stdout, stderr); records a mutable planfile blob."""

    def __init__(self, *, plan_rc=0, show_json="{}", show_rc=0, apply_rc=0, watch_rc=0, blob=b"PLAN-A"):
        self.plan_rc, self.show_json, self.show_rc = plan_rc, show_json, show_rc
        self.apply_rc, self.watch_rc, self.blob = apply_rc, watch_rc, blob
        self.applied = False
        self.destroyed = False

    def runner(self, cmd, cwd=None):
        if "apply" in cmd:
            self.applied = True
            return (self.apply_rc, "apply complete", "" if self.apply_rc == 0 else "boom")
        if "destroy" in cmd:
            self.destroyed = True
            return (0, "destroy complete", "")
        if "show" in cmd:
            return (self.show_rc, self.show_json, "")
        if "-detailed-exitcode" in cmd:  # watch re-plan
            return (self.watch_rc, "", "" if self.watch_rc != 1 else "err")
        if "plan" in cmd:  # plan -out
            return (self.plan_rc, "", "" if self.plan_rc == 0 else "plan boom")
        return (0, "", "")

    def read_bytes(self, path):
        return self.blob


def _actuator(tf, **kw):
    return TerraformActuator(".", runner=tf.runner, read_bytes=tf.read_bytes, **kw)


# --- pure escalation -----------------------------------------------------
def test_escalate_pure_create_is_consequential():
    cls, reasons = escalate(_plan_json(_rc("aws_s3_bucket.a", "aws_s3_bucket", ["create"])))
    assert cls == ActionClass.CONSEQUENTIAL and reasons == []


def test_escalate_destroy_is_irreversible():
    cls, reasons = escalate(_plan_json(_rc("aws_db_instance.p", "aws_db_instance", ["delete"])))
    assert cls == ActionClass.IRREVERSIBLE and "destroy/replace" in reasons[0]


def test_escalate_iam_widening_is_irreversible():
    cls, reasons = escalate(_plan_json(_rc("aws_iam_role.r", "aws_iam_role", ["create"])))
    assert cls == ActionClass.IRREVERSIBLE and "IAM widening" in reasons[0]


def test_escalation_override_shape():
    ov = escalation_override(_plan_json(_rc("aws_iam_policy.p", "aws_iam_policy", ["create"])))
    assert ov["terraform apply"] == ActionClass.IRREVERSIBLE
    assert ov["terraform destroy"] == ActionClass.IRREVERSIBLE


# --- Capture C (direct IAM tool calls) -----------------------------------
def test_iam_action_class():
    assert iam_action_class("attach_role_policy") == ActionClass.IRREVERSIBLE
    assert iam_action_class("add-iam-policy-binding") == ActionClass.IRREVERSIBLE
    assert iam_action_class("create_role_assignment") == ActionClass.IRREVERSIBLE
    assert iam_action_class("create_clusterrolebinding") == ActionClass.IRREVERSIBLE
    assert iam_action_class("get_object") is None
    assert iam_action_class("list_buckets") is None


def test_iam_tool_overrides_filters():
    ov = iam_tool_overrides(["get_object", "attach_user_policy", "describe_instances"])
    assert ov == {"attach_user_policy": ActionClass.IRREVERSIBLE}


# --- plan_digest ---------------------------------------------------------
def test_plan_digest_stable_and_sensitive():
    assert plan_digest(b"X") == plan_digest(b"X")
    assert plan_digest(b"X") != plan_digest(b"Y")


# --- actuator.plan -------------------------------------------------------
def test_plan_binds_digest_and_classifies():
    tf = FakeTf(show_json=json.dumps(_plan_json(_rc("aws_iam_role.r", "aws_iam_role", ["create"]))),
                blob=b"PLAN-A")
    res = _actuator(tf).plan()
    assert res.plan_digest == plan_digest(b"PLAN-A")
    assert res.action_class == ActionClass.IRREVERSIBLE
    assert res.report.grader.value == "iac"


def test_plan_failure_is_fail_closed():
    tf = FakeTf(plan_rc=1)
    res = _actuator(tf).plan()
    assert res.plan_digest == "" and res.report.errored
    assert res.action_class == ActionClass.IRREVERSIBLE  # unknown plan ⇒ most restrictive


def test_plan_show_failure_fails_closed_to_irreversible():
    # Red-team round 2: `plan` succeeds but `show -json` fails ⇒ we can't read what it does, so the
    # classification must NOT fall open to CONSEQUENTIAL.
    tf = FakeTf(show_rc=1, show_json="")
    res = _actuator(tf).plan()
    assert res.action_class == ActionClass.IRREVERSIBLE and res.report.errored


def test_plan_show_empty_json_fails_closed():
    # Red-team round 5 (audit): `show -json` exits 0 but emits unparseable/empty JSON ⇒ must still
    # fail closed to IRREVERSIBLE, not the less-restrictive CONSEQUENTIAL.
    tf = FakeTf(show_rc=0, show_json="not json")
    res = _actuator(tf).plan()
    assert res.action_class == ActionClass.IRREVERSIBLE and res.report.errored


def test_plan_detects_midplan_file_swap():
    # Red-team round 2 Finding 1: the planfile is swapped between the classify-read and the digest —
    # plan() re-digests before/after `show` and must refuse on a mismatch (fail closed IRREVERSIBLE).
    blobs = iter([b"PLAN-A", b"PLAN-B", b"PLAN-B"])  # before-show, after-show (swapped), ...

    tf = FakeTf(show_json=json.dumps(_plan_json(_rc("aws_s3_bucket.a", "aws_s3_bucket", ["create"]))))
    act = TerraformActuator(".", runner=tf.runner, read_bytes=lambda _p: next(blobs))
    res = act.plan()
    assert res.action_class == ActionClass.IRREVERSIBLE and res.report.errored
    assert res.plan_digest == ""


def test_act_does_not_raise_on_runner_timeout():
    # Red-team: a hung apply (TimeoutExpired) must become a clean refusal, not an uncaught exception.
    import subprocess

    def hanging(_cmd, _cwd=None):
        raise subprocess.TimeoutExpired(cmd=_cmd, timeout=1)

    act = TerraformActuator(".", runner=hanging, read_bytes=lambda _p: b"PLAN-A")
    res = act.act(approved_digest=plan_digest(b"PLAN-A"))
    assert res.applied is False and res.rc == 124


# --- actuator.act: plan-binding / TOCTOU (the security core) -------------
def test_act_applies_only_on_matching_digest():
    tf = FakeTf(blob=b"PLAN-A")
    act = _actuator(tf)
    res = act.act(approved_digest=plan_digest(b"PLAN-A"))
    assert res.applied is True and tf.applied is True


def test_act_refuses_on_digest_mismatch_toctou():
    # Adversary swaps the planfile AFTER approval: approved digest is for PLAN-A, file is now PLAN-B.
    tf = FakeTf(blob=b"PLAN-B")
    act = _actuator(tf)
    res = act.act(approved_digest=plan_digest(b"PLAN-A"))
    assert res.applied is False and tf.applied is False
    assert "mismatch" in res.reason


def test_act_refuses_with_empty_digest():
    tf = FakeTf(blob=b"PLAN-A")
    res = _actuator(tf).act(approved_digest="")
    assert res.applied is False and tf.applied is False


def test_act_refuses_when_planfile_missing():
    tf = FakeTf()

    def boom(_path):
        raise OSError("no such file")

    act = TerraformActuator(".", runner=tf.runner, read_bytes=boom)
    res = act.act(approved_digest="anything")
    assert res.applied is False and tf.applied is False and "refused" in res.reason


# --- actuator.destroy ----------------------------------------------------
def test_destroy_refused_without_approval():
    tf = FakeTf()
    assert _actuator(tf).destroy().applied is False and tf.destroyed is False
    assert _actuator(tf).destroy(approved=True).applied is True


# --- actuator.watch (act-then-verify) ------------------------------------
def test_watch_converged_drift_error():
    assert _actuator(FakeTf(watch_rc=0)).watch().verdict == Verdict.PASS
    assert _actuator(FakeTf(watch_rc=2)).watch().verdict == Verdict.FAIL
    assert _actuator(FakeTf(watch_rc=1)).watch().errored is True


# --- argv / option-injection hardening -----------------------------------
def test_unsafe_binary_and_planfile_rejected():
    with pytest.raises(ValueError):
        TerraformActuator(".", binary="-rf")
    with pytest.raises(ValueError):
        TerraformActuator(".", planfile="-out=/etc/x")
    with pytest.raises(ValueError):
        TerraformActuator(".", planfile="; rm -rf /")


# --- gateway integration: dynamic escalation end-to-end ------------------
def _gateway_for(plan_res, tf, *, approve=None):
    """Wire a Gateway whose apply invokes the actuator with the BOUND digest, classified from the plan."""
    policy = Policy(overrides=escalation_override(plan_res.plan_json))

    def invoke(_tool, _args):
        return tf_actuator.act(plan_res.plan_digest)

    def gate(_tool, _args):
        return {"verdict": plan_res.report.verdict.value}

    tf_actuator = _actuator(tf)
    return Gateway(invoke, policy=policy, gate=gate, approve=approve)


def test_gateway_irreversible_plan_dry_runs_without_approval():
    tf = FakeTf(show_json=json.dumps(_plan_json(_rc("aws_iam_role.r", "aws_iam_role", ["create"]))))
    plan_res = _actuator(tf).plan()
    gw = _gateway_for(plan_res, tf, approve=None)  # no human approval channel
    res = gw.handle("terraform apply", {})
    assert res.decision == Decision.DRY_RUN and tf.applied is False


def test_gateway_irreversible_plan_applies_with_approval():
    tf = FakeTf(show_json=json.dumps(_plan_json(_rc("aws_iam_role.r", "aws_iam_role", ["create"]))))
    plan_res = _actuator(tf).plan()
    gw = _gateway_for(plan_res, tf, approve=lambda _t, _a: True)
    res = gw.handle("terraform apply", {})
    assert res.decision == Decision.FORWARD
    assert isinstance(res.result, ActResult) and res.result.applied is True


def test_gateway_consequential_plan_forwards_on_pass():
    tf = FakeTf(show_json=json.dumps(_plan_json(_rc("aws_s3_bucket.a", "aws_s3_bucket", ["create"]))))
    plan_res = _actuator(tf).plan()
    assert plan_res.action_class == ActionClass.CONSEQUENTIAL
    gw = _gateway_for(plan_res, tf)  # CONSEQUENTIAL → gated by verdict, no human approval needed
    res = gw.handle("terraform apply", {})
    assert res.decision == Decision.FORWARD and res.result.applied is True
