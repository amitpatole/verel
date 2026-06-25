"""Verdict-forgery guard for the GateRun status mirror.

A GateRun's verdict IS the security signal ("nothing is done until a grader returns a verdict"), so a
forged `pass` is the crown-jewel attack. The mirror must trust ONLY the Job the operator created,
identified by its server-assigned uid (recorded in GateRun.status.jobUID) — never the author-settable
label / ownerReference. These pin that logic without a cluster (the handler glue itself needs one)."""

import pytest

pytest.importorskip("kopf", reason="operator tests need verel[operator]")

from verel.operator.handlers import _job_authenticated, _trusted_git_image


def test_git_image_overridable_via_env(monkeypatch):
    # default is the pinned Chainguard digest; operators can point at their own mirror (R6 L-1)
    monkeypatch.delenv("VEREL_GATERUN_GIT_IMAGE", raising=False)
    assert "@sha256:" in _trusted_git_image()
    monkeypatch.setenv("VEREL_GATERUN_GIT_IMAGE", "ghcr.io/me/git@sha256:" + "a" * 64)
    assert _trusted_git_image() == "ghcr.io/me/git@sha256:" + "a" * 64


def test_authentic_job_uid_matches_recorded_jobuid():
    # the operator recorded the real Job's uid; the firing Job carries that same (server-assigned) uid
    assert _job_authenticated({"uid": "real-123"}, {"jobUID": "real-123"}) is True


def test_forged_job_with_wrong_uid_is_rejected():
    # an attacker's exit-0 Job: any label/ownerReference, but a DIFFERENT (its own) server-assigned uid
    forged = {"uid": "attacker-999", "labels": {"verel.dev/gaterun": "victim"},
              "ownerReferences": [{"kind": "GateRun", "name": "victim", "uid": "real-123",
                                   "controller": True}]}
    assert _job_authenticated(forged, {"jobUID": "real-123"}) is False


def test_no_recorded_jobuid_fails_closed():
    # GateRun has no jobUID yet (e.g. create was refused / never ran) → never mirror a verdict
    assert _job_authenticated({"uid": "anything"}, {}) is False
    assert _job_authenticated({"uid": "anything"}, {"jobUID": ""}) is False
    assert _job_authenticated({"uid": "anything"}, None) is False


def test_missing_job_uid_fails_closed():
    # a Job event with no uid in meta can't match a recorded uid
    assert _job_authenticated({}, {"jobUID": "real-123"}) is False
