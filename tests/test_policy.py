"""Gated rollout: per-grader modes, evidence-gated promotion, demotion, auto-demotion, kill switch."""

from __future__ import annotations

import json

import pytest

from verel.cli import main
from verel.pilot import Label, ShadowLog, evaluate, run_pilot
from verel.pilot.mode import Mode
from verel.pilot.policy import (
    Policy,
    PolicyError,
    PolicyStore,
    autodemote,
    enforced_verdict,
    health,
)
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rep(bad, grader=GraderKind.DSP, errored=False):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss, grader=grader,
                         errored=errored))


def populate(tmp_path, n=200, dsp_ok=True):
    """n artifacts, half defective. DSP flags defects precisely; AUDIO_LLM (advisory kind) is noisy."""
    log = ShadowLog(tmp_path / "pilot.jsonl")
    labels = []
    for i in range(n):
        defect = i % 2 == 0
        labels.append(Label(artifact_id=f"a{i}", defect=defect))
        dsp_bad = defect if dsp_ok else (not defect)
        run_pilot([rep(dsp_bad), rep(i % 3 == 0, GraderKind.AUDIO_LLM)], artifact_id=f"a{i}", log=log)
    return log, labels


# ---- applying a policy -----------------------------------------------------------------------------
def test_policy_modes_decide_what_blocks():
    pol = Policy(graders={"dsp": Mode.ENFORCE, "audio_llm": Mode.ADVISORY})
    assert enforced_verdict([rep(True), rep(False, GraderKind.AUDIO_LLM)], pol) is Verdict.FAIL        # dsp enforces
    assert enforced_verdict([rep(False), rep(True, GraderKind.AUDIO_LLM)], pol) is Verdict.WARN        # advisory: WARN at most
    assert enforced_verdict([rep(False), rep(False, GraderKind.AUDIO_LLM)], pol) is Verdict.PASS
    shadow_only = Policy(graders={"dsp": Mode.SHADOW})
    assert enforced_verdict([rep(True)], shadow_only) is Verdict.PASS                                    # shadow never counts
    assert enforced_verdict([rep(True)], Policy()) is Verdict.PASS                                       # default shadow


def test_run_pilot_with_policy_records_would_be_but_enforces_only_promoted(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    pol = Policy(graders={"dsp": Mode.ENFORCE})
    d = run_pilot([rep(True), rep(True, GraderKind.AUDIO_LLM)], artifact_id="a", log=log, policy=pol)
    assert d.mode is Mode.POLICY and d.blocked and d.would_be is Verdict.FAIL
    d2 = run_pilot([rep(False), rep(True, GraderKind.AUDIO_LLM)], artifact_id="b", log=log, policy=pol)
    assert not d2.blocked and d2.enforced is Verdict.PASS and d2.would_be in (Verdict.WARN, Verdict.FAIL, Verdict.PASS)


def test_policy_mode_without_policy_is_refused():
    with pytest.raises(ValueError):
        run_pilot([rep(False)], artifact_id="a", mode="policy")


def test_kill_switch_forces_shadow(monkeypatch):
    pol = Policy(graders={"dsp": Mode.ENFORCE})
    monkeypatch.setenv("VEREL_PILOT_KILL_SWITCH", "1")
    d = run_pilot([rep(True)], artifact_id="a", policy=pol)
    assert not d.blocked and "kill switch" in d.reason
    d = run_pilot([rep(True)], artifact_id="b", mode="enforce")
    assert not d.blocked
    monkeypatch.delenv("VEREL_PILOT_KILL_SWITCH")
    assert run_pilot([rep(True)], artifact_id="c", policy=pol).blocked


def test_gate_crash_with_policy_blocks_only_if_something_enforces(monkeypatch):
    import verel.pilot.shadow as sh
    monkeypatch.setattr(sh, "gate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("verel.pilot.policy.gate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    d = run_pilot([rep(False)], artifact_id="a", policy=Policy(graders={"dsp": Mode.ENFORCE}))
    assert d.gate_error and d.blocked
    d = run_pilot([rep(False)], artifact_id="b", policy=Policy())
    assert d.gate_error and not d.blocked


# ---- promotion rules -------------------------------------------------------------------------------
def test_promotion_requires_evidence_and_the_advisory_step(tmp_path):
    log, labels = populate(tmp_path)
    ev = evaluate(log.records(), labels)
    store = PolicyStore(tmp_path / "policy.jsonl")
    with pytest.raises(PolicyError, match="advisory first"):
        store.promote("dsp", "enforce", "amit", ev)                           # skipping the advisory stage
    store.promote("dsp", "advisory", "amit", ev)
    rec = store.promote("dsp", "enforce", "amit", ev)                          # earned: precise + good recall
    assert rec.mode == "enforce" and not rec.overridden and rec.evidence["ready_to_enforce"] is True
    assert store.current().mode_for("dsp") is Mode.ENFORCE


def test_a_noisy_grader_cannot_be_promoted_without_an_explicit_override(tmp_path):
    log, labels = populate(tmp_path)
    ev = evaluate(log.records(), labels)
    store = PolicyStore(tmp_path / "policy.jsonl")
    store.promote("audio_llm", "advisory", "amit", ev)
    with pytest.raises(PolicyError, match="has not earned"):
        store.promote("audio_llm", "enforce", "amit", ev)
    with pytest.raises(PolicyError):
        store.promote("audio_llm", "enforce", "amit", ev, override_reason="too short")
    rec = store.promote("audio_llm", "enforce", "amit", ev, override_reason="regulator requires this check now")
    assert rec.overridden and store.current().mode_for("audio_llm") is Mode.ENFORCE
    assert "OVERRIDE" in json.dumps(rec.model_dump()) or rec.overridden


def test_promotion_without_any_evidence_is_refused(tmp_path):
    store = PolicyStore(tmp_path / "policy.jsonl")
    store.promote("dsp", "advisory", "a")
    with pytest.raises(PolicyError):
        store.promote("dsp", "enforce", "a", None)


@pytest.mark.parametrize("bad", [("nope", "advisory"), ("*", "advisory"), ("dsp", "yolo"), ("dsp", "shadow")])
def test_bad_promotions(tmp_path, bad):
    store = PolicyStore(tmp_path / "policy.jsonl")
    with pytest.raises((PolicyError, ValueError)):
        store.promote(bad[0], bad[1], "a")


def test_default_mode_cannot_be_enforce_and_demotion_needs_a_reason(tmp_path):
    store = PolicyStore(tmp_path / "policy.jsonl")
    with pytest.raises(PolicyError):
        store.set_default("enforce", "a")
    store.set_default("advisory", "a", "start soft")
    assert store.current().mode_for("anything") is Mode.ADVISORY
    with pytest.raises(PolicyError):
        store.demote("dsp", "advisory", "a", "  ")
    with pytest.raises(PolicyError):
        store.demote("dsp", "enforce", "a", "x")


def test_policy_history_is_tamper_evident(tmp_path):
    from verel._chainlog import LogCorrupt
    store = PolicyStore(tmp_path / "policy.jsonl")
    store.promote("dsp", "advisory", "a")
    store.demote("dsp", "shadow", "a", "back off")
    p = tmp_path / "policy.jsonl"
    p.write_text(p.read_text().replace('"mode":"shadow"', '"mode":"enforce"'))
    with pytest.raises(LogCorrupt):
        store.current()                                  # a forged "enforce" cannot slip in via the file


# ---- regression watch ------------------------------------------------------------------------------
def test_autodemote_on_precision_regression(tmp_path):
    log, labels = populate(tmp_path, n=200)
    ev = evaluate(log.records(), labels)
    store = PolicyStore(tmp_path / "policy.jsonl")
    store.promote("dsp", "advisory", "a", ev)
    store.promote("dsp", "enforce", "a", ev)
    assert all(h.healthy for h in health(log.records(), labels, store.current()))
    # the grader then starts firing on clean artifacts (a bad config push, a model drift...)
    more = []
    for i in range(200, 280):
        more.append(Label(artifact_id=f"a{i}", defect=False))
        run_pilot([rep(True)], artifact_id=f"a{i}", log=log)
    demoted = autodemote(store, log.records(), labels + more, window=80)
    assert [h.grader for h in demoted] == ["dsp"]
    assert store.current().mode_for("dsp") is Mode.ADVISORY
    last = store.records()[-1]
    assert last.by == "auto" and last.action == "autodemote"
    with pytest.raises(PolicyError):
        store.promote("dsp", "enforce", "a", evaluate(log.records(), labels + more))   # no quiet re-promotion


def test_autodemote_on_outages(tmp_path):
    store = PolicyStore(tmp_path / "policy.jsonl")
    store.promote("dsp", "advisory", "a")
    store.promote("dsp", "enforce", "a", None, override_reason="bootstrapping the pilot with sign-off")
    log = ShadowLog(tmp_path / "l.jsonl")
    labels = []
    for i in range(40):
        labels.append(Label(artifact_id=f"x{i}", defect=False))
        run_pilot([rep(False, errored=(i % 2 == 0))], artifact_id=f"x{i}", log=log)
    assert [h.grader for h in autodemote(store, log.records(), labels)] == ["dsp"]


# ---- CLI ---------------------------------------------------------------------------------------------
def test_cli_rollout(tmp_path, capsys):
    log, labels = populate(tmp_path)
    lf = tmp_path / "labels.json"
    lf.write_text(json.dumps([lab.model_dump() for lab in labels]))
    pol, lg = str(tmp_path / "policy.jsonl"), str(tmp_path / "pilot.jsonl")
    base = ["--policy", pol]
    assert main(["pilot", "promote", *base, "--log", lg, "--labels", str(lf), "--grader", "dsp", "--to",
                 "enforce", "--by", "amit"]) == 1                                      # must go via advisory first
    assert main(["pilot", "promote", *base, "--log", lg, "--labels", str(lf), "--grader", "dsp", "--to",
                 "advisory", "--by", "amit"]) == 0
    assert main(["pilot", "promote", *base, "--log", lg, "--labels", str(lf), "--grader", "dsp", "--to",
                 "enforce", "--by", "amit"]) == 0
    assert main(["pilot", "policy", *base]) == 0
    assert "dsp" in capsys.readouterr().out
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps([rep(True).model_dump(mode="json")]))
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "n1", "--log", lg, "--policy", pol]) == 1
    assert main(["pilot", "health", *base, "--log", lg, "--labels", str(lf)]) == 0
    assert main(["pilot", "demote", *base, "--grader", "dsp", "--reason", "rollback drill", "--by", "amit"]) == 0
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "n2", "--log", lg, "--policy", pol]) == 0
    assert main(["pilot", "demote", *base, "--grader", "dsp", "--reason", "", "--by", "amit"]) == 1


# ---- over HTTP ---------------------------------------------------------------------------------------
def test_service_rollout_flow(tmp_path):
    import urllib.error
    import urllib.request

    from verel.auth import Authenticator, TokenStore, add_token
    from verel.pilot.service import PilotServer
    tf = tmp_path / "t.json"
    op = add_token(tf, id="op", role="operator", tenant="acme")
    op2 = add_token(tf, id="op2", role="operator", tenant="acme")
    op3 = add_token(tf, id="op3", role="operator", tenant="acme")
    adm = add_token(tf, id="adm", role="admin", tenant="acme")
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()

    def call(method, path, tok, body=None):
        req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers={"Authorization": f"Bearer {tok}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    try:
        for i in range(200):
            defect = i % 2 == 0
            call("POST", "/v1/pilot/record", op, {"artifact_id": f"a{i}", "reports": [rep(defect).model_dump(mode="json")]})
        call("POST", "/v1/pilot/labels", op2, {"labels": [{"artifact_id": f"a{i}", "defect": i % 2 == 0} for i in range(100)]})
        # one reviewer is not enough evidence for ENFORCE: a second reviewer must label too
        assert call("POST", "/v1/pilot/promote", adm, {"grader": "dsp", "to": "advisory"})[0] == 200
        st, why = call("POST", "/v1/pilot/promote", adm, {"grader": "dsp", "to": "enforce"})
        assert st == 409 and "reviewer" in why["error"] or "earned" in why["error"]
        call("POST", "/v1/pilot/labels", op3, {"labels": [{"artifact_id": f"a{i}", "defect": i % 2 == 0} for i in range(100, 200)]})
        assert call("POST", "/v1/pilot/promote", op, {"grader": "dsp", "to": "advisory"})[0] == 403        # operators can't
        st, rec = call("POST", "/v1/pilot/promote", adm, {"grader": "dsp", "to": "enforce"})
        assert st == 200 and rec["evidence"]["ready_to_enforce"] is True and rec["by"] == "adm"
        # the tenant now has a policy: the request cannot pick a mode, and dsp blocks
        assert call("POST", "/v1/pilot/record", op, {"artifact_id": "p1", "mode": "shadow",
                                                     "reports": [rep(True).model_dump(mode="json")]})[0] == 400
        st, d = call("POST", "/v1/pilot/record", op, {"artifact_id": "p1", "reports": [rep(True).model_dump(mode="json")]})
        assert st == 200 and d["mode"] == "policy" and d["enforced"] == "fail"
        st, p = call("GET", "/v1/pilot/policy", op)
        assert p["graders"] == {"dsp": "enforce"} and len(p["history"]) == 2
        assert call("POST", "/v1/pilot/demote", adm, {"grader": "dsp", "reason": "drill"})[0] == 200
        assert call("POST", "/v1/pilot/record", op, {"artifact_id": "p2", "reports": [rep(True).model_dump(mode="json")]})[1]["enforced"] == "warn"   # demoted to advisory: surfaces, never blocks
    finally:
        srv.stop()


# ---- hot folder + jobs honour the policy ---------------------------------------------------------------
def test_hotfolder_policy_mode(tmp_path):
    import os
    import time

    from verel.connectors.hotfolder import HotFolder, scan_once
    from verel.pilot.tenancy import policy_store
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    hf = HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", mode="policy", settle_s=0)
    with pytest.raises(ValueError):
        scan_once(hf) if (root / "incoming" / "x").write_bytes(b"x") or True else None   # no policy yet: refuse
    (root / "incoming" / "x").unlink()
    store = policy_store(tmp_path / "data", "acme")
    store.promote("media", "advisory", "a")
    store.promote("media", "enforce", "a", None, override_reason="pilot sign-off by the QC lead")
    p = root / "incoming" / "bad.mxf"
    p.write_bytes(b"x")
    import hashlib
    facts = {"audio": {"integrated_lufs": -5, "true_peak_dbtp": 3}, "asset": {"sha256": hashlib.sha256(b"x").hexdigest()}}
    (root / "incoming" / "bad.mxf.facts.json").write_text(json.dumps(facts))
    os.utime(p, (time.time() - 100,) * 2)
    out = scan_once(hf)
    assert out[0].enforced == "fail" and (root / "quarantine/bad.mxf").exists()
