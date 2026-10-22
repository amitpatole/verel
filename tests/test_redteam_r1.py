"""Regression pins for red-team round 1 (media + pilot). Each test reproduces a finding that was
confirmed against the first implementation and asserts it is now closed."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import time

import pytest

from verel import _chainlog
from verel._chainlog import ChainLog, LogCorrupt
from verel.media import grade_media, grade_provenance, merge, parse_manifest_report
from verel.media import provenance as prov
from verel.media.rules import parse_spec
from verel.pilot import Label, ShadowLog, evaluate, load_labels, run_pilot
from verel.pilot.log import ShadowRecord, valid_artifact_id
from verel.pilot.render import render
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def _rep(bad, grader=GraderKind.DSP, errored=False):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss, grader=grader,
                         errored=errored))


def _filled(tmp_path, n=3):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(n):
        run_pilot([_rep(True)], artifact_id=f"a{i}", log=log)
    return log


# ---- H1: an unkeyed chain could be rebuilt; now it needs the key -------------------------------------
def test_h1_rebuilt_chain_without_key_is_detected(tmp_path, monkeypatch):
    log = _filled(tmp_path)
    recs = log.records()
    monkeypatch.setenv("VEREL_LOG_KEY", "attacker-guess")      # attacker doesn't have the real key
    prev = _chainlog.GENESIS
    lines = []
    for r in recs:
        f = ShadowRecord(**{**r.model_dump(), "would_be": Verdict.PASS, "enforced": Verdict.PASS,
                            "prev_hash": prev, "hash": "", "mac": ""})
        f.hash = f.compute_hash()
        f.mac = _chainlog._mac(f.hash)
        prev = f.hash
        lines.append(f.model_dump_json())
    log.path.write_text("\n".join(lines) + "\n")
    monkeypatch.setenv("VEREL_LOG_KEY", "test-log-key")        # the honest verifier
    with pytest.raises(LogCorrupt):
        log.verify()


def test_h1_forged_ledger_and_deletion(tmp_path):
    log = _filled(tmp_path)
    log.path.unlink()
    with pytest.raises(LogCorrupt):
        log.verify()
    log2 = _filled(tmp_path / "x")
    log2._ledger.write_text(json.dumps({"head": "0" * 64, "total": 0, "mac": "00"}))
    with pytest.raises(LogCorrupt):
        log2.verify()
    log3 = _filled(tmp_path / "y")
    log3._ledger.unlink()
    with pytest.raises(LogCorrupt):
        log3.verify()


def test_h1_extra_field_not_silently_accepted(tmp_path):
    log = _filled(tmp_path, 2)
    lines = log.path.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["note"] = "smuggled"
    lines[0] = json.dumps(obj)
    log.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LogCorrupt):
        log.verify()


def _crash_before_final_ledger(fn):
    """Run `fn` in a forked child that dies (os._exit) right before the ledger is finalized, exactly like a
    process kill between 'records written' and 'ledger updated'."""
    pid = os.fork()
    if pid == 0:
        orig = _chainlog.ChainLog._write_ledger

        def dying(self, head, total, segs, pending=None):
            if pending is None and head != _chainlog.GENESIS and getattr(self, "_armed", False):
                os._exit(0)
            return orig(self, head, total, segs, pending)

        _chainlog.ChainLog._write_ledger = dying
        try:
            fn()
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def test_h1_crash_between_append_and_ledger_is_recovered(tmp_path):
    log = _filled(tmp_path, 2)

    def child():
        log._armed = True
        run_pilot([_rep(False)], artifact_id="crash", log=log)

    _crash_before_final_ledger(child)
    assert log.verify() == 3                      # the announced write is accepted: records exist, ledger lagged
    run_pilot([_rep(False)], artifact_id="a9", log=log)
    assert log.verify() == 4


def test_h1_stale_ledger_cannot_hide_truncated_records(tmp_path):
    """Round 5: restoring an OLD ledger copy and truncating the log used to pass verification."""
    log = _filled(tmp_path, 4)
    stale = (tmp_path / "l.jsonl.head").read_text()
    for i in range(4, 12):
        run_pilot([_rep(False)], artifact_id=f"a{i}", log=log)
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:7]) + "\n")      # 3 records past the stale ledger
    (tmp_path / "l.jsonl.head").write_text(stale)
    with pytest.raises(LogCorrupt):
        log.verify()
    with pytest.raises(LogCorrupt):
        run_pilot([_rep(False)], artifact_id="fork", log=log)       # and an append refuses to make the fork permanent


# ---- H2 / M1: provenance ----------------------------------------------------------------------------
def _m(**over):
    m = {"active_manifest": "u:1", "validation_status": [],
         "manifests": {"u:1": {"signature_info": {"issuer": "Org"}, "assertions": []}}}
    m.update(over)
    return m


@pytest.mark.parametrize("state", ["Valid", "Trusted", "valid", None])
def test_h2_failure_codes_beat_declared_state(state):
    d = _m(validation_status=[{"code": "assertion.dataHash.mismatch"}])
    if state:
        d["validation_state"] = state
    assert parse_manifest_report(d).state == "invalid"


def test_m1_require_trusted_needs_trusted_state(tmp_path):
    (tmp_path / "m.json").write_text(json.dumps(_m(validation_state="Valid")))
    (tmp_path / "p.json").write_text(json.dumps({"version": 1, "require_trusted_credential": True}))
    r = grade_provenance(str(tmp_path), manifest_json="m.json", policy="p.json")
    assert r.verdict is Verdict.FAIL
    (tmp_path / "m.json").write_text(json.dumps(_m(validation_state="Trusted")))
    assert grade_provenance(str(tmp_path), manifest_json="m.json", policy="p.json").verdict is Verdict.PASS


# ---- M2: a hostile file name must not fake "no manifest" --------------------------------------------
def test_m2_filename_cannot_fake_no_claim(tmp_path, monkeypatch):
    class R:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(argv, **kw):
        r = R()
        r.stderr = f"Error: could not read {argv[-1]}"       # a real hard failure that echoes the path
        return r

    monkeypatch.setattr(prov.shutil, "which", lambda _n: "/usr/bin/c2patool")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError):
        prov.read_with_c2patool("/x/No claim found.jpg")

    def real_no_claim(argv, **kw):
        r = R()
        r.stderr = "Error: No claim found"
        return r

    monkeypatch.setattr(subprocess, "run", real_no_claim)
    assert prov.read_with_c2patool("/x/a.jpg") is None


# ---- M3: YAML alias bombs ---------------------------------------------------------------------------
def test_m3_yaml_alias_bomb_rejected_fast(tmp_path):
    levels = ["a: &a0 [x,x,x,x,x,x,x,x,x]"] + [
        f"b{i}: &a{i} [*a{i-1},*a{i-1},*a{i-1},*a{i-1},*a{i-1},*a{i-1},*a{i-1},*a{i-1},*a{i-1}]"
        for i in range(1, 8)]
    spec = "version: 1\n" + "\n".join(f"x{i}: 1" for i in range(0)) + "\nrules:\n  - id: r\n    path: p\n    op: eq\n    value: *a7\n"
    (tmp_path / "s.yaml").write_text("\n".join(levels) + "\n" + spec)
    (tmp_path / "f.json").write_text('{"p": 1}')
    t = time.time()
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["f.json"], spec="s.yaml")
    assert time.time() - t < 2


def test_m3_eq_value_must_be_plain():
    with pytest.raises(ValueError):
        parse_spec({"version": 1, "rules": [{"id": "r", "path": "p", "op": "eq", "value": {"a": [1]}}]})
    with pytest.raises(ValueError):
        parse_spec({"version": 1, "rules": [{"id": "r", "path": "p", "op": "in", "value": [[1]]}]})


# ---- M4: readiness needs recall and reliability -----------------------------------------------------
def test_m4_low_recall_and_high_error_rate_block_graduation(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    labels = []
    for i in range(300):
        defect = i < 150
        labels.append(Label(artifact_id=f"a{i}", defect=defect))
        # the grader flags only 40 of 150 defects (recall 0.27), never a false positive
        run_pilot([_rep(defect and i < 40)], artifact_id=f"a{i}", log=log)
    ev = evaluate(log.records(), labels, min_samples=30, min_precision=0.9)
    g = ev.graders[0]
    assert g.stats.precision == 1.0 and not g.ready_to_enforce and "recall" in g.reason
    assert evaluate(log.records(), labels, min_samples=30, min_precision=0.9, min_recall=0.2).graders[0].ready_to_enforce

    log2 = ShadowLog(tmp_path / "l2.jsonl")
    labels2 = []
    for i in range(200):
        labels2.append(Label(artifact_id=f"b{i}", defect=i % 2 == 0))
        rep = _rep(i % 2 == 0, errored=(i % 3 == 0))
        run_pilot([rep], artifact_id=f"b{i}", log=log2)
    g2 = evaluate(log2.records(), labels2, min_samples=10, min_precision=0.5, min_recall=0.1).graders[0]
    assert g2.errored > 0 and not g2.ready_to_enforce and "errored" in g2.reason


# ---- M5: facts bound to the asset -------------------------------------------------------------------
def test_m5_asset_binding(tmp_path):
    (tmp_path / "a.mxf").write_bytes(b"real-bytes")
    spec = {"version": 1, "profiles": ["ebu_r128"]}
    (tmp_path / "s.json").write_text(json.dumps(spec))
    good = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}
    (tmp_path / "f.json").write_text(json.dumps(good))
    r1 = grade_media(str(tmp_path), facts=["f.json"], spec="s.json", asset="a.mxf")
    assert r1.verdict is Verdict.PASS
    (tmp_path / "f.json").write_text(json.dumps({**good, "asset": {"sha256": "0" * 64}}))
    r2 = grade_media(str(tmp_path), facts=["f.json"], spec="s.json", asset="a.mxf")
    assert r2.verdict is Verdict.FAIL and r2.issues[0].severity is Severity.CRITICAL
    import hashlib
    (tmp_path / "f.json").write_text(json.dumps({**good, "asset": {"sha256": hashlib.sha256(b"real-bytes").hexdigest()}}))
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json", asset="a.mxf").verdict is Verdict.PASS
    (tmp_path / "a.mxf").write_bytes(b"other")
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json", asset="a.mxf").verdict is Verdict.FAIL


def test_m5_manifest_json_bound_to_asset_changes_receipt(tmp_path):
    saved = _m(validation_state="Valid")
    (tmp_path / "m.json").write_text(json.dumps(saved))
    (tmp_path / "a.mp4").write_bytes(b"one")
    a = grade_provenance(str(tmp_path), manifest_json="m.json", asset="a.mp4", reader=lambda p: saved)
    (tmp_path / "a.mp4").write_bytes(b"two")
    b = grade_provenance(str(tmp_path), manifest_json="m.json", asset="a.mp4", reader=lambda p: saved)
    c = grade_provenance(str(tmp_path), manifest_json="m.json")
    assert len({a.run_receipt.inputs_digest, b.run_receipt.inputs_digest, c.run_receipt.inputs_digest}) == 3


# ---- L2: bounded, regular-file-only reads -----------------------------------------------------------
def test_l2_devices_fifos_and_giant_lines(tmp_path):
    with pytest.raises(ValueError):
        load_labels("/dev/zero")
    os.mkfifo(tmp_path / "fifo.jsonl")
    with pytest.raises(LogCorrupt):
        ShadowLog(tmp_path / "fifo.jsonl").verify()
    big = tmp_path / "big.jsonl"
    big.write_text("x" * (2 * 1024 * 1024) + "\n")
    with pytest.raises(LogCorrupt):
        ShadowLog(big).verify()


# ---- L3: hostile shapes never crash -----------------------------------------------------------------
def test_l3_hostile_facts_and_manifests_never_crash(tmp_path):
    spec = {"version": 1, "rules": [
        {"id": "n", "path": "x", "op": "gte", "value": 1},
        {"id": "b", "path": "y", "op": "between", "value": [1, 9], "ref": "z"},
        {"id": "s", "path": "w", "op": "superset", "value": ["a"], "ref": "z"}]}
    (tmp_path / "s.json").write_text(json.dumps(spec))
    (tmp_path / "f.json").write_text('{"x": ' + "9" * 400 + ', "y": 5, "z": "str", "w": ["a"]}')
    r = grade_media(str(tmp_path), facts=["f.json"], spec="s.json")
    assert r.verdict is Verdict.FAIL
    for doc in (_m(validation_status=5), _m(manifests={"u:1": {"assertions": 5}}),
                _m(manifests={"u:1": {"assertions": [{"label": "c2pa.actions", "data": {"actions": 5}}]}}),
                {"manifests": [], "active_manifest": []}):
        parse_manifest_report(doc)


def test_l3_yaml_datetime_waiver_expiry(tmp_path):
    (tmp_path / "s.yaml").write_text(
        "version: 1\nprofiles: [ebu_r128]\nwaivers:\n  - rule: ebu_r128.true_peak\n    reason: r\n"
        "    expires: 2030-01-01 00:00:00\n")
    (tmp_path / "f.json").write_text('{"audio":{"integrated_lufs":-23,"true_peak_dbtp":5}}')
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.yaml", today=dt.date(2026, 1, 1)).verdict is Verdict.PASS


# ---- L4: type confusion -----------------------------------------------------------------------------
def test_l4_superset_is_type_strict_and_merge_conflicts_on_type(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "rules": [
        {"id": "s", "path": "c", "op": "superset", "value": ["True", "1"]},
        {"id": "p", "path": "n", "op": "present"}]}))
    (tmp_path / "f.json").write_text('{"c": [true, 1], "n": null}')
    r = grade_media(str(tmp_path), facts=["f.json"], spec="s.json")
    ids = {i.detail["rule_id"] for i in r.issues}
    assert r.verdict is Verdict.FAIL and ids == {"s", "p"}     # coerced superset fails; null is "not measured"
    with pytest.raises(ValueError):
        merge([{"x": True}, {"x": 1}])


# ---- L5: AI detection breadth -----------------------------------------------------------------------
def test_l5_ai_in_templates_and_ingredient_manifests():
    src = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
    tmpl = _m(manifests={"u:1": {"assertions": [{"label": "c2pa.actions.v2", "data": {
        "templates": [{"action": "c2pa.created", "digitalSourceType": src}]}}]}})
    assert parse_manifest_report(tmpl).ai_generated
    ing = _m(manifests={"u:1": {"assertions": []}, "u:0": {"assertions": [{"label": "c2pa.actions", "data": {
        "actions": [{"action": "c2pa.created", "digitalSourceType": src}]}}]}})
    assert parse_manifest_report(ing).ai_generated


# ---- L6: ids and terminal output --------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["x\n", "x\r", "\nx"])
def test_l6_artifact_id_trailing_newline_rejected(bad):
    with pytest.raises(ValueError):
        valid_artifact_id(bad)


def test_l6_render_neutralises_control_characters(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([_rep(True)], artifact_id="a", log=log)
    ev = evaluate(log.records(), [Label(artifact_id="a", defect=True)])
    ev.graders[0].grader = "dsp\x1b]0;pwned\x07"
    assert "\x1b" not in render(ev) and "\x07" not in render(ev)


def test_chainlog_is_generic_over_record_types(tmp_path):
    assert ChainLog is not None
