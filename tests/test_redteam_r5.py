"""Regression pins for red-team round 5."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.request

import pytest

from verel._chainlog import ChainLog, ChainRecord
from verel.auth import Authenticator, TokenStore, add_token
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue
from verel.jobs.queue import QuotaExceeded
from verel.media import grade_provenance, parse_manifest_report
from verel.pilot import ShadowLog, run_pilot
from verel.pilot.log import DuplicateArtifact
from verel.pilot.service import PilotServer
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rep(bad):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a",
                 source=GraderKind.DSP)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss,
                         grader=GraderKind.DSP))


class Rec(ChainRecord):
    n: int


# ---- 3: real C2PA success/informational codes must not read as tampering --------------------------------
def _m(codes):
    return {"active_manifest": "u", "validation_status": [{"code": c} for c in codes],
            "manifests": {"u": {"assertions": []}}}


@pytest.mark.parametrize("codes", [
    ["claimSignature.validated", "signingCredential.ocsp.notRevoked", "signingCredential.trusted"],
    ["assertion.hashedURI.match", "timeStamp.validated", "claimSignature.insideValidity"]])
def test_real_success_codes_stay_valid(codes):
    assert parse_manifest_report(_m(codes)).state in ("valid", "trusted")


@pytest.mark.parametrize("codes", [["signingCredential.ocsp.skipped"], ["signingCredential.ocsp.inaccessible"]])
def test_ocsp_unavailable_is_a_warning_not_tampering(tmp_path, codes):
    (tmp_path / "m.json").write_text(json.dumps(_m(codes)))
    r = grade_provenance(str(tmp_path), manifest_json="m.json")
    assert r.verdict is Verdict.WARN and any("revocation" in i.message for i in r.issues)


@pytest.mark.parametrize("code", ["signingCredential.ocsp.revoked", "claimSignature.mismatch"])
def test_revocation_and_signature_failures_still_fail(code):
    assert parse_manifest_report(_m([code])).state == "invalid"


# ---- 4/5/7: hot folder ----------------------------------------------------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, data=b"media", age=100, facts=True):
    p = hf.root / "incoming" / name
    p.write_bytes(data)
    if facts:
        (hf.root / "incoming" / f"{name}.facts.json").write_text(json.dumps({
            "audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0},
            "asset": {"sha256": hashlib.sha256(data).hexdigest()}}))
    os.utime(p, (time.time() - age,) * 2)
    return p


def test_metadata_only_change_during_grading_is_regraded_and_delivered(tmp_path, monkeypatch):
    hf = _hf(tmp_path, mode="enforce")
    p = _drop(hf, "ep.mxf")
    import verel.connectors.hotfolder as h
    real = h.run_pilot
    calls = []

    def chmod_once(*a, **k):
        d = real(*a, **k)
        if not calls:
            calls.append(1)
            os.chmod(p, 0o600)                    # an indexer touches metadata: ctime moves, content does not
        return d

    monkeypatch.setattr(h, "run_pilot", chmod_once)
    first = scan_once(hf)[0]
    assert "changed while" in first.note and not first.moved_to
    second = scan_once(hf)
    assert second and second[0].moved_to == "passed/ep.mxf"            # a NEW version id: not stuck as a duplicate


def test_crash_after_decision_before_move_is_finished_not_stuck(tmp_path, monkeypatch):
    hf = _hf(tmp_path, mode="enforce")
    _drop(hf, "ep.mxf")
    import verel.connectors.hotfolder as h
    real_move = h._move
    monkeypatch.setattr(h, "_move", lambda *a, **k: (_ for _ in ()).throw(OSError("simulated crash")))
    assert scan_once(hf)[0].action == "skipped"                         # decision recorded, move failed
    monkeypatch.setattr(h, "_move", real_move)
    out = scan_once(hf)
    assert out and out[0].moved_to == "passed/ep.mxf"                   # recognised as our own decision, finished


def test_late_facts_for_an_old_file_are_not_quarantined_instantly(tmp_path):
    hf = _hf(tmp_path, mode="enforce", facts_timeout_s=3600)
    _drop(hf, "old.mxf", age=2 * 86400, facts=False)                    # old mtime, no facts yet
    out = scan_once(hf)
    assert out[0].action == "waiting" and not (hf.root / "quarantine").exists()
    (hf.root / "incoming" / "old.mxf.facts.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0},
        "asset": {"sha256": hashlib.sha256(b"media").hexdigest()}}))
    assert scan_once(hf)[0].enforced == "pass"


def test_waiting_is_measured_from_first_sight_across_runs(tmp_path):
    hf = _hf(tmp_path, mode="enforce", facts_timeout_s=3600)
    _drop(hf, "x.mxf", facts=False)
    scan_once(hf, now=time.time())
    later = scan_once(_hf(tmp_path, mode="enforce", facts_timeout_s=3600), now=time.time() + 4000)
    assert later[0].action == "graded" and later[0].enforced == "fail"   # first seen 4000 s ago: now it is overdue


def test_hostile_directory_in_place_of_a_sidecar_does_not_stop_the_scan(tmp_path):
    hf = _hf(tmp_path)
    _drop(hf, "good1.mxf")
    _drop(hf, "good2.mxf", data=b"other")
    (hf.root / "incoming" / "good1.mxf.verel.json").mkdir()
    out = {o.name: o for o in scan_once(hf)}
    assert out["good2.mxf"].action == "graded"
    assert out["good1.mxf"].action == "skipped"


# ---- 6: queue --------------------------------------------------------------------------------------------
def test_one_tenant_filling_its_rows_does_not_block_another(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_JOBS_MAX_ROWS", "5")
    jq = JobQueue(tmp_path / "j.sqlite")
    for i in range(5):
        jq.enqueue("attacker", "k", {"i": i})
    with pytest.raises(QuotaExceeded):
        jq.enqueue("attacker", "k", {})
    jq.enqueue("victim", "k", {"ok": True})                              # unaffected


def test_dead_jobs_do_not_keep_their_payload(tmp_path):
    import sqlite3
    jq = JobQueue(tmp_path / "j.sqlite")
    jid = jq.enqueue("t", "k", {"big": "x" * 5000}, max_attempts=1)
    j = jq.claim("w", ["k"])
    assert jq.fail(j, "boom") == "dead"
    assert sqlite3.connect(jq.path).execute("SELECT payload FROM jobs WHERE id=?", (jid,)).fetchone()[0] == "{}"


# ---- 8: unique-record writes are not O(n) ------------------------------------------------------------------
def test_unique_append_is_fast_on_a_big_log_and_still_unique(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    log.append_batch(lambda e: [])
    recs = [log.records()]  # touch
    _ = recs
    for chunk in range(6):
        from datetime import datetime, timezone

        from verel.pilot.log import ShadowRecord
        from verel.pilot.mode import Mode
        stamp = datetime.now(timezone.utc).isoformat()

        def make(e, c=chunk, ts=stamp):
            return [ShadowRecord(artifact_id=f"x{c}-{i}", ts=ts, mode=Mode.SHADOW, would_be=Verdict.PASS,
                                 enforced=Verdict.PASS) for i in range(500)]

        log.append_batch(make)
    t0 = time.time()
    for i in range(40):
        run_pilot([rep(False)], artifact_id=f"new{i}", log=log, unique=True)
    assert time.time() - t0 < 10
    with pytest.raises(DuplicateArtifact):
        run_pilot([rep(False)], artifact_id="x3-7", log=log, unique=True)
    with pytest.raises(DuplicateArtifact):
        run_pilot([rep(False)], artifact_id="new5", log=log, unique=True)
    run_pilot([rep(False)], artifact_id="x3-77777", log=log, unique=True)   # a prefix/lookalike is not a duplicate


# ---- 9: tokens -----------------------------------------------------------------------------------------------
def test_token_store_recovers_after_a_transient_bad_file_and_notices_chmod(tmp_path):
    p = tmp_path / "tokens.json"
    tok = add_token(p, id="a", role="viewer", tenant="t")
    s = TokenStore(p)
    assert s.authenticate(tok) is not None
    good = p.read_bytes()
    st = p.stat()
    p.write_bytes(b"{ not json")
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert s.authenticate(tok) is None                                   # bad file: everyone denied
    p.write_bytes(good)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))                     # same bytes, same mtime restored
    assert s.authenticate(tok) is not None                               # and the next request recovers
    os.chmod(p, 0o662)                                                   # group-writable after startup
    assert s.authenticate(tok) is None
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    assert s.authenticate(tok) is not None


# ---- 1: a stale ledger cannot hide truncation (also covered in r1/r4) ---------------------------------------------
def test_stale_ledger_copy_with_a_truncated_log_is_caught(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(30):
        lg.append(Rec(n=i))
    stale = (tmp_path / "c.jsonl.head").read_text()
    for i in range(30, 60):
        lg.append(Rec(n=i))
    lines = lg.path.read_text().splitlines()
    lg.path.write_text("\n".join(lines[:50]) + "\n")
    (tmp_path / "c.jsonl.head").write_text(stale)
    from verel._chainlog import LogCorrupt
    with pytest.raises(LogCorrupt):
        lg.verify()


# ---- 2 / 10 / 11: service --------------------------------------------------------------------------------------
@pytest.fixture
def env(tmp_path):
    tf = tmp_path / "t.json"
    t = {k: add_token(tf, id=k, role=r, tenant="acme") for k, r in (
        ("view", "viewer"), ("op", "operator"), ("op2", "operator"), ("adm", "admin"))}
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    yield srv, t, tmp_path
    srv.stop()


def call(srv, method, path, tok, body=None):
    req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_one_operator_cannot_fabricate_both_halves_of_the_evidence(env):
    srv, t, tmp = env
    from verel.pilot.tenancy import policy_store
    store = policy_store(tmp / "data", "acme")
    store.promote("dsp", "advisory", "a")
    store.promote("dsp", "enforce", "a", None, override_reason="bootstrap with sign-off from the QC lead")
    for i in range(25):                                         # the SAME operator records fake FAILs and labels them clean
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"f{i}", "reports": [rep(True).model_dump(mode="json")]})
    call(srv, "POST", "/v1/pilot/labels", t["op"], {"labels": [{"artifact_id": f"f{i}", "defect": False} for i in range(25)]})
    st, d = call(srv, "POST", "/v1/pilot/health", t["adm"], {})
    assert st == 200 and d["autodemoted"] == []                  # self-labeled decisions are not evidence
    st, ev = call(srv, "GET", "/v1/pilot/evaluation", t["view"])
    assert ev["labeled"] == 0
    # but a DIFFERENT person labeling them is
    call(srv, "POST", "/v1/pilot/labels", t["op2"], {"labels": [{"artifact_id": f"f{i}", "defect": False} for i in range(25)]})
    assert call(srv, "GET", "/v1/pilot/evaluation", t["view"])[1]["labeled"] in (0, 25)


def test_privileged_denials_keep_being_audited(env):
    srv, t, tmp = env
    for _ in range(30):
        assert call(srv, "POST", "/v1/pilot/record", t["view"], {})[0] == 403          # cheap denials burn their budget
    assert call(srv, "POST", "/v1/pilot/archive", t["view"], {"log": "audit", "keep_last": 0})[0] == 403
    assert call(srv, "POST", "/v1/pilot/promote", t["op"], {"grader": "dsp", "to": "advisory"})[0] == 403
    text = (tmp / "data/tenants/acme/audit.jsonl").read_text()
    assert "POST /v1/pilot/archive" in text and "POST /v1/pilot/promote" in text


def test_archiving_the_decision_log_does_not_reopen_artifact_ids(env):
    srv, t, tmp = env
    for i in range(4):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"e{i}", "reports": [rep(False).model_dump(mode="json")]})
    assert call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": "e0", "reports": [rep(True).model_dump(mode="json")]})[0] == 409
    assert call(srv, "POST", "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "pilot"})[0] == 200
    st, _ = call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": "e0", "reports": [rep(True).model_dump(mode="json")]})
    assert st == 409                                             # still decided, even though it left the live log
    assert call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": "brand-new", "reports": [rep(False).model_dump(mode="json")]})[0] == 200


def test_archive_of_decisions_requires_an_audit_record(env):
    srv, t, tmp = env
    call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": "e0", "reports": [rep(False).model_dump(mode="json")]})
    audit = tmp / "data/tenants/acme/audit.jsonl"
    audit.unlink()
    audit.mkdir()                                                # audit log unusable
    assert call(srv, "POST", "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "pilot"})[0] == 503
    assert (tmp / "data/tenants/acme/pilot.jsonl").read_text().count("\n") >= 1       # nothing was archived
