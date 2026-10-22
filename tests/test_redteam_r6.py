"""Regression pins for red-team round 6."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from verel import _chainlog
from verel._chainlog import ChainLog, ChainRecord, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.cli import main
from verel.connectors.hotfolder import MAX_VERSIONS_PER_NAME, HotFolder, scan_once
from verel.jobs import JobQueue, Worker, WorkerContext
from verel.pilot import Label, ShadowLog, evaluate, run_pilot
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


# ---- F1: a shadow decision must never release a file under enforce ---------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, good, data=b"media"):
    p = hf.root / "incoming" / name
    p.write_bytes(data)
    lufs = -23.0 if good else -5.0
    (hf.root / "incoming" / f"{name}.facts.json").write_text(json.dumps({
        "audio": {"integrated_lufs": lufs, "true_peak_dbtp": -2.0 if good else 3.0},
        "asset": {"sha256": hashlib.sha256(data).hexdigest()}}))
    os.utime(p, (time.time() - 100,) * 2)
    return p


def test_a_shadow_pass_is_not_reused_after_switching_to_enforce(tmp_path):
    hf = _hf(tmp_path, mode="shadow")
    _drop(hf, "bad.mxf", good=False)
    out = scan_once(hf)[0]
    assert out.would_be == "fail" and out.enforced == "pass"             # shadow: recorded, nothing moves
    hf2 = _hf(tmp_path, mode="enforce")
    os.unlink(hf.root / "incoming" / "bad.mxf.verel.json")               # the "natural workaround", or an attacker
    out = scan_once(hf2)[0]
    assert out.enforced == "fail" and out.moved_to == "quarantine/bad.mxf"
    assert not (hf.root / "passed").exists()


def test_touching_a_file_cannot_flood_the_evidence_log(tmp_path):
    hf = _hf(tmp_path)
    p = _drop(hf, "ep.mxf", good=True)
    for i in range(MAX_VERSIONS_PER_NAME + 15):
        t = time.time() - 100 + i
        os.utime(p, (t, t))
        scan_once(hf)
    from verel.pilot.tenancy import pilot_log
    assert len(pilot_log(tmp_path / "data", "acme").records()) <= MAX_VERSIONS_PER_NAME


def test_first_seen_store_keeps_working_past_its_size_cap(tmp_path, monkeypatch):
    import verel.connectors.hotfolder as h
    monkeypatch.setattr(h, "MAX_SEEN", 50)
    hf = _hf(tmp_path, mode="enforce", facts_timeout_s=3600)
    for i in range(80):
        (hf.root / "incoming" / f"w{i:03d}.mxf").write_bytes(b"x")
    hf.max_per_scan = 200
    t0 = time.time()
    scan_once(hf, now=t0)
    late = _hf(tmp_path, mode="enforce", facts_timeout_s=3600)
    late.max_per_scan = 200
    out = scan_once(late, now=t0 + 4000)
    assert any(o.action == "graded" for o in out)                      # new first-seen times were still saved


# ---- F2: readers must not see a write half-way -----------------------------------------------------------------
def test_readers_never_see_spurious_corruption_during_writes(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    stop = threading.Event()
    errors: list[str] = []

    def writer():
        i = 0
        while not stop.is_set():
            lg.append(Rec(n=i))
            i += 1

    def reader():
        while not stop.is_set():
            try:
                lg.verify()
            except LogCorrupt as e:
                errors.append(str(e))
            except _chainlog.LogBusy:
                pass

    th = [threading.Thread(target=writer)] + [threading.Thread(target=reader) for _ in range(3)]
    [t.start() for t in th]
    time.sleep(2.0)
    stop.set()
    [t.join() for t in th]
    assert errors == []


# ---- F3: evidence counts files and attributes jobs to the person who enqueued them -----------------------
def test_one_file_under_many_ids_is_one_piece_of_evidence(tmp_path):
    root = tmp_path / "m"
    root.mkdir()
    (root / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (root / "a.mxf").write_bytes(b"the-same-bad-file")
    (root / "f.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0},
        "asset": {"sha256": hashlib.sha256(b"the-same-bad-file").hexdigest()}}))
    ctx = WorkerContext(data_dir=tmp_path / "d", roots={"acme": {"m": root}})
    jq = JobQueue(tmp_path / "j.sqlite")
    for i in range(30):
        jq.enqueue("acme", "media_grade", {"root": "m", "facts": ["f.json"], "spec": "s.json", "asset": "a.mxf",
                                           "artifact_id": f"copy-{i}"}, by="op1")
    w = Worker(jq, ctx)
    while w.run_once():
        pass
    from verel.pilot.tenancy import pilot_log
    recs = pilot_log(tmp_path / "d", "acme").records()
    assert len(recs) == 30 and {r.recorded_by for r in recs} == {"op1"} and len({r.content for r in recs}) == 1
    ev = evaluate(recs, [Label(artifact_id=f"copy-{i}", defect=True) for i in range(30)], min_samples=1)
    assert ev.overall.n == 1 and ev.duplicate_content == 29             # thirty ids, one file, one data point


def test_job_decisions_are_not_independent_of_the_person_who_enqueued_them(tmp_path):
    tf = tmp_path / "t.json"
    op = add_token(tf, id="op", role="operator", tenant="acme")
    add_token(tf, id="op2", role="operator", tenant="acme")
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    try:
        root = tmp_path / "m"
        root.mkdir()
        (root / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
        (root / "a.mxf").write_bytes(b"bad")
        (root / "f.json").write_text(json.dumps({
            "audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0},
            "asset": {"sha256": hashlib.sha256(b"bad").hexdigest()}}))

        def call(method, path, tok, body=None):
            req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode() if body is not None else None,
                                         method=method, headers={"Authorization": f"Bearer {tok}"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"{}")

        st, d = call("POST", "/v1/jobs", op, {"kind": "media_grade", "payload": {
            "root": "m", "facts": ["f.json"], "spec": "s.json", "asset": "a.mxf", "artifact_id": "mine"}})
        assert st == 202
        ctx = WorkerContext(data_dir=tmp_path / "data", roots={"acme": {"m": root}})
        Worker(srv.queue, ctx).run_once()
        call("POST", "/v1/pilot/labels", op, {"labels": [{"artifact_id": "mine", "defect": True}]})
        assert call("GET", "/v1/pilot/evaluation?min_samples=1", op)[1]["labeled"] == 0     # I enqueued it: I can't score it
    finally:
        srv.stop()


# ---- F4: retention does not reopen labels -----------------------------------------------------------------------
def test_an_archived_label_cannot_be_flipped_by_a_non_admin(tmp_path):
    tf = tmp_path / "t.json"
    op = add_token(tf, id="op", role="operator", tenant="acme")
    op2 = add_token(tf, id="op2", role="operator", tenant="acme")
    adm = add_token(tf, id="adm", role="admin", tenant="acme")
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()

    def call(method, path, tok, body=None):
        req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers={"Authorization": f"Bearer {tok}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    try:
        call("POST", "/v1/pilot/record", op, {"artifact_id": "a", "reports": [rep(True).model_dump(mode="json")]})
        assert call("POST", "/v1/pilot/labels", op2, {"labels": [{"artifact_id": "a", "defect": True}]})[0] == 200
        assert call("POST", "/v1/pilot/archive", adm, {"keep_last": 0, "log": "labels"})[0] == 200
        st, _ = call("POST", "/v1/pilot/labels", op2, {"labels": [{"artifact_id": "a", "defect": False}]})
        assert st == 409
    finally:
        srv.stop()


# ---- F5: repair can only drop the announced batch's own records ---------------------------------------------------
def test_repair_refuses_to_drop_acknowledged_records(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(n=0))
    captured = {}
    orig = ChainLog._write_ledger

    def spy(self, head, total, segs, pending=None):
        if pending is not None and "led" not in captured:
            orig(self, head, total, segs, pending)
            captured["led"] = (tmp_path / "c.jsonl.head").read_text()      # a ledger captured mid-batch
            return None
        return orig(self, head, total, segs, pending)

    ChainLog._write_ledger = spy
    try:
        lg.append_batch(lambda e: [Rec(n=i) for i in range(1, 9)])         # an 8-record batch
    finally:
        ChainLog._write_ledger = orig
    lg.append(Rec(n=100))                                                   # acknowledged afterwards
    lg.append(Rec(n=101))
    (tmp_path / "c.jsonl.head").write_text(captured["led"])                  # attacker restores the mid-batch ledger
    with pytest.raises(LogCorrupt):
        lg.verify()
    before = lg.path.read_text()
    with pytest.raises(LogCorrupt, match="refusing"):
        lg.repair()                                                        # the hint is followed: still no data loss
    assert lg.path.read_text() == before


# ---- F7: the CLI can verify service data --------------------------------------------------------------------------
def test_cli_verifies_tenant_logs_with_a_domain(tmp_path, capsys):
    from verel.pilot.tenancy import pilot_log
    log = pilot_log(tmp_path / "data", "acme")
    run_pilot([rep(False)], artifact_id="x", log=log)
    path = str(log.path)
    assert main(["pilot", "verify", "--log", path]) == 2
    assert main(["pilot", "verify", "--log", path, "--domain", "acme/pilot"]) == 0


# ---- F8: archived-id lookup is cached ---------------------------------------------------------------------------
def test_archived_ids_are_cached_between_appends(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(20):
        run_pilot([rep(False)], artifact_id=f"a{i}", log=log)
    log.archive_first(20, tmp_path / "seg.archive")
    assert log.archived_has("a3") and not log.archived_has("zzz")
    key = str(tmp_path / "l.jsonl.ids")
    assert key in _chainlog._IDS_CACHE
    first = _chainlog._IDS_CACHE[key]
    log.archived_has("a4")
    assert _chainlog._IDS_CACHE[key] is first                              # not re-read while the file is unchanged
