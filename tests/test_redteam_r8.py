"""Regression pins for red-team round 8."""

from __future__ import annotations

import hashlib
import json
import os
import time

import pytest

from verel import _chainlog
from verel._chainlog import LogCorrupt
from verel.cli import main
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue, Worker, WorkerContext
from verel.pilot import ShadowLog, run_pilot
from verel.pilot.tenancy import pilot_log
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Report, Verdict


def rep():
    return assign(Report(verdict=Verdict.PASS, summary="s", issues=[], grader=GraderKind.DSP))


# ---- F5: the archived-id index is chained: no delete + duplicate trick ---------------------------------------------
def test_archived_id_index_cannot_be_edited_even_keeping_the_line_count(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(4):
        run_pilot([rep()], artifact_id=f"a{i}", log=log)
    log.archive_first(4, tmp_path / "s.archive")
    ids = tmp_path / "l.jsonl.ids"
    lines = ids.read_bytes().splitlines(keepends=True)
    assert log.archived_has("a1")
    ids.write_bytes(lines[0] + lines[2] + lines[2] + lines[3])            # drop a1's line, duplicate another
    with pytest.raises(LogCorrupt):
        log.archived_has("a1")
    with pytest.raises(LogCorrupt):
        run_pilot([rep()], artifact_id="a1", log=log, unique=True)
    ids.write_bytes(lines[1] + lines[0] + lines[2] + lines[3])            # reordered
    with pytest.raises(LogCorrupt):
        log.archived_has("a0")


def test_a_second_archive_extends_the_chain(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(6):
        run_pilot([rep()], artifact_id=f"b{i}", log=log)
    log.archive_first(2, tmp_path / "s1.archive")
    log.archive_first(2, tmp_path / "s2.archive")
    assert all(log.archived_has(f"b{i}") for i in range(4)) and not log.archived_has("b5")


# ---- F6: a failed archive leaves nothing behind --------------------------------------------------------------------
def test_failed_archive_rolls_back_ids_and_segment(tmp_path, monkeypatch):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(3):
        run_pilot([rep()], artifact_id=f"c{i}", log=log)
    real = _chainlog._write_atomic

    def boom(path, text, **kw):
        if str(path).endswith("l.jsonl"):
            raise OSError(28, "No space left on device")
        return real(path, text, **kw)

    monkeypatch.setattr(_chainlog, "_write_atomic", boom)
    with pytest.raises(OSError):
        log.archive_first(3, tmp_path / "seg.archive")
    monkeypatch.setattr(_chainlog, "_write_atomic", real)
    assert not (tmp_path / "seg.archive").exists()
    assert not log.archived_has("c0")                                       # no phantom archived ids
    log.archive_first(3, tmp_path / "seg.archive")                          # and a retry under the same name works
    assert log.archived_has("c0")


# ---- F1: only decisions whose facts named THIS file count as measured evidence --------------------------------------------
def test_jobs_with_unbound_facts_are_not_evidence(tmp_path, monkeypatch):
    monkeypatch.delenv("VEREL_EVIDENCE_ALLOW_SELF_REPORTED", raising=False)
    import urllib.request

    from verel.auth import Authenticator, TokenStore, add_token
    from verel.pilot.service import PilotServer
    tf = tmp_path / "t.json"
    adm = add_token(tf, id="adm", role="admin", tenant="acme")
    root = tmp_path / "m"
    root.mkdir()
    (root / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (root / "a.mxf").write_bytes(b"real-file")
    (root / "unbound.json").write_text(json.dumps({"audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0}}))
    (root / "bound.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0},
        "asset": {"sha256": hashlib.sha256(b"real-file").hexdigest()}}))
    ctx = WorkerContext(data_dir=tmp_path / "data", roots={"acme": {"m": root}})
    jq = JobQueue(tmp_path / "data" / "jobs.sqlite")
    base = {"root": "m", "spec": "s.json", "asset": "a.mxf"}
    jq.enqueue("acme", "media_grade", {**base, "facts": ["unbound.json"], "artifact_id": "unbound-1"}, by="op")
    jq.enqueue("acme", "media_grade", {**base, "facts": ["bound.json"], "artifact_id": "bound-1"}, by="op")
    w = Worker(jq, ctx)
    while w.run_once():
        pass
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    try:
        req = urllib.request.Request(srv.url + "/v1/pilot/evaluation?min_samples=1",
                                     headers={"Authorization": f"Bearer {adm}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            ev = json.loads(r.read())
        assert ev["self_reported_excluded"] == 1                           # the unbound job decision is left out
    finally:
        srv.stop()
    recs = {r.artifact_id: r for r in pilot_log(tmp_path / "data", "acme").records()}
    assert recs["bound-1"].bound and not recs["unbound-1"].bound


# ---- hot folder: F2 / F3 / F4 -----------------------------------------------------------------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def test_a_non_utf8_file_name_does_not_stop_the_scan(tmp_path):
    hf = _hf(tmp_path, facts_timeout_s=0)
    bad = os.path.join(bytes(hf.root / "incoming"), b"\xff\xfe.mxf")
    with open(bad, "wb") as f:
        f.write(b"x")
    os.utime(bad, (time.time() - 100,) * 2)
    p = hf.root / "incoming" / "good.mxf"
    p.write_bytes(b"ok")
    (hf.root / "incoming" / "good.mxf.facts.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0},
        "asset": {"sha256": hashlib.sha256(b"ok").hexdigest()}}))
    os.utime(p, (time.time() - 100,) * 2)
    out = scan_once(hf)
    assert any(o.action == "skipped" and "UTF-8" in o.note for o in out)
    assert any(o.name == "good.mxf" and o.action == "graded" for o in out)


def test_scan_cost_does_not_grow_quadratically_with_the_number_of_files(tmp_path):
    hf = _hf(tmp_path, max_per_scan=50)
    for i in range(3000):
        (hf.root / "incoming" / f"f{i:05d}.mxf").write_bytes(b"x")
    t0 = time.time()
    scan_once(hf)
    assert time.time() - t0 < 5          # the O(files x keys) pruning took tens of seconds at this size


def test_flooding_the_first_seen_store_does_not_reset_the_version_cap(tmp_path, monkeypatch):
    import verel.connectors.hotfolder as h
    monkeypatch.setattr(h, "MAX_SEEN", 40)
    hf = _hf(tmp_path)
    p = hf.root / "incoming" / "ep.mxf"
    p.write_bytes(b"x" * 10)
    (hf.root / "incoming" / "ep.mxf.facts.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0},
        "asset": {"sha256": hashlib.sha256(b"x" * 10).hexdigest()}}))
    t0 = time.time()
    for i in range(h.MAX_VERSIONS_PER_NAME + 5):
        os.utime(p, (t0 - 1000 + i, t0 - 1000 + i))
        scan_once(hf, now=t0)
    n_before = len(pilot_log(tmp_path / "data", "acme").records())
    assert n_before <= h.MAX_VERSIONS_PER_NAME
    for i in range(200):                                                   # flood: many files waiting for facts
        (hf.root / "incoming" / f"junk{i}.mxf").write_bytes(b"j")
    hf.max_per_scan = 400
    scan_once(hf, now=t0)
    os.utime(p, (t0 - 10, t0 - 10))
    scan_once(hf, now=t0)
    assert len(pilot_log(tmp_path / "data", "acme").records()) <= h.MAX_VERSIONS_PER_NAME


# ---- F8 -------------------------------------------------------------------------------------------------------------------------
def test_cli_reports_a_busy_log_instead_of_a_traceback(tmp_path, capsys, monkeypatch):
    log = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([rep()], artifact_id="a", log=log)
    monkeypatch.setattr(_chainlog, "LOCK_TIMEOUT_S", 0.2)
    held = log._lock()
    try:
        rc = main(["pilot", "archive", "--log", str(tmp_path / "l.jsonl"), "--keep-last", "0"])
    finally:
        os.close(held)
    assert rc == 2 and "busy" in capsys.readouterr().err
