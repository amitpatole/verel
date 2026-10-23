"""Regression pins for red-team round 7."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request

import pytest

from verel import _chainlog
from verel._chainlog import ChainLog, ChainRecord, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue
from verel.pilot import ShadowLog, run_pilot
from verel.pilot.service import PilotServer
from verel.pilot.tenancy import pilot_log, policy_store
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rep(bad, sha=None, bound=False):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a",
                 source=GraderKind.MEDIA)] if bad else []
    r = assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss,
                      grader=GraderKind.MEDIA))
    if sha:
        r.artifacts["asset_sha256"] = sha
    if bound:
        r.artifacts["facts_bound"] = "1"
    return r


class Rec(ChainRecord):
    n: int
    tag: str = ""


# ---- 1: a slow verify must not block writers ------------------------------------------------------------------
def test_a_slow_reader_does_not_block_a_writer(tmp_path, monkeypatch):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(5):
        lg.append(Rec(n=i))
    orig = ChainLog._verify_files
    started = threading.Event()

    def slow(self, check_ledger):
        started.set()
        time.sleep(1.5)                          # verification runs AFTER the shared lock was released
        return orig(self, check_ledger)

    monkeypatch.setattr(ChainLog, "_verify_files", slow)
    th = threading.Thread(target=lg.verify)
    th.start()
    assert started.wait(5)
    t0 = time.time()
    monkeypatch.setattr(ChainLog, "_verify_files", orig)
    lg.append(Rec(n=99))
    assert time.time() - t0 < 1.0                # the writer did not wait for the reader's verification
    th.join()


def test_read_only_copies_can_still_be_verified(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    lg = ChainLog(tmp_path / "ro" / "c.jsonl", Rec)
    for i in range(3):
        lg.append(Rec(n=i))
    d = tmp_path / "ro"
    for f in d.iterdir():
        os.chmod(f, 0o400)
    os.chmod(d, 0o500)
    try:
        assert ChainLog(d / "c.jsonl", Rec).verify() == 3
    finally:
        os.chmod(d, 0o700)


# ---- 2: the ledger cannot grow without bound -------------------------------------------------------------------
def test_ledger_stays_small_after_many_archives(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec, id_field="tag")
    for i in range(260):
        lg.append(Rec(n=i, tag=f"t{i}"))
        lg.archive_first(1, tmp_path / f"seg{i}.archive")
    led = json.loads((tmp_path / "c.jsonl.head").read_text())
    assert len(led["segments"]) <= _chainlog.MAX_SEGMENT_ENTRIES
    assert (tmp_path / "c.jsonl.head").stat().st_size < 100_000
    lg.append(Rec(n=1000, tag="x"))
    assert lg.verify() == 1
    assert lg.missing_segments() == []           # folded entries are not reported as missing
    assert lg.archived_has("t0") and lg.archived_has("t259")


# ---- 7: the archived-id index is keyed, counted and written only for a real archive --------------------------------
def test_archived_id_index_resists_forgery_deletion_and_failed_archives(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(4):
        run_pilot([rep(False)], artifact_id=f"clip-{i}", log=log)
    log.archive_first(4, tmp_path / "s1.archive")
    ids = tmp_path / "l.jsonl.ids"
    assert log.archived_has("clip-1")
    with open(ids, "ab") as f:                                       # a forged line (no valid key) is reported
        f.write(hashlib.sha256(b"clip-9").hexdigest()[:16].encode() + b" 0000000000000000\n")
    with pytest.raises(LogCorrupt):
        log.archived_has("clip-9")
    ids.write_bytes(b"".join(ids.read_bytes().splitlines(keepends=True)[:4]))   # restore the genuine 4 lines
    assert log.archived_has("clip-1")
    ids.unlink()                                                     # deleting the index is detected, not trusted
    with pytest.raises(LogCorrupt):
        log.archived_has("clip-1")
    with pytest.raises(LogCorrupt):
        run_pilot([rep(True)], artifact_id="clip-1", log=log, unique=True)


def test_a_failed_archive_leaves_no_archived_ids(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(3):
        run_pilot([rep(False)], artifact_id=f"a{i}", log=log)
    (tmp_path / "taken.archive").write_text("x")
    with pytest.raises(ValueError):
        log.archive_first(3, tmp_path / "taken.archive")
    assert not log.archived_has("a0")
    assert not (tmp_path / "l.jsonl.ids").exists()


# ---- 9 / 10: queue ----------------------------------------------------------------------------------------------------
def test_an_old_queue_file_is_migrated(tmp_path):
    p = tmp_path / "old.sqlite"
    c = sqlite3.connect(p)
    c.executescript("""CREATE TABLE jobs(
      id TEXT PRIMARY KEY, tenant TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
      state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
      run_after REAL NOT NULL, lease_owner TEXT, lease_expires REAL, result TEXT, error TEXT,
      dedupe_key TEXT, created REAL NOT NULL, updated REAL NOT NULL);""")
    c.commit()
    c.close()
    jq = JobQueue(p)
    jid = jq.enqueue("t", "k", {}, by="op")
    job = jq.claim("w", ["k"])
    assert job.id == jid and job.by == "op"


def test_a_busy_tenant_is_not_locked_out_by_its_own_finished_jobs(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_JOBS_MAX_ROWS", "10")
    jq = JobQueue(tmp_path / "j.sqlite")
    now = time.time()
    for i in range(10):
        jid = jq.enqueue("busy", "k", {"i": i}, now=now - 3600)
        j = jq.claim("w", ["k"], now=now - 3500)
        jq.complete(j, {}, now=now - 3400)
        _ = jid
    jq.enqueue("busy", "k", {"fresh": True})                          # makes room by dropping old FINISHED jobs
    assert jq.stats("busy")["queued"] == 1
    for _ in range(12):                                                # but pending work is never dropped
        try:
            jq.enqueue("busy", "k", {})
        except Exception:
            break
    else:
        pytest.fail("expected the row cap to apply to pending work")


# ---- 5 / 6: hot folder ---------------------------------------------------------------------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, good=True, data=b"media"):
    p = hf.root / "incoming" / name
    p.write_bytes(data)
    (hf.root / "incoming" / f"{name}.facts.json").write_text(json.dumps({
        "audio": {"integrated_lufs": -23.0 if good else -5.0, "true_peak_dbtp": -2.0 if good else 3.0},
        "asset": {"sha256": hashlib.sha256(data).hexdigest()}}))
    os.utime(p, (time.time() - 100,) * 2)
    return p


def test_swapped_bytes_with_a_restored_mtime_are_recorded_as_a_new_version(tmp_path):
    hf = _hf(tmp_path)
    p = _drop(hf, "ep.mxf", good=True, data=b"AAAAAAAAAAAA")
    scan_once(hf)
    mt = p.stat().st_mtime_ns
    _drop(hf, "ep.mxf", good=False, data=b"BBBBBBBBBBBB")              # same size, different bytes
    os.utime(p, ns=(mt, mt))                                           # mtime restored
    (hf.root / "incoming" / "ep.mxf.verel.json").unlink()
    out = scan_once(hf)
    assert out and out[0].would_be == "fail"
    assert len(pilot_log(tmp_path / "data", "acme").records()) == 2    # NOT graded without being recorded


def test_names_that_sanitize_alike_are_different_artifacts(tmp_path):
    hf = _hf(tmp_path)
    _drop(hf, "a b.mxf", data=b"one")
    _drop(hf, "a_b.mxf", data=b"two")
    scan_once(hf)
    ids = {r.artifact_id for r in pilot_log(tmp_path / "data", "acme").records()}
    assert len(ids) == 2


def test_the_version_cap_resets_after_a_day(tmp_path):
    import verel.connectors.hotfolder as h
    hf = _hf(tmp_path)
    p = _drop(hf, "ep.mxf")
    t0 = time.time()
    for i in range(h.MAX_VERSIONS_PER_NAME + 3):
        os.utime(p, (t0 - 1000 + i, t0 - 1000 + i))
        scan_once(hf, now=t0)
    os.utime(p, (t0 - 500, t0 - 500))
    blocked = scan_once(hf, now=t0)
    assert blocked and blocked[0].action == "skipped"
    os.utime(p, (t0 - 400, t0 - 400))
    later = scan_once(hf, now=t0 + 2 * 86400)                          # a day later the sender's budget is fresh
    assert later and later[0].action == "graded"


# ---- 3 / 4: self-reported decisions are not evidence --------------------------------------------------------------------
@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("VEREL_EVIDENCE_ALLOW_SELF_REPORTED", raising=False)     # the secure default
    tf = tmp_path / "t.json"
    t = {k: add_token(tf, id=k, role=r, tenant="acme") for k, r in (
        ("op", "operator"), ("rev", "operator"), ("rev2", "operator"), ("adm", "admin"), ("view", "viewer"))}
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


def test_forged_http_decisions_cannot_demote_a_good_grader(env):
    srv, t, tmp = env
    store = policy_store(tmp / "data", "acme")
    store.promote("media", "advisory", "a")
    store.promote("media", "enforce", "a", None, override_reason="bootstrap with sign-off from the QC lead")
    for i in range(25):                                       # an operator forges FAILs for assets that are fine...
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"f{i}",
                                                        "reports": [rep(True).model_dump(mode="json")]})
    # ...and an honest reviewer, judging the ASSETS, labels them clean
    call(srv, "POST", "/v1/pilot/labels", t["rev"], {"labels": [{"artifact_id": f"f{i}", "defect": False} for i in range(25)]})
    st, d = call(srv, "POST", "/v1/pilot/health", t["adm"], {})
    assert st == 200 and d["autodemoted"] == []               # self-reported decisions are not evidence
    ev = call(srv, "GET", "/v1/pilot/evaluation", t["view"])[1]
    assert ev["labeled"] == 0 and ev["self_reported_excluded"] == 25
    assert policy_store(tmp / "data", "acme").current().mode_for("media").value == "enforce"


def test_a_decoy_record_cannot_suppress_a_real_decision(env):
    srv, t, tmp = env
    sha = hashlib.sha256(b"the real file").hexdigest()
    call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": "decoy",
                                                    "reports": [rep(False, sha).model_dump(mode="json")]})
    log = pilot_log(tmp / "data", "acme")
    run_pilot([rep(True, sha, bound=True)], artifact_id="real", log=log, ref="hotfolder", recorded_by="hotfolder", trusted=True)
    st, ev = call(srv, "GET", "/v1/pilot/evaluation?min_samples=1", t["view"])
    assert ev["self_reported_excluded"] == 1 and ev["duplicate_content"] == 0   # the decoy never reaches the dedupe
