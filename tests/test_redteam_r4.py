"""Regression pins for red-team round 4."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

import pytest

from verel import _chainlog
from verel._chainlog import ChainLog, ChainRecord, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue, Worker, WorkerContext
from verel.jobs.queue import QuotaExceeded
from verel.media import grade_media, parse_manifest_report
from verel.pilot import Label, ShadowLog, evaluate, run_pilot
from verel.pilot.log import DuplicateArtifact
from verel.pilot.mode import Mode
from verel.pilot.policy import Policy, health
from verel.pilot.service import PilotServer
from verel.pilot.tenancy import policy_store
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rep(bad, grader=GraderKind.DSP):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss, grader=grader))


class Rec(ChainRecord):
    n: int


# ---- 1: a repeated facts list is a memory bomb ------------------------------------------------------
def test_repeated_or_excessive_facts_files_are_refused(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (tmp_path / "f.json").write_text("{" + '"pad":"' + "x" * 3_000_000 + '"}')
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["f.json"] * 40, spec="s.json")
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["f.json", "./f.json"], spec="s.json")      # same file, different spelling
    for i in range(9):
        (tmp_path / f"g{i}.json").write_text("{}")
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=[f"g{i}.json" for i in range(9)], spec="s.json")


# ---- 2: re-recording cannot rewrite evidence ---------------------------------------------------------
def test_first_decision_is_scored_and_service_refuses_a_second(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([rep(False)], artifact_id="a", log=log, unique=True)
    with pytest.raises(DuplicateArtifact):
        run_pilot([rep(True)], artifact_id="a", log=log, unique=True)
    assert len(log.records()) == 1
    ev = evaluate(list(log.records()) + [log.records()[0].model_copy(update={"would_be": Verdict.FAIL})],
                  [Label(artifact_id="a", defect=True)])
    assert ev.overall.fn == 1                      # the later (forged-looking) record is ignored


def test_health_ignores_rerecords(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    labels = []
    for i in range(40):
        labels.append(Label(artifact_id=f"b{i}", defect=False))
        run_pilot([rep(True)], artifact_id=f"b{i}", log=log)               # 40 false alarms
    for i in range(40):
        run_pilot([rep(False)], artifact_id=f"b{i}", log=log)              # "fixed" by re-recording
    h = health(log.records(), labels, Policy(graders={"dsp": Mode.ENFORCE}))
    assert [x.healthy for x in h] == [False]


# ---- 3: enforcement requires the asset ---------------------------------------------------------------
def test_enforce_jobs_need_the_asset(tmp_path):
    root = tmp_path / "m"
    root.mkdir()
    (root / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (root / "f.json").write_text(json.dumps({"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}))
    ctx = WorkerContext(data_dir=tmp_path / "d", roots={"acme": {"m": root}}, pins={("acme", "m", "spec"): "s.json"})
    jq = JobQueue(tmp_path / "j.sqlite")
    jid = jq.enqueue("acme", "media_grade", {"root": "m", "facts": ["f.json"], "artifact_id": "x", "mode": "enforce"})
    Worker(jq, ctx).run_once()
    assert jq.get("acme", jid)["state"] == "dead"


def test_retried_job_is_idempotent_but_a_foreign_duplicate_is_refused(tmp_path):
    root = tmp_path / "m"
    root.mkdir()
    (root / "s.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (root / "f.json").write_text(json.dumps({"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}))
    ctx = WorkerContext(data_dir=tmp_path / "d", roots={"acme": {"m": root}})
    jq = JobQueue(tmp_path / "j.sqlite")
    p = {"root": "m", "facts": ["f.json"], "spec": "s.json", "artifact_id": "same"}
    first = jq.enqueue("acme", "media_grade", p)
    Worker(jq, ctx).run_once()
    assert jq.get("acme", first)["state"] == "done"
    other = jq.enqueue("acme", "media_grade", p)                          # a different job, same artifact id
    Worker(jq, ctx).run_once()
    assert jq.get("acme", other)["state"] == "dead"
    # a retry of the SAME job (crash after the record was written) succeeds instead of dying
    jid = jq.enqueue("acme", "media_grade", {**p, "artifact_id": "retry"})
    w = Worker(jq, ctx)
    job = jq.claim(w.id, list(w.handlers))
    w.handlers["media_grade"](job, ctx)                                   # attempt 1 writes the record, then "crashes"
    again = w.handlers["media_grade"](job, ctx)
    assert again["enforced"] == "pass"
    _ = jid


# ---- 4: hot folder ------------------------------------------------------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, facts, data=b"media"):
    p = hf.root / "incoming" / name
    p.write_bytes(data)
    (hf.root / "incoming" / f"{name}.facts.json").write_text(
        json.dumps({**facts, "asset": {"sha256": hashlib.sha256(data).hexdigest()}}))
    os.utime(p, (time.time() - 100,) * 2)
    return p


GOOD = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}
BAD = {"audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0}}


def test_once_runs_make_progress_past_hidden_files(tmp_path):
    for i in range(30):
        (tmp_path / "hf" / "incoming").mkdir(parents=True, exist_ok=True)
        (tmp_path / "hf" / "incoming" / f".hidden{i}").write_bytes(b"x")
    hf = _hf(tmp_path, max_per_scan=10)
    _drop(hf, "real.mxf", GOOD)
    out = []
    for _ in range(3):                          # a FRESH HotFolder each time, like `hotfolder --once`
        out += scan_once(_hf_again(hf))
    assert any(o.name == "real.mxf" and o.action == "graded" for o in out)


def _hf_again(hf):
    return HotFolder(root=hf.root, data_dir=hf.data_dir, tenant=hf.tenant, spec=hf.spec, settle_s=0,
                     max_per_scan=hf.max_per_scan)


def test_swapped_content_with_restored_mtime_is_regraded(tmp_path):
    hf = _hf(tmp_path)
    p = _drop(hf, "ep.mxf", GOOD, data=b"AAAAAAAAAAAA")
    assert scan_once(hf)[0].action == "graded"
    mt = p.stat().st_mtime_ns
    p.write_bytes(b"BBBBBBBBBBBB")              # same size, different bytes...
    os.utime(p, ns=(mt, mt))                    # ...mtime restored. ctime cannot be.
    (hf.root / "incoming" / "ep.mxf.facts.json").write_text(
        json.dumps({**GOOD, "asset": {"sha256": hashlib.sha256(b"AAAAAAAAAAAA").hexdigest()}}))
    out = scan_once(hf)
    assert out and out[0].action in ("graded", "skipped")                 # not silently trusted
    if out[0].action == "graded":
        assert out[0].would_be == "fail"                                  # stale hash no longer matches the file


def test_file_changed_between_grading_and_move_is_not_moved(tmp_path, monkeypatch):
    hf = _hf(tmp_path, mode="enforce")
    p = _drop(hf, "ep.mxf", GOOD)
    import verel.connectors.hotfolder as h
    real = h.run_pilot

    def swap_then_pilot(*a, **k):
        d = real(*a, **k)
        p.write_bytes(b"EVIL-CONTENT-NOW")
        return d

    monkeypatch.setattr(h, "run_pilot", swap_then_pilot)
    out = scan_once(hf)
    assert "changed while" in out[0].note and not out[0].moved_to
    assert (hf.root / "incoming" / "ep.mxf").read_bytes() == b"EVIL-CONTENT-NOW"
    assert not (hf.root / "passed").exists()


# ---- 5: a crashed batch is recoverable -----------------------------------------------------------------
def test_interrupted_batch_is_recovered_not_bricked(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(n=0))
    pid = os.fork()
    if pid == 0:                                    # a child killed right before the ledger is finalized
        orig = ChainLog._write_ledger

        def dying(self, head, total, segs, pending=None):
            if pending is None:
                os._exit(0)
            return orig(self, head, total, segs, pending)

        ChainLog._write_ledger = dying
        lg.append_batch(lambda e: [Rec(n=i) for i in range(1, 6)])
        os._exit(0)
    os.waitpid(pid, 0)
    assert lg.verify() == 6                         # the announced batch landed completely
    lg.append(Rec(n=99))
    assert lg.verify() == 7
    lines = lg.path.read_text().splitlines()        # but a ledger AHEAD of the log (truncation) is still caught
    lg.path.write_text("\n".join(lines[:-3]) + "\n")
    with pytest.raises(LogCorrupt):
        lg.verify()


def test_half_persisted_batch_needs_an_explicit_repair(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(n=0))
    committed = (tmp_path / "c.jsonl.head").read_text()
    lg.append_batch(lambda e: [Rec(n=i) for i in range(1, 6)])
    full = lg.path.read_text().splitlines()
    # power loss: the pending marker was durable, only 2 of the 5 records reached the disk
    import json as _json
    led = _json.loads(committed)
    after = _json.loads((tmp_path / "c.jsonl.head").read_text())
    hashes = [_json.loads(line)["hash"] for line in full[1:]]
    led["pending"] = {"head": after["head"], "total": after["total"], "hashes": hashes}
    led["mac"] = lg._m(lg._ledger_text(led["head"], led["total"], led["segments"],
                                       (after["head"], after["total"], tuple(hashes))))
    (tmp_path / "c.jsonl.head").write_text(_json.dumps(led))
    lg.path.write_text("\n".join(full[:3]) + "\n")                   # record 0 + 2 of the batch
    with pytest.raises(LogCorrupt, match="repair"):
        lg.verify()
    with pytest.raises(LogCorrupt):
        lg.append(Rec(n=7))                                           # no silent auto-rollback of anything
    assert lg.repair() == 2
    assert lg.verify() == 1
    lg.append(Rec(n=8))
    assert lg.verify() == 2


def test_batch_size_is_capped(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    with pytest.raises(ValueError):
        lg.append_batch(lambda e: [Rec(n=i) for i in range(_chainlog.MAX_BATCH + 1)])


# ---- 6: repair never destroys a committed record ---------------------------------------------------------
def test_stripped_newline_is_restored_not_truncated(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(3):
        lg.append(Rec(n=i))
    raw = lg.path.read_text()
    lg.path.write_text(raw.rstrip("\n"))                                   # strip only the final newline
    lg.append(Rec(n=3))
    assert lg.verify() == 4                                                # the third record survived


# ---- 7: denial spam / audit ordering ------------------------------------------------------------------------
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


def test_denied_calls_cannot_fill_the_audit_log(env):
    srv, t, tmp = env
    for _ in range(100):
        assert call(srv, "POST", "/v1/pilot/record", t["view"], {})[0] == 403
    lines = (tmp / "data/tenants/acme/audit.jsonl").read_text().count("\n")
    assert lines <= 21 and srv.stats["denials_not_audited"] >= 79


def test_intent_is_audited_before_a_policy_change(env):
    srv, t, tmp = env
    audit = tmp / "data/tenants/acme/audit.jsonl"
    audit.parent.mkdir(parents=True, mode=0o700)
    audit.mkdir()                                                          # make the audit log unusable
    st, _ = call(srv, "POST", "/v1/pilot/default", t["adm"], {"mode": "advisory"})
    assert st == 503
    assert policy_store(tmp / "data", "acme").records() == []              # and the change did NOT happen


# ---- 8: reviewers, dedupe keys, number edges, odd statuses, token tmp ------------------------------------------
def _record_and_label(srv, t, n=40):
    for i in range(n):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"a{i}", "reports": [rep(i % 2 == 0).model_dump(mode="json")]})
    return [{"artifact_id": f"a{i}", "defect": i % 2 == 0} for i in range(n)]


def test_a_promoter_or_a_stray_label_does_not_make_a_second_reviewer(env):
    srv, t, tmp = env
    rows = _record_and_label(srv, t)
    call(srv, "POST", "/v1/pilot/labels", t["op"], {"labels": rows})
    assert call(srv, "POST", "/v1/pilot/promote", t["adm"], {"grader": "dsp", "to": "advisory"})[0] == 200
    call(srv, "POST", "/v1/pilot/labels/amend", t["adm"], {"labels": [{**rows[0], "defect": rows[0]["defect"]}]})
    st, d = call(srv, "POST", "/v1/pilot/promote", t["adm"], {"grader": "dsp", "to": "enforce"})
    assert st == 409 and ("reviewer" in d["error"] or "earned" in d["error"])
    # op2 labels ONE unrelated artifact only: still not a reviewer of the evidence
    for i in range(40, 41):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"a{i}", "reports": [rep(False).model_dump(mode="json")]})
    call(srv, "POST", "/v1/pilot/labels", t["op2"], {"labels": [{"artifact_id": "a40", "defect": False}]})
    st, d = call(srv, "GET", "/v1/pilot/evaluation", t["view"])
    assert d["reviewers"] == 1 and d["label_authors"] == 2


def test_requesters_cannot_squat_internal_dedupe_keys(tmp_path):
    jq = JobQueue(tmp_path / "j.sqlite")
    with pytest.raises(ValueError):
        jq.enqueue("t", "k", {}, dedupe_key="internal:notify:abc:1")
    jq.enqueue("t", "k", {}, dedupe_key="internal:notify:abc:1", internal=True)


def test_queue_row_cap_is_per_tenant_and_done_jobs_drop_their_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_JOBS_MAX_ROWS", "3")
    jq = JobQueue(tmp_path / "j.sqlite")
    for _ in range(3):
        jq.enqueue("t", "k", {"big": "x" * 1000})
    with pytest.raises(QuotaExceeded):
        jq.enqueue("t", "k", {})
    jq.enqueue("t2", "k", {})                                              # another tenant is not locked out
    j = jq.claim("w", ["k"])
    jq.complete(j, {})
    import sqlite3
    row = sqlite3.connect(jq.path).execute("SELECT payload FROM jobs WHERE id=?", (j.id,)).fetchone()
    assert row[0] == "{}"                                                  # finished jobs do not keep their payload


@pytest.mark.parametrize("op,value,fact,expect", [
    ("eq", 9007199254740993, 9007199254740992, Verdict.FAIL),
    ("eq", 48000, 48000.0, Verdict.PASS),
    ("ne", 0, -0.0, Verdict.FAIL)])
def test_exact_numeric_equality(tmp_path, op, value, fact, expect):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "rules": [{"id": "r", "path": "c", "op": op, "value": value}]}))
    (tmp_path / "f.json").write_text(json.dumps({"c": fact}))
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is expect


def test_between_with_ref_bounds_must_be_finite_numbers(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "rules": [
        {"id": "r", "path": "x", "op": "between", "value": [0, 1], "ref": "bounds"}]}))
    for bounds in (["-inf", "inf"], [float("1e999")] if False else ["a", "b"], [5, 1]):
        (tmp_path / "f.json").write_text(json.dumps({"x": 999, "bounds": bounds}))
        assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.FAIL


@pytest.mark.parametrize("status", [[{}], [{"code": ""}], [{"code": "  "}], ["str"], [5], "nope", 7, [None]])
def test_uninterpretable_validation_status_is_not_valid(status):
    d = {"active_manifest": "u", "validation_status": status, "manifests": {"u": {"assertions": []}}}
    assert parse_manifest_report(d).state == "invalid"


def test_token_file_writes_cannot_follow_a_planted_symlink(tmp_path):
    victim = tmp_path / "VICTIM"
    victim.write_text("precious")
    os.symlink(victim, tmp_path / "tokens.json.tmp")
    add_token(tmp_path / "tokens.json", id="a", role="viewer", tenant="t")
    assert victim.read_text() == "precious"
    assert not (tmp_path / "tokens.json").is_symlink()


# ---- observation: reads are cached, writes invalidate ---------------------------------------------------------
def test_verified_read_cache_is_invalidated_by_any_change(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(5):
        lg.append(Rec(n=i))
    time.sleep(0.2)                                                        # past the freshness window
    assert lg.verify() == 5 and lg.verify() == 5                           # second call served from cache
    assert (str(lg.path), "") in _chainlog._VERIFIED
    p = lg.path
    st = p.stat()
    p.write_text(p.read_text().replace('"n":3', '"n":9'))                 # same length edit
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))                       # mtime restored; ctime still moves
    with pytest.raises(LogCorrupt):
        lg.verify()
