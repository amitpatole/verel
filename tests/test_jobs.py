"""verel.jobs: durable fenced queue + workers + signed webhooks + hot folder."""

from __future__ import annotations

import http.server
import json
import os
import threading
import time
from pathlib import Path

import pytest

from verel.connectors import webhook as wh
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue, LeaseLost, Worker, WorkerContext, backoff, run_pool
from verel.pilot.tenancy import pilot_log


# ------------------------------------------------------------------ queue
def q(tmp_path):
    return JobQueue(tmp_path / "jobs.sqlite")


def test_enqueue_claim_complete(tmp_path):
    jq = q(tmp_path)
    jid = jq.enqueue("acme", "media_grade", {"a": 1})
    j = jq.claim("w1", ["media_grade"])
    assert j and j.id == jid and j.attempts == 1 and j.payload == {"a": 1}
    assert jq.claim("w2", ["media_grade"]) is None                    # one worker per job
    jq.complete(j, {"ok": True})
    assert jq.get("acme", jid)["state"] == "done" and jq.stats("acme")["done"] == 1


def test_dedupe_is_idempotent_per_tenant(tmp_path):
    jq = q(tmp_path)
    a = jq.enqueue("acme", "k", {}, dedupe_key="ep-1")
    assert jq.enqueue("acme", "k", {}, dedupe_key="ep-1") == a
    assert jq.enqueue("globex", "k", {}, dedupe_key="ep-1") != a


def test_tenant_scoped_get(tmp_path):
    jq = q(tmp_path)
    jid = jq.enqueue("acme", "k", {})
    assert jq.get("globex", jid) is None and jq.get("acme", jid) is not None


@pytest.mark.parametrize("kind", ["", "a b", "x" * 65, "a;drop", "../x"])
def test_bad_kinds_rejected(tmp_path, kind):
    with pytest.raises(ValueError):
        q(tmp_path).enqueue("t", kind, {})


def test_payload_cap_and_sql_safety(tmp_path):
    jq = q(tmp_path)
    with pytest.raises(ValueError):
        jq.enqueue("t", "k", {"x": "y" * 300_000})
    jid = jq.enqueue("t'; DROP TABLE jobs;--", "k", {"q": "'; DROP TABLE jobs;--"}, dedupe_key="'--")
    assert jq.get("t'; DROP TABLE jobs;--", jid)["state"] == "queued"


def test_retry_backoff_then_dead(tmp_path):
    jq = q(tmp_path)
    jid = jq.enqueue("t", "k", {}, max_attempts=2, now=1000)
    j = jq.claim("w", ["k"], now=1000)
    assert jq.fail(j, "boom", now=1000) == "queued"
    assert jq.claim("w", ["k"], now=1000 + backoff(1) - 1) is None     # not yet runnable
    j2 = jq.claim("w", ["k"], now=1000 + backoff(1) + 1)
    assert j2 and j2.attempts == 2
    assert jq.fail(j2, "boom again", now=2000) == "dead"
    assert jq.get("t", jid)["state"] == "dead" and "boom again" in jq.get("t", jid)["error"]


def test_permanent_failure_is_dead_immediately(tmp_path):
    jq = q(tmp_path)
    j = (jq.enqueue("t", "k", {}), jq.claim("w", ["k"]))[1]
    assert jq.fail(j, "bad payload", permanent=True) == "dead"


def test_crashed_worker_job_is_requeued_then_exhausted(tmp_path):
    jq = q(tmp_path)
    jid = jq.enqueue("t", "k", {}, max_attempts=2, now=100)
    j1 = jq.claim("w1", ["k"], lease_s=10, now=100)
    assert jq.claim("w2", ["k"], now=105) is None                       # lease still valid
    j2 = jq.claim("w2", ["k"], now=200)                                  # w1 died: re-queued and re-claimed
    assert j2 and j2.id == jid and j2.attempts == 2 and j2.lease_owner == "w2"
    assert jq.claim("w3", ["k"], now=400) is None                        # attempts exhausted
    assert jq.get("t", jid)["state"] == "dead"
    _ = j1


def test_stale_worker_is_fenced_out(tmp_path):
    jq = q(tmp_path)
    jq.enqueue("t", "k", {}, now=100)
    old = jq.claim("w1", ["k"], lease_s=10, now=100)
    new = jq.claim("w2", ["k"], now=200)
    assert new.attempts == 2
    with pytest.raises(LeaseLost):
        jq.complete(old, {"stale": True})                                # cannot clobber the newer attempt
    with pytest.raises(LeaseLost):
        jq.fail(old, "stale")
    with pytest.raises(LeaseLost):
        jq.heartbeat(old)
    jq.complete(new, {"fresh": True})
    assert jq.get("t", new.id)["result"] == {"fresh": True}


def test_claim_is_exclusive_under_concurrency(tmp_path):
    jq = q(tmp_path)
    for i in range(60):
        jq.enqueue("t", "k", {"i": i})
    got: list[str] = []
    lock = threading.Lock()

    def work(n):
        while (j := q(tmp_path).claim(f"w{n}", ["k"])) is not None:
            with lock:
                got.append(j.id)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(got) == 60 and len(set(got)) == 60                        # every job claimed exactly once


def test_only_requested_kinds_are_claimed(tmp_path):
    jq = q(tmp_path)
    jq.enqueue("t", "other", {})
    assert jq.claim("w", ["media_grade"]) is None and jq.claim("w", []) is None


# ------------------------------------------------------------------ worker
def _setup(tmp_path):
    root = tmp_path / "media"
    root.mkdir()
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    (root / "good.json").write_text(json.dumps({"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}))
    (root / "bad.json").write_text(json.dumps({"audio": {"integrated_lufs": -10.0, "true_peak_dbtp": 1.0}}))
    jq = q(tmp_path)
    ctx = WorkerContext(data_dir=tmp_path / "data", roots={"acme": {"masters": root}, "globex": {"masters": root}})
    return jq, ctx, root


def test_worker_grades_and_records(tmp_path):
    jq, ctx, _ = _setup(tmp_path)
    g = jq.enqueue("acme", "media_grade", {"root": "masters", "facts": ["good.json"], "spec": "spec.json",
                                           "artifact_id": "ep-1"})
    b = jq.enqueue("acme", "media_grade", {"root": "masters", "facts": ["bad.json"], "spec": "spec.json",
                                           "artifact_id": "ep-2"})
    w = Worker(jq, ctx)
    assert w.run_once() and w.run_once() and not w.run_once()
    assert jq.get("acme", g)["result"]["verdict"] == "pass"
    r = jq.get("acme", b)["result"]
    assert r["verdict"] == "fail" and r["would_be"] == "fail" and r["enforced"] == "pass"   # shadow default
    recs = pilot_log(tmp_path / "data", "acme").records()
    assert [x.artifact_id for x in recs] == ["ep-1", "ep-2"]


@pytest.mark.parametrize("payload", [
    {"root": "nope", "facts": ["good.json"], "spec": "spec.json", "artifact_id": "x"},      # unknown root
    {"root": "masters", "facts": ["../../etc/passwd"], "spec": "spec.json", "artifact_id": "x"},  # traversal
    {"root": "masters", "facts": ["good.json"], "spec": "spec.json", "artifact_id": "bad id\n"},
    {"root": "masters", "facts": "good.json", "spec": "spec.json", "artifact_id": "x"},
    {"root": "masters", "facts": ["good.json"], "spec": "spec.json", "artifact_id": "x", "mode": "yolo"},
    {"root": "masters", "facts": ["good.json"], "spec": "spec.json", "artifact_id": "x", "notify": "evil"},
    {"root": "/etc", "facts": ["good.json"], "spec": "spec.json", "artifact_id": "x"},
])
def test_hostile_payloads_die_permanently_without_side_effects(tmp_path, payload):
    jq, ctx, _ = _setup(tmp_path)
    jid = jq.enqueue("acme", "media_grade", payload)
    Worker(jq, ctx).run_once()
    j = jq.get("acme", jid)
    assert j["state"] == "dead" and j["attempts"] == 1                                       # no retry storm
    path = tmp_path / "data/tenants/acme/pilot.jsonl"
    assert not path.exists() or all(r.artifact_id != "x" for r in pilot_log(tmp_path / "data", "acme").records())


def test_handler_crash_is_retried_not_fatal(tmp_path):
    jq, ctx, _ = _setup(tmp_path)

    def flaky(job, c):
        raise RuntimeError("transient")

    jid = jq.enqueue("t", "flaky", {})
    w = Worker(jq, ctx, handlers={"flaky": flaky})
    assert w.run_once()                                              # the worker survives the crash
    row = jq.get("t", jid)
    assert row["state"] == "queued" and row["attempts"] == 1 and "handler failed" in row["error"] and "transient" not in row["error"]
    again = jq.claim("w", ["flaky"], now=time.time() + backoff(1) + 1)
    assert again and again.attempts == 2


def test_pool_drains_queue(tmp_path):
    jq, ctx, _ = _setup(tmp_path)
    for i in range(12):
        jq.enqueue("acme", "media_grade", {"root": "masters", "facts": ["good.json"], "spec": "spec.json",
                                           "artifact_id": f"ep-{i}"})
    stop = threading.Event()
    run_pool(jq, ctx, concurrency=4, stop=stop, poll_s=0.05)
    for _ in range(100):
        if jq.stats("acme")["done"] == 12:
            break
        time.sleep(0.1)
    stop.set()
    assert jq.stats("acme")["done"] == 12
    assert len(pilot_log(tmp_path / "data", "acme").records()) == 12


# ------------------------------------------------------------------ webhooks
def test_signature_roundtrip_and_replay_window():
    body = b'{"a":1}'
    sig = wh.sign("s3cret", "1000", body)
    assert wh.verify_signature("s3cret", "1000", body, sig, now=1100)
    assert not wh.verify_signature("s3cret", "1000", body, sig, now=5000)                 # replay window
    assert not wh.verify_signature("wrong", "1000", body, sig, now=1100)
    assert not wh.verify_signature("s3cret", "1000", body + b" ", sig, now=1100)           # body tamper
    assert not wh.verify_signature("s3cret", "abc", body, sig, now=1100)
    assert not wh.verify_signature("s3cret", "1000", body, "", now=1100)


@pytest.mark.parametrize("sink", [
    wh.Sink("http://example.com/x", "s"),                          # http without opt-in
    wh.Sink("https://example.com/x", ""),                          # unsigned
    wh.Sink("file:///etc/passwd", "s"),
    wh.Sink("https://169.254.169.254/latest", "s"),                # cloud metadata
])
def test_deliver_refuses_unsafe_sinks(sink):
    with pytest.raises(wh.DeliveryError) as e:
        wh.deliver(sink, {"a": 1})
    assert e.value.permanent


def test_deliver_end_to_end_signed_and_no_redirects():
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.update(body=body, ts=self.headers["X-Verel-Timestamp"], sig=self.headers["X-Verel-Signature"])
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/")
                self.end_headers()
                return
            self.send_response(204 if self.path == "/ok" else 500)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert wh.deliver(wh.Sink(base + "/ok", "k", allow_http=True), {"x": 1}) == 204
        assert wh.verify_signature("k", got["ts"], got["body"], got["sig"])
        with pytest.raises(wh.DeliveryError) as e:
            wh.deliver(wh.Sink(base + "/boom", "k", allow_http=True), {"x": 1})
        assert not e.value.permanent                                  # 5xx is retried
        with pytest.raises(wh.DeliveryError):
            wh.deliver(wh.Sink(base + "/redir", "k", allow_http=True), {"x": 1})   # 3xx is not followed
    finally:
        srv.shutdown()


def test_worker_notify_enqueues_signed_webhook_to_configured_sink_only(tmp_path):
    from verel.jobs import BUILTIN
    jq, ctx, _ = _setup(tmp_path)
    ctx.sinks = {"acme": {"qc": wh.Sink("https://hooks.example.com/verel", "k")}}
    sent = []
    handlers = {**BUILTIN, "webhook": lambda job, c: sent.append(job.payload) or {"status": 204}}
    w = Worker(jq, ctx, handlers=handlers)
    mk = {"root": "masters", "facts": ["good.json"], "spec": "spec.json", "notify": "qc"}
    a = jq.enqueue("acme", "media_grade", {**mk, "artifact_id": "ep-1"})
    g = jq.enqueue("globex", "media_grade", {**mk, "artifact_id": "ep-9"})   # tenant without that sink
    while w.run_once():
        pass
    assert jq.get("acme", a)["state"] == "done"
    assert jq.get("globex", g)["state"] == "dead"                              # cannot borrow acme's sink
    assert len(sent) == 1 and sent[0]["sink"] == "qc" and sent[0]["event"]["tenant"] == "acme"
    assert "ep-1" not in json.dumps(sent[0])                                   # artifact id is hashed in events


# ------------------------------------------------------------------ hot folder
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, facts, age=100, bind=True):
    import hashlib
    p = hf.root / "incoming" / name
    p.write_bytes(b"media-bytes-" + name.encode())
    if facts is not None:
        body = {**facts, "asset": {"sha256": hashlib.sha256(p.read_bytes()).hexdigest()}} if bind else facts
        (hf.root / "incoming" / f"{name}.facts.json").write_text(json.dumps(body))
    old = time.time() - age
    os.utime(p, (old, old))
    return p


GOOD = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}
BAD = {"audio": {"integrated_lufs": -9.0, "true_peak_dbtp": 2.0}}


def test_hotfolder_shadow_never_moves_anything(tmp_path):
    hf = _hf(tmp_path)
    _drop(hf, "ok.mxf", GOOD)
    _drop(hf, "bad.mxf", BAD)
    out = {o.name: o for o in scan_once(hf)}
    assert out["bad.mxf"].would_be == "fail" and out["bad.mxf"].enforced == "pass" and not out["bad.mxf"].moved_to
    assert (hf.root / "incoming/bad.mxf").exists() and (hf.root / "incoming/bad.mxf.verel.json").exists()
    assert not (hf.root / "quarantine").exists()
    assert scan_once(hf) == []                                      # idempotent: already graded at this size/mtime


def test_hotfolder_enforce_routes_and_never_deletes(tmp_path):
    hf = _hf(tmp_path, mode="enforce")
    _drop(hf, "ok.mxf", GOOD)
    _drop(hf, "bad.mxf", BAD)
    scan_once(hf)
    assert (hf.root / "passed/ok.mxf").exists() and (hf.root / "passed/ok.mxf.verel.json").exists()
    assert (hf.root / "quarantine/bad.mxf").read_bytes().startswith(b"media-bytes-")
    assert not (hf.root / "incoming/bad.mxf").exists()
    # same name again: never overwrites what is already in quarantine
    _drop(hf, "bad.mxf", BAD)
    scan_once(hf)
    assert (hf.root / "quarantine/bad.mxf").exists() and (hf.root / "quarantine/bad-1.mxf").exists()


def test_hotfolder_advisory_never_quarantines(tmp_path):
    hf = _hf(tmp_path, mode="advisory")
    _drop(hf, "bad.mxf", BAD)
    scan_once(hf)
    assert (hf.root / "review/bad.mxf").exists() and not (hf.root / "quarantine").exists()


def test_hotfolder_missing_facts_wait_then_fail_closed(tmp_path):
    hf = _hf(tmp_path, mode="enforce", facts_timeout_s=3600)
    _drop(hf, "nofacts.mxf", None, age=10)
    t0 = time.time()
    assert scan_once(hf, now=t0)[0].action == "waiting"
    out = {o.name: o for o in scan_once(hf, now=t0 + 4000)}               # first seen 4000 s ago: overdue
    assert out["nofacts.mxf"].action == "graded" and out["nofacts.mxf"].enforced == "fail"
    assert (hf.root / "quarantine/nofacts.mxf").exists()                  # an unmeasured asset is never passed


def test_hotfolder_ignores_symlinks_temp_files_and_unsettled(tmp_path):
    hf = _hf(tmp_path, settle_s=60)
    secret = tmp_path / "secret.mxf"
    secret.write_bytes(b"x")
    os.symlink(secret, hf.root / "incoming/link.mxf")
    (hf.root / "incoming/.hidden.mxf").write_bytes(b"x")
    (hf.root / "incoming/half.mxf.part").write_bytes(b"x")
    _drop(hf, "fresh.mxf", GOOD, age=1)
    names = {o.name: o.action for o in scan_once(hf)}
    assert names.get("link.mxf") == "skipped" and names.get("fresh.mxf") == "settling"
    assert ".hidden.mxf" not in names and "half.mxf.part" not in names
    assert secret.exists() and not (hf.root / "quarantine").exists()


def test_hotfolder_changed_file_is_regraded(tmp_path):
    hf = _hf(tmp_path)
    p = _drop(hf, "ep.mxf", GOOD)
    scan_once(hf)
    p.write_bytes(b"different-bytes")
    old = time.time() - 100
    os.utime(p, (old, old))
    assert scan_once(hf)[0].action == "graded"


def test_hotfolder_hostile_names_cannot_escape(tmp_path):
    hf = _hf(tmp_path, mode="enforce")
    p = _drop(hf, "we ird;name$(x).mxf", BAD)
    scan_once(hf)
    assert any(Path(hf.root / "quarantine").iterdir()) and not p.exists()
    recs = pilot_log(tmp_path / "data", "acme").records()
    assert recs[0].artifact_id.startswith("hf:incoming/we_ird_name__x_.mxf")
