"""Regression pins for red-team round 3 (log, service, policy, jobs, hot folder, webhooks, media)."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from verel import _chainlog
from verel._chainlog import ChainLog, ChainRecord, LogBusy, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.connectors import webhook as wh
from verel.connectors.hotfolder import HotFolder, scan_once
from verel.jobs import JobQueue, Worker, WorkerContext
from verel.jobs.queue import QuotaExceeded
from verel.media import grade_media
from verel.pilot import Label, ShadowLog, run_pilot
from verel.pilot.mode import Mode
from verel.pilot.policy import Policy, PolicyError, PolicyStore, autodemote, health
from verel.pilot.service import PilotServer
from verel.pilot.tenancy import policy_store
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rep(bad, grader=GraderKind.DSP):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss, grader=grader))


class Rec(ChainRecord):
    n: int
    blob: str = ""


# ---- 1: a stuck writer cannot park every other request ------------------------------------------------
def test_lock_wait_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(_chainlog, "LOCK_TIMEOUT_S", 0.3)
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    held = lg._lock()
    try:
        t0 = time.time()
        with pytest.raises(LogBusy):
            lg.append(Rec(n=1))
        assert time.time() - t0 < 3
    finally:
        os.close(held)
    lg.append(Rec(n=2))
    assert lg.verify() == 1


def test_batch_append_is_one_write_and_atomic_on_failure(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(n=0))

    def boom(existing):
        return [Rec(n=1), Rec(n=2, blob="x" * 400_000)]       # the second record is too large

    with pytest.raises(ValueError):
        lg.append_batch(boom)
    assert lg.verify() == 1                                   # all-or-nothing
    lg.append_batch(lambda e: [Rec(n=i) for i in range(1, 51)])
    assert lg.verify() == 51


def _post(srv, path, tok, body):
    req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _get(srv, path, tok):
    req = urllib.request.Request(srv.url + path, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


@pytest.fixture
def env(tmp_path):
    tf = tmp_path / "t.json"
    t = {k: add_token(tf, id=k, role=r, tenant=ten) for k, r, ten in (
        ("op", "operator", "acme"), ("op2", "operator", "acme"), ("op3", "operator", "acme"),
        ("view", "viewer", "acme"),
        ("adm", "admin", "acme"), ("gview", "viewer", "globex"), ("gop", "operator", "globex"))}
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    yield srv, t, tmp_path
    srv.stop()


def test_label_requests_are_capped_and_tenants_dont_starve_each_other(env):
    srv, t, _ = env
    assert _post(srv, "/v1/pilot/labels", t["op"],
                 {"labels": [{"artifact_id": f"x{i}", "defect": True} for i in range(501)]})[0] == 400
    st = [_get(srv, "/v1/pilot/verify", t["gview"])[0] for _ in range(5)]
    assert st == [200] * 5


def test_per_tenant_inflight_writes_are_limited(env):
    srv, t, _ = env
    import verel.pilot.service as svc
    assert svc.MAX_INFLIGHT_PER_TENANT >= 1
    results = []
    gate = threading.Barrier(24)

    def go(i):
        gate.wait()
        results.append(_post(srv, "/v1/pilot/record", t["op"], {"artifact_id": f"c{i}", "reports": [rep(False).model_dump(mode="json")]})[0])

    th = [threading.Thread(target=go, args=(i,)) for i in range(24)]
    [x.start() for x in th]
    [x.join() for x in th]
    assert set(results) <= {200, 429, 503} and 200 in results       # excess is refused fast, never parked


# ---- 2/3/4: hot folder ------------------------------------------------------------------------------
def _hf(tmp_path, **kw):
    root = tmp_path / "hf"
    (root / "incoming").mkdir(parents=True)
    (root / "spec.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
    kw.setdefault("settle_s", 0)
    return HotFolder(root=root, data_dir=tmp_path / "data", tenant="acme", spec="spec.json", **kw)


def _drop(hf, name, facts, data=b"media", bind=True, age=100):
    p = hf.root / "incoming" / name
    p.write_bytes(data)
    body = {**facts, "asset": {"sha256": hashlib.sha256(data).hexdigest()}} if bind else facts
    (hf.root / "incoming" / f"{name}.facts.json").write_text(json.dumps(body))
    os.utime(p, (time.time() - age,) * 2)
    return p


GOOD = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}
BAD = {"audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0}}


def test_hotfolder_tmp_symlink_cannot_clobber_a_file(tmp_path):
    hf = _hf(tmp_path)
    victim = tmp_path / "VICTIM.txt"
    victim.write_text("PRECIOUS")
    _drop(hf, "ep.mxf", GOOD)
    os.symlink(victim, hf.root / "incoming" / "ep.mxf.verel.json.tmp")
    scan_once(hf)
    assert victim.read_text() == "PRECIOUS"
    assert (hf.root / "incoming" / "ep.mxf.verel.json").exists()


def test_hotfolder_forged_sidecar_does_not_suppress_grading(tmp_path):
    hf = _hf(tmp_path, mode="enforce")
    p = _drop(hf, "bad.mxf", BAD)
    st = p.stat()
    forged = {"asset_sig": [st.st_size, st.st_mtime_ns], "would_be": "pass", "enforced": "pass",
              "report": {}, "mac": "0" * 64}
    (hf.root / "incoming" / "bad.mxf.verel.json").write_text(json.dumps(forged))
    out = scan_once(hf)
    assert out and out[0].action == "graded" and out[0].enforced == "fail"
    assert (hf.root / "quarantine" / "bad.mxf").exists()


def test_hotfolder_genuine_sidecar_still_suppresses_regrade(tmp_path):
    hf = _hf(tmp_path)
    _drop(hf, "ok.mxf", GOOD)
    assert scan_once(hf)[0].action == "graded"
    assert scan_once(hf) == []


def test_hotfolder_requires_facts_bound_to_the_file(tmp_path):
    hf = _hf(tmp_path, mode="enforce")
    _drop(hf, "unbound.mxf", GOOD, bind=False)
    out = scan_once(hf)
    assert out[0].enforced == "fail" and (hf.root / "quarantine" / "unbound.mxf").exists()
    # compliant facts copied onto a DIFFERENT file: the hash does not match
    donor = hashlib.sha256(b"the-good-file").hexdigest()
    p = hf.root / "incoming" / "evil.mxf"
    p.write_bytes(b"something-else")
    (hf.root / "incoming" / "evil.mxf.facts.json").write_text(json.dumps({**GOOD, "asset": {"sha256": donor}}))
    os.utime(p, (time.time() - 100,) * 2)
    out = {o.name: o for o in scan_once(hf)}
    assert out["evil.mxf"].enforced == "fail" and (hf.root / "quarantine" / "evil.mxf").exists()
    ok = _drop(hf, "fine.mxf", GOOD, data=b"fine")
    assert {o.name: o for o in scan_once(hf)}["fine.mxf"].enforced == "pass" and ok is not None


def test_hotfolder_scan_work_is_bounded_and_fair(tmp_path):
    hf = _hf(tmp_path, max_per_scan=50, facts_timeout_s=10**9)
    for i in range(200):
        (hf.root / "incoming" / f"w{i:03d}.mxf").write_bytes(b"x")
        os.utime(hf.root / "incoming" / f"w{i:03d}.mxf", (time.time() - 100,) * 2)
    assert len(scan_once(hf)) <= 50
    _drop(hf, "zzz-last.mxf", GOOD, data=b"last")
    seen = set()
    for _ in range(6):                       # the rotating cursor reaches the file at the end of the list
        seen |= {o.name for o in scan_once(hf) if o.action == "graded"}
    assert "zzz-last.mxf" in seen


# ---- 5/6/7: policy ----------------------------------------------------------------------------------
def test_operator_labels_cannot_demote_a_grader(env):
    srv, t, tmp = env
    store = policy_store(tmp / "data", "acme")
    store.promote("dsp", "advisory", "a")
    store.promote("dsp", "enforce", "a", None, override_reason="bootstrap with sign-off from QC lead")
    for i in range(60):
        _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": f"f{i}", "reports": [rep(True).model_dump(mode="json")]})
    st, d = _post(srv, "/v1/pilot/labels", t["op2"], {"labels": [{"artifact_id": f"f{i}", "defect": False} for i in range(60)]})
    assert st == 200 and "autodemoted" not in d
    assert policy_store(tmp / "data", "acme").current().mode_for("dsp") is Mode.ENFORCE   # unchanged
    assert _post(srv, "/v1/pilot/health", t["op"], {})[0] == 403                          # operators can't trigger it
    st, d = _post(srv, "/v1/pilot/health", t["adm"], {})
    assert st == 200 and d["autodemoted"][0]["grader"] == "dsp"
    assert policy_store(tmp / "data", "acme").current().mode_for("dsp") is Mode.ADVISORY


def test_enforce_needs_labels_from_two_reviewers(env):
    srv, t, tmp = env
    for i in range(200):
        _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": f"a{i}", "reports": [rep(i % 2 == 0).model_dump(mode="json")]})
    rows = [{"artifact_id": f"a{i}", "defect": i % 2 == 0} for i in range(200)]
    _post(srv, "/v1/pilot/labels", t["op2"], {"labels": rows})            # one reviewer (not the recorder)
    assert _post(srv, "/v1/pilot/promote", t["adm"], {"grader": "dsp", "to": "advisory"})[0] == 200
    st, d = _post(srv, "/v1/pilot/promote", t["adm"], {"grader": "dsp", "to": "enforce"})
    assert st == 409 and "reviewer" in d["error"]
    st, d = _post(srv, "/v1/pilot/promote", t["adm"], {"grader": "dsp", "to": "enforce",
                                                         "override_reason": "regulator requires this control now"})
    assert st == 200 and d["overridden"] is True


def test_health_cannot_be_diluted_by_padding_with_passes(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    labels = []
    for i in range(40):                                  # 40 bad flags (all false alarms)
        labels.append(Label(artifact_id=f"bad{i}", defect=False))
        run_pilot([rep(True)], artifact_id=f"bad{i}", log=log)
    for i in range(400):                                 # then 400 clean passes to push them out of a window
        labels.append(Label(artifact_id=f"ok{i}", defect=False))
        run_pilot([rep(False)], artifact_id=f"ok{i}", log=log)
    pol = Policy(graders={"dsp": Mode.ENFORCE})
    h = health(log.records(), labels, pol, window=200)
    assert [x.healthy for x in h] == [False]


@pytest.mark.parametrize("bad", ["policy", "POLICY"])
def test_policy_cannot_be_a_grader_mode(tmp_path, bad):
    store = PolicyStore(tmp_path / "p.jsonl")
    with pytest.raises(PolicyError):
        store.demote("dsp", bad, "a", "why")
    with pytest.raises(PolicyError):
        store.promote("dsp", bad, "a")
    with pytest.raises(PolicyError):
        store.set_default(bad, "a")
    assert autodemote(store, [], []) == []


# ---- 8/9: jobs --------------------------------------------------------------------------------------
def _ctx(tmp_path, tenants=("acme", "globex")):
    base = tmp_path / "m"
    ctx_roots = {}
    for t in tenants:
        r = base / t
        r.mkdir(parents=True)
        (r / "strict.json").write_text(json.dumps({"version": 1, "profiles": ["ebu_r128"]}))
        (r / "lenient.json").write_text(json.dumps({"version": 1, "rules": [{"id": "x", "path": "z", "op": "present", "on_missing": "skip"}]}))
        (r / "a.mxf").write_bytes(b"asset-bytes")
        (r / "f.json").write_text(json.dumps({"audio": {"integrated_lufs": -5.0, "true_peak_dbtp": 3.0},
                                               "asset": {"sha256": hashlib.sha256(b"asset-bytes").hexdigest()}}))
        ctx_roots[t] = {"masters": r}
    return WorkerContext(data_dir=tmp_path / "data", roots=ctx_roots), base


def _run(jq, ctx, tenant, payload, kind="media_grade"):
    jid = jq.enqueue(tenant, kind, payload)
    Worker(jq, ctx).run_once()
    return jq.get(tenant, jid)


def test_jobs_cannot_pick_a_mode_when_the_tenant_has_a_policy(tmp_path):
    ctx, _ = _ctx(tmp_path)
    jq = JobQueue(tmp_path / "j.sqlite")
    ctx.pins[("acme", "masters", "spec")] = "strict.json"
    store = policy_store(ctx.data_dir, "acme")
    store.promote("media", "advisory", "a")
    store.promote("media", "enforce", "a", None, override_reason="bootstrap with sign-off from QC lead")
    base = {"root": "masters", "facts": ["f.json"], "asset": "a.mxf"}
    assert _run(jq, ctx, "acme", {**base, "artifact_id": "p1", "mode": "policy"})["result"]["enforced"] == "fail"
    for n, bad_mode in enumerate(("shadow", "advisory", "enforce", "bogus")):
        j = _run(jq, ctx, "acme", {**base, "artifact_id": f"m{n}", "mode": bad_mode})
        assert j["state"] == "dead" and j["result"] is None
    j = _run(jq, ctx, "acme", {**base, "artifact_id": "p2"})   # no mode at all means policy
    assert j["result"]["enforced"] == "fail"


def test_roots_are_bound_to_tenants_and_specs_can_be_pinned(tmp_path):
    ctx, base = _ctx(tmp_path)
    jq = JobQueue(tmp_path / "j.sqlite")
    ctx.roots = {"acme": {"masters": base / "acme"}}                      # globex has NO root
    p = {"root": "masters", "facts": ["f.json"], "spec": "strict.json", "artifact_id": "x", "asset": "a.mxf"}
    assert _run(jq, ctx, "acme", p)["state"] == "done"
    assert _run(jq, ctx, "globex", p)["state"] == "dead"                  # cannot use acme's root
    # a requester cannot swap a pinned spec for a lenient one
    ctx.pins[("acme", "masters", "spec")] = "strict.json"
    j = _run(jq, ctx, "acme", {**p, "spec": "lenient.json", "artifact_id": "x2"})
    assert j["state"] == "dead"
    assert _run(jq, ctx, "acme", {**p, "spec": "strict.json", "artifact_id": "x3"})["result"]["verdict"] == "fail"
    # enforcing modes require a pinned spec
    ctx.pins.clear()
    j = _run(jq, ctx, "acme", {**p, "mode": "enforce", "artifact_id": "y"})
    assert j["state"] == "dead"


def test_provenance_jobs_need_an_asset(tmp_path):
    ctx, base = _ctx(tmp_path)
    jq = JobQueue(tmp_path / "j.sqlite")
    (base / "acme" / "m.json").write_text(json.dumps({"active_manifest": "u", "validation_status": [],
                                                       "manifests": {"u": {"assertions": []}}}))
    j = _run(jq, ctx, "acme", {"root": "masters", "manifest_json": "m.json", "artifact_id": "p"}, "provenance_grade")
    assert j["state"] == "dead"


def test_job_errors_do_not_leak_server_paths(tmp_path):
    ctx, base = _ctx(tmp_path)
    jq = JobQueue(tmp_path / "j.sqlite")
    p = {"root": "masters", "facts": ["f.json"], "spec": "strict.json", "artifact_id": "x", "asset": "a" * 300}
    j = _run(jq, ctx, "acme", p)
    assert str(base) not in json.dumps(j) and "Errno" not in json.dumps(j)
    j = _run(jq, ctx, "acme", {**p, "asset": 5})
    assert j["state"] == "dead"


def test_queue_quota_fairness_and_retention(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_JOBS_MAX_PENDING", "5")
    jq = JobQueue(tmp_path / "j.sqlite")
    for i in range(5):
        jq.enqueue("a", "k", {"i": i})
    with pytest.raises(QuotaExceeded):
        jq.enqueue("a", "k", {})
    jq.enqueue("a", "k", {}, internal=True)                               # follow-up jobs are exempt
    jq.enqueue("b", "k", {"mine": True})                                  # another tenant is unaffected
    first = jq.claim("w1", ["k"])
    second = jq.claim("w2", ["k"])
    assert {first.tenant, second.tenant} == {"a", "b"}                    # b is not stuck behind a's backlog
    jq.complete(first, {})
    jq.complete(second, {})
    assert jq.purge(0, now=time.time() + 1) == 2
    assert jq.stats("a")["done"] == 0


def test_deeply_nested_payload_is_refused(tmp_path):
    jq = JobQueue(tmp_path / "j.sqlite")
    deep: dict = {}
    cur = deep
    for _ in range(40):
        cur["x"] = {}
        cur = cur["x"]
    with pytest.raises(ValueError):
        jq.enqueue("t", "k", deep)


# ---- 11: torn writes ---------------------------------------------------------------------------------
def test_torn_write_is_rolled_back_and_a_torn_tail_is_repaired(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(n=1))
    lg.append(Rec(n=2))
    # a crash left a partial final line that never reached the ledger
    with open(lg.path, "a") as f:
        f.write('{"prev_hash":"abc","hash":"def","mac":"x","n":3')
    assert lg.verify() == 2                      # readers ignore the torn tail
    lg.append(Rec(n=3))                          # the next writer repairs it
    assert lg.verify() == 3 and lg.path.read_text().endswith("\n")
    # truncating a COMMITTED record is still detected
    lines = lg.path.read_text().splitlines()
    lg.path.write_text("\n".join(lines[:-1]) + "\n" + lines[-1][:30])
    with pytest.raises(LogCorrupt):
        lg.verify()


def test_short_write_under_a_file_size_limit_leaves_no_torn_record(tmp_path):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(3):
        lg.append(Rec(n=i))
    size = lg.path.stat().st_size
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    import signal
    old = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (size + 40, hard))
    try:
        with pytest.raises(OSError):
            lg.append(Rec(n=99))
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        signal.signal(signal.SIGXFSZ, old)
    assert lg.verify() == 3 and lg.path.stat().st_size == size            # rolled back, still appendable
    lg.append(Rec(n=4))
    assert lg.verify() == 4


# ---- 12: read-only tokens cannot fill the audit log; archive works on every log -------------------------
def test_reads_are_not_audited_and_audit_log_can_be_archived(env):
    srv, t, tmp = env
    audit = tmp / "data/tenants/acme/audit.jsonl"
    _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": "r1", "reports": [rep(False).model_dump(mode="json")]})
    before = audit.read_text().count("\n")
    for _ in range(25):
        assert _get(srv, "/v1/pilot/verify", t["view"])[0] == 200
        assert _get(srv, "/v1/pilot/evaluation", t["view"])[0] == 200
    assert audit.read_text().count("\n") == before                        # a viewer cannot grow it
    assert _post(srv, "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "audit"})[0] == 200
    assert _post(srv, "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "labels"})[0] == 200
    assert _post(srv, "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "nope"})[0] == 400


def test_full_audit_log_does_not_block_archiving_it(env, monkeypatch):
    srv, t, tmp = env
    for i in range(3):
        _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": f"f{i}", "reports": [rep(False).model_dump(mode="json")]})
    monkeypatch.setattr(_chainlog, "MAX_RECORDS", 3)
    assert _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": "x", "reports": [rep(False).model_dump(mode="json")]})[0] == 503
    assert _post(srv, "/v1/pilot/archive", t["adm"], {"keep_last": 0, "log": "audit"})[0] == 200
    assert _post(srv, "/v1/pilot/record", t["op"], {"artifact_id": "y", "reports": [rep(False).model_dump(mode="json")]})[0] in (200, 503)


# ---- 13: numbers ------------------------------------------------------------------------------------
@pytest.mark.parametrize("op,value,fact,expect", [
    ("ne", 0, 0.0, Verdict.FAIL), ("not_in", [0], 0.0, Verdict.FAIL),
    ("eq", 48000, 48000.0, Verdict.PASS), ("in", [48000], 48000.0, Verdict.PASS),
    ("ne", 1, True, Verdict.PASS), ("eq", 1, True, Verdict.FAIL)])
def test_numeric_equality_ignores_int_vs_float_but_not_bool(tmp_path, op, value, fact, expect):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "rules": [{"id": "r", "path": "c", "op": op, "value": value}]}))
    (tmp_path / "f.json").write_text(json.dumps({"c": fact}))
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is expect


# ---- 16: webhooks -----------------------------------------------------------------------------------
def test_webhook_event_id_is_signed_and_non_ascii_signature_is_a_no_not_a_crash():
    assert wh.verify_signature("k", str(int(time.time())), b"{}", "é" * 70) is False
    seen = {}

    class S:
        pass

    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            seen.update(body=json.loads(body), hdr=self.headers["X-Verel-Event-Id"])
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        wh.deliver(wh.Sink(f"http://127.0.0.1:{srv.server_address[1]}/x", "k", allow_http=True), {"a": 1})
    finally:
        srv.shutdown()
    assert seen["hdr"] == seen["body"]["event_id"]                        # the header is a copy of a signed field


def test_cli_hotfolder_output_is_terminal_safe(tmp_path, capsys):
    from verel.cli import main
    hf = _hf(tmp_path)
    name = "ev\x1b]0;pwned\x07il.mxf"
    _drop(hf, name, GOOD)
    assert main(["hotfolder", "--root", str(hf.root), "--data-dir", str(tmp_path / "data"), "--tenant", "acme",
                 "--spec", "spec.json", "--once", "--settle-s", "0"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "would-be" in out
    _ = Path
