"""Regression pins for red-team round 2 (service, evidence log, media, provenance)."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from verel._chainlog import ChainLog, ChainRecord, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.auth.rbac import parse_role
from verel.media import grade_media, grade_provenance, parse_manifest_report
from verel.pilot import ShadowLog, run_pilot
from verel.pilot.service import PilotServer
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def _rep(bad, fp=None):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a",
                 source=GraderKind.DSP)] if bad else []
    r = assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss, grader=GraderKind.DSP))
    if fp is not None and r.issues:
        r.issues[0].fingerprint = fp
    return r.model_dump(mode="json")


@pytest.fixture
def env(tmp_path):
    tf = tmp_path / "tokens.json"
    t = {"op": add_token(tf, id="op", role="operator", tenant="acme"),
         "view": add_token(tf, id="view", role="viewer", tenant="acme"),
         "adm": add_token(tf, id="adm", role="admin", tenant="acme"),
         "gop": add_token(tf, id="gop", role="operator", tenant="globex"),
         "op2": add_token(tf, id="op2", role="operator", tenant="acme")}
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    yield srv, t, tmp_path
    srv.stop()


def call(srv, method, path, token=None, body=None):
    req = urllib.request.Request(srv.url + path, data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ---- F1: unauthenticated traffic must not write to (or slow down) anyone's evidence -------------------
def test_f1_anonymous_requests_write_nothing_persistent(env):
    srv, t, tmp = env
    before = {p: p.stat().st_size for p in (tmp / "data").rglob("*") if p.is_file()}
    for _ in range(50):
        assert call(srv, "GET", "/v1/pilot/verify", "vrl_" + "z" * 43)[0] == 401
        assert call(srv, "POST", "/v1/pilot/record", None, {})[0] == 401
    after = {p: p.stat().st_size for p in (tmp / "data").rglob("*") if p.is_file()}
    assert before == after and srv.stats["unauthenticated"] == 100


def test_f1_append_is_constant_time_not_quadratic(tmp_path):
    class Rec(ChainRecord):
        n: int

    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    t0 = time.time()
    for i in range(1500):
        lg.append(Rec(n=i))
    assert time.time() - t0 < 25                    # O(n) per append would need many minutes
    assert lg.verify() == 1500                      # and the full chain still verifies


# ---- F2: one request must not brick a tenant's logs ---------------------------------------------------
def test_f2_giant_label_and_fingerprint_cannot_brick_logs(env):
    srv, t, _ = env
    assert call(srv, "POST", "/v1/pilot/labels", t["op"], {"labels": [{"artifact_id": "A" * 1_200_000, "defect": True}]})[0] == 400
    st, d = call(srv, "POST", "/v1/pilot/record", t["gop"], {"artifact_id": "ok", "reports": [_rep(True, fp="f" * 1_200_000)]})
    assert st == 200
    assert call(srv, "GET", "/v1/pilot/verify", t["gop"])[0] == 200
    assert call(srv, "POST", "/v1/pilot/record", t["gop"], {"artifact_id": "ok2", "reports": [_rep(True)]})[0] == 200
    assert call(srv, "GET", "/v1/pilot/evaluation", t["view"])[0] == 200


def test_f2_oversized_record_refused_before_writing(tmp_path):
    class Rec(ChainRecord):
        blob: str

    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    lg.append(Rec(blob="ok"))
    with pytest.raises(ValueError):
        lg.append(Rec(blob="x" * 400_000))
    assert lg.verify() == 1


# ---- F3: conflicting labels cannot both land ---------------------------------------------------------
def test_f3_concurrent_conflicting_labels(env):
    srv, t, tmp = env
    ids = [f"race{i}" for i in range(20)]
    for i in ids:
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": i, "reports": [_rep(False)]})
    barrier = threading.Barrier(2)

    def post(defect):
        barrier.wait()
        for i in ids:
            call(srv, "POST", "/v1/pilot/labels", t["op"], {"labels": [{"artifact_id": i, "defect": defect}]})

    th = [threading.Thread(target=post, args=(d,)) for d in (True, False)]
    [x.start() for x in th]
    [x.join() for x in th]
    from verel.pilot.tenancy import label_log
    recs = label_log(tmp / "data", "acme").records()
    by = {}
    for r in recs:
        by.setdefault(r.artifact_id, set()).add(r.defect)
    assert len(recs) == 20 and all(len(v) == 1 for v in by.values())      # exactly one label per artifact


# ---- F4: a viewer cannot weaken the readiness thresholds ---------------------------------------------
def test_f4_weaker_or_nan_thresholds_do_not_manufacture_readiness(env):
    srv, t, _ = env
    for i in range(3):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"e{i}", "reports": [_rep(True)]})
    call(srv, "POST", "/v1/pilot/labels", t["op2"], {"labels": [{"artifact_id": f"e{i}", "defect": True} for i in range(3)]})
    st, ev = call(srv, "GET", "/v1/pilot/evaluation?min_samples=1&min_precision=0&min_recall=0&max_errored_rate=1", t["view"])
    assert st == 200 and ev["graders"][0]["ready_to_enforce"] is False and ev["min_samples"] == 30
    assert call(srv, "GET", "/v1/pilot/evaluation?min_precision=nan", t["view"])[0] == 400
    assert call(srv, "GET", "/v1/pilot/evaluation?min_samples=inf", t["view"])[0] == 400
    assert ev["label_authors"] == 1


# ---- F5 / F6 / F7: media + provenance ---------------------------------------------------------------
def _spec(tmp_path, rule):
    (tmp_path / "s.json").write_text(json.dumps({"version": 1, "rules": [rule]}))


@pytest.mark.parametrize("facts", [{"c": True}, {"c": ["mono"]}, {"c": {"x": "mono"}}])
def test_f5_not_in_never_fails_open(tmp_path, facts):
    _spec(tmp_path, {"id": "r", "path": "c", "op": "not_in", "value": [True, "mono"]})
    (tmp_path / "f.json").write_text(json.dumps(facts))
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.FAIL if facts["c"] is not True \
        else grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.FAIL


def test_f5_not_in_and_in_semantics_for_plain_scalars(tmp_path):
    _spec(tmp_path, {"id": "r", "path": "c", "op": "not_in", "value": ["mono"]})
    (tmp_path / "f.json").write_text('{"c": "stereo"}')
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.PASS
    (tmp_path / "f.json").write_text('{"c": "mono"}')
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.FAIL
    _spec(tmp_path, {"id": "r", "path": "c", "op": "ne", "value": 1})
    (tmp_path / "f.json").write_text('{"c": true}')
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.json").verdict is Verdict.PASS   # True is not 1


@pytest.mark.parametrize("code", ["claimSignature.mismatch", "claimSignature.missing", "signingCredential.ocsp.revoked",
                                  "timeStamp.outsideValidity", "algorithm.unsupported", "general.error", "brand.new.code"])
def test_f6_unknown_or_signature_failure_codes_are_invalid(code):
    d = {"active_manifest": "u:1", "validation_status": [{"code": code}], "validation_state": "Valid",
         "manifests": {"u:1": {"assertions": []}}}
    assert parse_manifest_report(d).state == "invalid"


@pytest.mark.parametrize("code", ["claimSignature.validated", "assertion.hashedURI.match", "assertion.dataHash.match",
                                  "signingCredential.trusted", "timeStamp.validated"])
def test_f6_known_success_codes_stay_valid(code):
    d = {"active_manifest": "u:1", "validation_status": [{"code": code}],
         "manifests": {"u:1": {"assertions": []}}}
    assert parse_manifest_report(d).state == "valid"


def test_f7_fabricated_report_with_unrelated_asset_is_caught(tmp_path):
    fake = {"active_manifest": "u:1", "validation_status": [], "validation_state": "Trusted",
            "manifests": {"u:1": {"signature_info": {"issuer": "Trusted News"}, "assertions": []}}}
    (tmp_path / "m.json").write_text(json.dumps(fake))
    (tmp_path / "a.mp4").write_bytes(b"unrelated")
    real = {"active_manifest": "u:9", "validation_status": [], "manifests": {"u:9": {"assertions": []}}}
    r = grade_provenance(str(tmp_path), manifest_json="m.json", asset="a.mp4", reader=lambda p: real)
    assert r.verdict is Verdict.FAIL and any("does not match" in i.message for i in r.issues)
    r = grade_provenance(str(tmp_path), manifest_json="m.json", asset="a.mp4", reader=lambda p: None)
    assert r.verdict is Verdict.FAIL
    alone = grade_provenance(str(tmp_path), manifest_json="m.json")
    assert any("unverified input" in i.message for i in alone.issues)


# ---- F8: planted symlinks cannot redirect our writes ------------------------------------------------
def test_f8_symlinks_cannot_redirect_writes(tmp_path):
    victim = tmp_path / "VICTIM.txt"
    victim.write_text("precious")
    log = ShadowLog(tmp_path / "pilot.jsonl", domain="d")
    run_pilot([Report.model_validate(_rep(False))], artifact_id="a", log=log)
    # a symlink at a predictable temp name is ignored (temp names are unique + O_EXCL)
    os.symlink(victim, tmp_path / "pilot.jsonl.head.tmp")
    os.symlink(victim, tmp_path / "pilot.jsonl.tmp")
    run_pilot([Report.model_validate(_rep(False))], artifact_id="b", log=log)
    assert victim.read_text() == "precious"
    # a symlink as the log / lock / ledger itself is refused
    for name in ("l2.jsonl", "l2.jsonl.lock"):
        os.symlink(victim, tmp_path / name)
    with pytest.raises((LogCorrupt, OSError)):
        run_pilot([Report.model_validate(_rep(False))], artifact_id="c", log=ShadowLog(tmp_path / "l2.jsonl"))
    assert victim.read_text() == "precious"


def test_f8_data_dir_must_be_private(tmp_path):
    from verel.pilot.tenancy import require_private_dir
    d = tmp_path / "pub"
    d.mkdir()
    os.chmod(d, 0o777)
    with pytest.raises(ValueError):
        require_private_dir(d)
    link = tmp_path / "ln"
    os.symlink(tmp_path, link)
    with pytest.raises(ValueError):
        require_private_dir(link)


# ---- F9: evidence is bound to its tenant/log, and lost segments are visible ---------------------------
def test_f9_evidence_cannot_be_moved_between_tenants(env):
    srv, t, tmp = env
    for i in range(3):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"acme-{i}", "reports": [_rep(True)]})
    call(srv, "POST", "/v1/pilot/record", t["gop"], {"artifact_id": "globex-1", "reports": [_rep(True)]})
    a, g = tmp / "data/tenants/acme", tmp / "data/tenants/globex"
    (g / "pilot.jsonl").write_text((a / "pilot.jsonl").read_text())
    (g / "pilot.jsonl.head").write_text((a / "pilot.jsonl.head").read_text())
    st, d = call(srv, "GET", "/v1/pilot/verify", t["gop"])
    assert st == 500 and "integrity" in d["error"]


def test_f9_missing_archive_segments_are_reported(env):
    srv, t, tmp = env
    for i in range(4):
        call(srv, "POST", "/v1/pilot/record", t["op"], {"artifact_id": f"e{i}", "reports": [_rep(False)]})
    assert call(srv, "POST", "/v1/pilot/archive", t["adm"], {"keep_last": 1})[0] == 200
    assert call(srv, "GET", "/v1/pilot/verify", t["view"])[1]["missing_archive_segments"] == []
    for f in (tmp / "data/tenants/acme").glob("pilot.*.archive"):
        f.unlink()
    st, d = call(srv, "GET", "/v1/pilot/verify", t["view"])
    assert st == 200 and len(d["missing_archive_segments"]) == 1


# ---- observations ------------------------------------------------------------------------------------
def test_idp_role_claims_must_be_exact():
    for bad in ("admin\n", " ADMIN", "Admin", "admin ", ["admin"], 1):
        with pytest.raises(ValueError):
            parse_role(bad, strict=True)
    assert parse_role("admin", strict=True).value == "admin"


def test_non_ascii_mac_is_corruption_not_a_crash(tmp_path):
    lg = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([Report.model_validate(_rep(False))], artifact_id="a", log=lg)
    run_pilot([Report.model_validate(_rep(False))], artifact_id="b", log=lg)
    lines = lg.path.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["mac"] = "é" * 64
    lines[0] = json.dumps(obj)
    lg.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LogCorrupt):
        lg.verify()


def test_log_fsync_modes(tmp_path, monkeypatch):
    class Rec(ChainRecord):
        n: int

    for mode in ("all", "record", "none", "bogus"):
        monkeypatch.setenv("VEREL_LOG_FSYNC", mode)
        lg = ChainLog(tmp_path / f"{mode}.jsonl", Rec)
        for i in range(3):
            lg.append(Rec(n=i))
        assert lg.verify() == 3
