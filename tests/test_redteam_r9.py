"""Regression pins for red-team round 9."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

from verel._chainlog import ChainLog, LogCorrupt
from verel.auth import Authenticator, TokenStore, add_token
from verel.cli import main
from verel.media import grade_media
from verel.media.demo import BROKEN, FIXED, SPEC
from verel.pilot import ShadowLog, run_pilot
from verel.pilot.log import ShadowRecord
from verel.pilot.service import PilotServer
from verel.pilot.tenancy import LabelRecord, label_log
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def rec(i):
    return ShadowRecord(artifact_id=f"a{i}", ts="t", mode="shadow", would_be="pass", enforced="pass")


def rep(grader=GraderKind.DSP, bad=False):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a", source=grader)]
    return assign(
        Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss if bad else [], grader=grader)
    )


# ---- F1: a ledger failure AFTER the live log was replaced must never delete the archived records -------------------
def test_archive_ledger_failure_keeps_segment_and_ids_and_recovers(tmp_path, monkeypatch):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(5):
        log.append_unique(rec(i))
    real, calls = ChainLog._write_ledger, {"n": 0}

    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:  # ENOSPC once, on the ledger write that follows the live-log replace
            raise OSError(28, "No space left on device")
        return real(self, *a, **k)

    monkeypatch.setattr(ChainLog, "_write_ledger", flaky)
    with pytest.raises(OSError):
        log.archive_first(3, tmp_path / "s.archive")
    assert (tmp_path / "s.archive").exists()  # the only copy of the archived records survives
    assert log.verify() == 2 and log.archived_count() == 3 and log.missing_segments() == []
    assert log.archived_has("a0")
    with pytest.raises(Exception):  # the retired id is still retired
        log.append_unique(rec(0))
    log.append_unique(rec(9))  # and the log keeps working


def test_archive_that_fails_before_the_replace_still_rolls_back(tmp_path, monkeypatch):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(5):
        log.append_unique(rec(i))
    import verel._chainlog as cl

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cl, "_write_atomic", boom)
    with pytest.raises(OSError):
        log.archive_first(3, tmp_path / "s.archive")
    monkeypatch.undo()
    assert not (tmp_path / "s.archive").exists() and log.verify() == 5 and not log.archived_has("a0")


# ---- F6: splicing a segment back in front of the live records is detected -----------------------------------------
def test_unarchive_by_splicing_the_segment_is_detected(tmp_path):
    p = tmp_path / "l.jsonl"
    log = ShadowLog(p)
    for i in range(6):
        log.append_unique(rec(i))
    log.archive_first(4, tmp_path / "s.archive")
    seg = (tmp_path / "s.archive").read_text().splitlines()
    live = p.read_text().splitlines()
    p.write_text("\n".join(seg + live[1:]) + "\n")
    (tmp_path / "s.archive").unlink()
    with pytest.raises(LogCorrupt):
        log.verify()


# ---- F3: every facts file must name the asset, not just one of them ---------------------------------------------
def test_one_binding_file_cannot_bind_another_files_measurements(tmp_path):
    (tmp_path / "spec.json").write_text(json.dumps(SPEC))
    (tmp_path / "ep1.mxf").write_bytes(b"real asset bytes, loud and late")
    sha = hashlib.sha256((tmp_path / "ep1.mxf").read_bytes()).hexdigest()
    (tmp_path / "ep1.sha.json").write_text(json.dumps({"asset": {"sha256": sha}}))
    (tmp_path / "other.json").write_text(json.dumps(FIXED))  # measured from a DIFFERENT file, names nothing
    r = grade_media(
        str(tmp_path), facts=["ep1.sha.json", "other.json"], spec="spec.json", asset="ep1.mxf",
        require_asset_binding=True,
    )
    assert r.verdict is Verdict.FAIL and "facts_bound" not in r.artifacts
    (tmp_path / "ep1.facts.json").write_text(json.dumps({**BROKEN, "asset": {"sha256": sha}}))
    ok = grade_media(
        str(tmp_path), facts=["ep1.facts.json"], spec="spec.json", asset="ep1.mxf", require_asset_binding=True
    )
    assert ok.artifacts.get("facts_bound") == "1"


# ---- F5: `bound` is only believed from a trusted in-process grader ----------------------------------------------
def test_bound_claim_from_a_caller_supplied_report_is_ignored(tmp_path):
    r = rep(GraderKind.MEDIA)
    r.artifacts["facts_bound"] = "1"
    log = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([r], artifact_id="x1", log=log, ref="hotfolder", recorded_by="hotfolder")
    run_pilot([r], artifact_id="x2", log=log, trusted=True)
    got = {x.artifact_id: x.bound for x in log.records()}
    assert got == {"x1": False, "x2": True}


# ---- F4: `verel pilot repair|verify|archive --kind labels` ------------------------------------------------------
def test_cli_can_verify_and_repair_a_label_log(tmp_path):
    root = tmp_path / "data"
    env = {**os.environ, "VEREL_LOG_FSYNC": "all"}
    child = r'''
import os, sys
from pathlib import Path
from verel.pilot.tenancy import label_log, LabelRecord
ll = label_log(Path(sys.argv[1]), "acme")
ll.append_batch(lambda ex: [LabelRecord(ts="t", by="op2", artifact_id=f"a{i}", defect=False) for i in range(3)])
real = os.fdopen
def fdopen(fd, *a, **k):
    fh = real(fd, *a, **k)
    if a and a[0] == "a":
        w = fh.write
        def partial(s):
            w("\n".join(s.split("\n")[:2]) + "\n"); fh.flush(); os.fsync(fd); os._exit(9)
        fh.write = partial
    return fh
os.fdopen = fdopen
ll.append_batch(lambda ex: [LabelRecord(ts="t", by="op2", artifact_id=f"b{i}", defect=True) for i in range(5)])
'''
    assert subprocess.run([sys.executable, "-c", child, str(root)], env=env).returncode == 9
    lp = str(root / "tenants" / "acme" / "labels.jsonl")
    base = ["--log", lp, "--domain", "acme/labels", "--kind", "labels"]
    assert main(["pilot", "verify", *base]) == 2  # interrupted batch is reported, not crashed on
    assert main(["pilot", "repair", *base]) == 0
    assert main(["pilot", "verify", *base]) == 0
    assert label_log(root, "acme").verify() == 3 and LabelRecord  # the three committed labels survive


# ---- F2: reviewers are counted over the labels that actually score evidence --------------------------------------
def test_reviewer_count_ignores_labels_that_score_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_EVIDENCE_ALLOW_SELF_REPORTED", "1")
    tf = tmp_path / "t.json"
    op = add_token(tf, id="op", role="operator", tenant="acme")
    op2 = add_token(tf, id="op2", role="operator", tenant="acme")
    adm = add_token(tf, id="adm", role="admin", tenant="acme")
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()

    def call(m, path, tok, b=None):
        r = urllib.request.Request(
            srv.url + path, data=json.dumps(b).encode() if b is not None else None, method=m,
            headers={"Authorization": f"Bearer {tok}"},
        )
        try:
            with urllib.request.urlopen(r, timeout=15) as x:
                return x.status, json.loads(x.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    try:
        for i in range(200):
            call("POST", "/v1/pilot/record", op, {"artifact_id": f"a{i}", "reports": [rep(bad=i % 2 == 0).model_dump(mode="json")]})
        call("POST", "/v1/pilot/labels", op2, {"labels": [{"artifact_id": f"a{i}", "defect": i % 2 == 0} for i in range(200)]})
        assert call("POST", "/v1/pilot/promote", adm, {"grader": "dsp", "to": "advisory"})[0] == 200
        for i in range(30):
            call("POST", "/v1/pilot/record", op, {"artifact_id": f"b{i}", "reports": [rep().model_dump(mode="json")]})
        # op labels only ITS OWN decisions: those labels are dropped from scoring, so op is not a second reviewer
        call("POST", "/v1/pilot/labels", op, {"labels": [{"artifact_id": f"b{i}", "defect": False} for i in range(30)]})
        st, body = call("POST", "/v1/pilot/promote", adm, {"grader": "dsp", "to": "enforce"})
        assert st == 409 and "reviewer" in json.dumps(body)
    finally:
        srv.stop()
