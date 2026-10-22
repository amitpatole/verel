"""Pilot-readiness pins: modes, tamper-evident log, evaluation math, CLI."""

from __future__ import annotations

import json

import pytest

from verel.cli import main
from verel.pilot import (
    Label,
    LogCorrupt,
    Mode,
    ShadowLog,
    apply_mode,
    evaluate,
    load_labels,
    parse_mode,
    run_pilot,
    wilson_lower,
)
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def _rep(bad: bool, grader=GraderKind.DSP, errored=False, sev=Severity.ERROR) -> Report:
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=sev, message="loud", locator="a@0", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss,
                         grader=grader, errored=errored))


# ---- modes -----------------------------------------------------------------
def test_mode_semantics():
    assert apply_mode(Verdict.FAIL, Mode.SHADOW) is Verdict.PASS
    assert apply_mode(Verdict.FAIL, Mode.ADVISORY) is Verdict.WARN
    assert apply_mode(Verdict.WARN, Mode.ADVISORY) is Verdict.WARN
    assert apply_mode(Verdict.FAIL, Mode.ENFORCE) is Verdict.FAIL


def test_unknown_mode_raises_not_defaults():
    with pytest.raises(ValueError):
        parse_mode("shadw")
    assert parse_mode(" ENFORCE ") is Mode.ENFORCE


def test_shadow_never_blocks_but_logs_real_verdict(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    d = run_pilot([_rep(True)], artifact_id="a1", mode="shadow", log=log)
    assert d.would_be is Verdict.FAIL and d.enforced is Verdict.PASS and not d.blocked
    r = log.records()[0]
    assert r.would_be is Verdict.FAIL and r.graders == {"dsp": "fail"} and r.fingerprints


def test_enforce_blocks():
    assert run_pilot([_rep(True)], artifact_id="a", mode="enforce").blocked


def test_gate_crash_fails_closed_and_is_recorded(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    # required grader with a bogus suite map forces the gate down a path; simulate crash directly
    import verel.pilot.shadow as sh
    orig = sh.gate
    sh.gate = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        d_enf = run_pilot([_rep(False)], artifact_id="a", mode="enforce", log=log)
        d_sh = run_pilot([_rep(False)], artifact_id="b", mode="shadow", log=log)
    finally:
        sh.gate = orig
    assert d_enf.blocked and d_enf.gate_error
    assert not d_sh.blocked and d_sh.gate_error and d_sh.would_be is Verdict.FAIL
    assert all(r.gate_error for r in log.records())


def test_worst_report_per_grader_wins(tmp_path):
    log = ShadowLog(tmp_path / "l.jsonl")
    run_pilot([_rep(True), _rep(False)], artifact_id="a", log=log)
    assert log.records()[0].graders["dsp"] == "fail"


@pytest.mark.parametrize("bad", ["a\nb", "", "x" * 300, "a b", "a;rm", "../../etc"[:0] + "a\x00b"])
def test_artifact_id_validated(bad, tmp_path):
    with pytest.raises(ValueError):
        run_pilot([_rep(False)], artifact_id=bad, log=ShadowLog(tmp_path / "l.jsonl"))


# ---- tamper-evident log ----------------------------------------------------
def _filled(tmp_path, n=4):
    log = ShadowLog(tmp_path / "l.jsonl")
    for i in range(n):
        run_pilot([_rep(i % 2 == 0)], artifact_id=f"a{i}", log=log)
    return log


def test_chain_verifies(tmp_path):
    assert _filled(tmp_path).verify() == 4


def test_edit_detected(tmp_path):
    log = _filled(tmp_path)
    txt = log.path.read_text().replace('"would_be":"fail"', '"would_be":"pass"', 1)
    log.path.write_text(txt)
    with pytest.raises(LogCorrupt):
        log.verify()


def test_delete_middle_and_reorder_detected(tmp_path):
    log = _filled(tmp_path)
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n")
    with pytest.raises(LogCorrupt):
        log.verify()
    log.path.write_text("\n".join([lines[1], lines[0], lines[2], lines[3]]) + "\n")
    with pytest.raises(LogCorrupt):
        log.verify()


def test_tail_truncation_caught_only_with_anchor(tmp_path):
    log = _filled(tmp_path)
    head = log.head()
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:-1]) + "\n")
    assert log.verify() == 3                       # self-contained chain can't see it...
    with pytest.raises(LogCorrupt):
        log.verify(expect_head=head)               # ...an external anchor does


def test_append_refuses_corrupt_chain(tmp_path):
    log = _filled(tmp_path)
    log.path.write_text(log.path.read_text().replace("a1", "zz", 1))
    with pytest.raises(LogCorrupt):
        run_pilot([_rep(False)], artifact_id="new", log=log)


def test_garbage_line_is_corruption(tmp_path):
    log = _filled(tmp_path, 1)
    with log.path.open("a") as f:
        f.write("not json\n")
    with pytest.raises(LogCorrupt):
        log.verify()


def test_log_file_private(tmp_path):
    log = _filled(tmp_path, 1)
    assert (log.path.stat().st_mode & 0o077) == 0


# ---- evaluation ------------------------------------------------------------
def test_wilson_penalises_small_samples():
    assert wilson_lower(5, 5) < wilson_lower(500, 500)
    assert wilson_lower(0, 0) == 0.0
    assert 0.0 <= wilson_lower(3, 10) <= 0.3


def _recs(tmp_path, spec, name="e.jsonl"):
    log = ShadowLog(tmp_path / name)
    for aid, reports in spec:
        run_pilot(reports, artifact_id=aid, log=log)
    return log.records()


def test_confusion_matrix(tmp_path):
    recs = _recs(tmp_path, [("a", [_rep(True)]), ("b", [_rep(True)]), ("c", [_rep(False)]), ("d", [_rep(False)])])
    ev = evaluate(recs, [Label(artifact_id="a", defect=True), Label(artifact_id="b", defect=False),
                         Label(artifact_id="c", defect=True), Label(artifact_id="d", defect=False)])
    s = ev.overall
    assert (s.tp, s.fp, s.fn, s.tn) == (1, 1, 1, 1)
    assert s.precision == 0.5 and s.recall == 0.5 and s.fpr == 0.5


def test_latest_record_wins_and_coverage_holes_counted(tmp_path):
    recs = _recs(tmp_path, [("a", [_rep(True)]), ("a", [_rep(False)]), ("zz", [_rep(False)])])
    ev = evaluate(recs, [Label(artifact_id="a", defect=False), Label(artifact_id="never", defect=True)])
    assert ev.overall.tn == 1 and ev.overall.fp == 0
    assert ev.unlabeled_records == 1 and ev.labels_without_record == 1


def test_errored_grader_excluded_not_counted_as_pass(tmp_path):
    recs = _recs(tmp_path, [("a", [_rep(False, errored=True)])])
    ev = evaluate(recs, [Label(artifact_id="a", defect=True)])
    g = ev.graders[0]
    assert g.errored == 1 and g.stats.n == 0 and g.stats.fn == 0 and not g.ready_to_enforce


def test_graduation_needs_samples_and_precision(tmp_path):
    few = _recs(tmp_path, [(f"a{i}", [_rep(True)]) for i in range(5)])
    labs = [Label(artifact_id=f"a{i}", defect=True) for i in range(5)]
    assert not evaluate(few, labs).graders[0].ready_to_enforce          # perfect but tiny sample
    many = _recs(tmp_path, [(f"b{i}", [_rep(True)]) for i in range(80)], name="m.jsonl")
    labs = [Label(artifact_id=f"b{i}", defect=True) for i in range(80)]
    assert evaluate(many, labs).graders[0].ready_to_enforce


def test_conflicting_labels_rejected(tmp_path):
    p = tmp_path / "lab.json"
    p.write_text(json.dumps([{"artifact_id": "a", "defect": True}, {"artifact_id": "a", "defect": False}]))
    with pytest.raises(ValueError):
        load_labels(p)


def test_labels_jsonl_and_bad_id(tmp_path):
    p = tmp_path / "lab.jsonl"
    p.write_text('{"artifact_id":"a","defect":true}\n{"artifact_id":"b","defect":false}\n')
    assert len(load_labels(p)) == 2
    p.write_text('{"artifact_id":"a\\nb","defect":true}\n')
    with pytest.raises(ValueError):
        load_labels(p)


# ---- CLI -------------------------------------------------------------------
def test_cli_record_eval_verify(tmp_path, capsys):
    log = str(tmp_path / "p.jsonl")
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps([_rep(True).model_dump(mode="json")]))
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x1", "--log", log]) == 0
    assert "PASS (would-be fail, mode shadow)" in capsys.readouterr().out
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x2", "--log", log,
                 "--mode", "enforce"]) == 1
    lab = tmp_path / "l.json"
    lab.write_text(json.dumps([{"artifact_id": "x1", "defect": True}, {"artifact_id": "x2", "defect": True}]))
    capsys.readouterr()
    assert main(["pilot", "eval", "--log", log, "--labels", str(lab), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["overall"]["tp"] == 2 and out["overall"]["precision"] == 1.0
    assert main(["pilot", "verify", "--log", log]) == 0


def test_cli_tampered_log_exits_2(tmp_path, capsys):
    log = tmp_path / "p.jsonl"
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(_rep(True).model_dump(mode="json")))
    main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x1", "--log", str(log)])
    log.write_text(log.read_text().replace("x1", "x9"))
    assert main(["pilot", "verify", "--log", str(log)]) == 2
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x2", "--log", str(log)]) == 2


def test_cli_bad_mode_exits_2(tmp_path):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps([_rep(False).model_dump(mode="json")]))
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x", "--mode", "shdow",
                 "--log", str(tmp_path / "l")]) == 2


def test_cli_demo(capsys):
    assert main(["pilot", "demo"]) == 0
    out = capsys.readouterr().out
    assert "Recommend graduating to ENFORCE: dsp" in out and "audio_llm" in out


def _proc_work(args):
    path, k = args
    for j in range(25):
        run_pilot([_rep(False)], artifact_id=f"w{k}-{j}", log=ShadowLog(path))


def test_concurrent_processes_keep_one_chain(tmp_path):
    """Without the append lock, parallel workers fork the chain (verified by disabling flock)."""
    import multiprocessing as mp
    path = str(tmp_path / "c.jsonl")
    with mp.get_context("fork").Pool(6) as pool:
        pool.map(_proc_work, [(path, k) for k in range(6)])
    assert ShadowLog(path).verify() == 150


def test_cli_deeply_nested_reports_json_exits_2(tmp_path):
    rp = tmp_path / "r.json"
    rp.write_text("[" * 100000 + "]" * 100000)
    assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", "x", "--log", str(tmp_path / "l")]) == 2
