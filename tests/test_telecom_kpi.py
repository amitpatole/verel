"""Phase 1 — telecom KPI/SLO vitals grader (deterministic threshold/regression gate over PM counters)."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("yaml", reason="telecom grader tests need verel[telecom] (pyyaml)")

from verel.ci.telecom_kpi import (
    builtin_profile,
    evaluate_kpis,
    frame_from_csv,
    frame_from_json,
    frame_from_openmetrics,
    grade_kpi,
    parse_frame,
)
from verel.ci.telecom_model import KpiThreshold, MetricFrame, MetricSample, load_thresholds
from verel.verdict.constants import PRECISE_GRADERS
from verel.verdict.gate import verify_signature
from verel.verdict.models import Confidence, GraderKind, IssueKind, Severity, Verdict


# --------------------------------------------------------------------------- adapters
def test_frame_from_json_list_and_flat():
    f = frame_from_json(json.dumps([{"kpi": "RM.RegInitSuccRate", "value": 0.91, "samples": 500}]))
    assert f.for_kpi("RM.RegInitSuccRate")[0].value == 0.91
    flat = frame_from_json(json.dumps({"metrics": {"DRB.UEThpDl": 120.0}}))
    assert flat.for_kpi("DRB.UEThpDl")[0].value == 120.0


def test_frame_from_csv_dims_and_samples():
    raw = "kpi,value,samples,cell\nRRC.ConnEstabSuccRate,0.97,800,cell-1\n"
    s = frame_from_csv(raw).for_kpi("RRC.ConnEstabSuccRate")[0]
    assert s.value == 0.97 and s.samples == 800 and s.dims == {"cell": "cell-1"}


def test_frame_from_openmetrics_maps_open5gs_names():
    raw = 'fivegs_amffunction_rm_reginitsucc{plmn="001-01"} 455\nfivegs_amffunction_rm_reginitreq 500\n# HELP x\n'
    f = frame_from_openmetrics(raw)
    kinds = {s.kpi for s in f.samples}
    assert kinds == {"RM.RegInitSucc", "RM.RegInitReq"}
    assert f.for_kpi("RM.RegInitSucc")[0].dims == {"plmn": "001-01"}


def test_parse_frame_autodetect():
    assert parse_frame('[{"kpi":"a","value":1}]').samples  # json
    assert parse_frame("kpi,value\na,1\n").samples  # csv


# --------------------------------------------------------------------------- thresholds
def test_load_thresholds_both_shapes():
    as_list = load_thresholds([{"kpi": "a", "min": 0.99}])
    as_map = load_thresholds({"a": {"min": 0.99}})
    assert as_list[0].kpi == as_map[0].kpi == "a" and as_list[0].min == 0.99


def test_kpi_kind_is_precise():
    assert GraderKind.KPI in PRECISE_GRADERS  # it gates


# --------------------------------------------------------------------------- evaluation
def _frame(kpi, value, samples=1000, dims=None):
    return MetricFrame(samples=[MetricSample(kpi=kpi, value=value, samples=samples, dims=dims or {})])


def test_breach_gates_at_error():
    issues = evaluate_kpis(_frame("RM.RegInitSuccRate", 0.91),
                           [KpiThreshold("RM.RegInitSuccRate", min=0.99, min_samples=200)])
    assert len(issues) == 1
    assert issues[0].severity == Severity.ERROR
    assert issues[0].kind == IssueKind.THRESHOLD_BREACH
    assert issues[0].source == GraderKind.KPI


def test_within_threshold_is_clean():
    assert evaluate_kpis(_frame("RM.RegInitSuccRate", 0.995),
                         [KpiThreshold("RM.RegInitSuccRate", min=0.99)]) == []


def test_lower_is_better_ceiling():
    issues = evaluate_kpis(_frame("RRU.PrbTotDl", 92.0),
                           [KpiThreshold("RRU.PrbTotDl", direction="lower_is_better", max=85.0)])
    assert issues and issues[0].severity == Severity.ERROR


def test_absent_counter_is_warning_never_pass():
    # fail closed: a threshold on a counter absent from the file must NOT pass silently
    issues = evaluate_kpis(MetricFrame(samples=[]), [KpiThreshold("RM.RegInitSuccRate", min=0.99)])
    assert issues and issues[0].severity == Severity.WARNING
    assert issues[0].confidence == Confidence.LOW
    assert "unmeasurable" in issues[0].message


def test_insufficient_samples_cannot_gate():
    # a breach computed over too few attempts is emitted LOW → clamps to WARNING (never fails a build)
    issues = evaluate_kpis(_frame("RM.RegInitSuccRate", 0.5, samples=10),
                           [KpiThreshold("RM.RegInitSuccRate", min=0.99, min_samples=200)])
    assert issues and issues[0].severity == Severity.WARNING
    assert issues[0].confidence == Confidence.LOW


def test_worst_cell_not_hidden_by_default():
    # two cells, one broken; worst aggregation surfaces the broken one
    frame = MetricFrame(samples=[
        MetricSample("RRC.ConnEstabSuccRate", 0.999, samples=900, dims={"cell": "good"}),
        MetricSample("RRC.ConnEstabSuccRate", 0.80, samples=900, dims={"cell": "bad"})])
    issues = evaluate_kpis(frame, [KpiThreshold("RRC.ConnEstabSuccRate", min=0.99, aggregation="worst")])
    assert issues and "cell=bad" in (issues[0].locator or "")


def test_baseline_regression_gates():
    now = _frame("MM.HoExeSuccRate", 0.985)
    base = _frame("MM.HoExeSuccRate", 0.995)
    issues = evaluate_kpis(now, [KpiThreshold("MM.HoExeSuccRate", max_delta_vs_baseline=0.005)], baseline=base)
    assert issues and issues[0].kind == IssueKind.BASELINE_REGRESSION
    assert issues[0].severity == Severity.ERROR


# --------------------------------------------------------------------------- end-to-end
def test_delta_only_rule_without_baseline_warns_never_silent_pass():
    # security (red-team R2): a max_delta_vs_baseline-only rule with NO baseline must NOT silently PASS.
    # It is unmeasurable → a non-gating WARNING (verdict WARN, not PASS).
    frame = _frame("K", 0.01, samples=100000)
    issues = evaluate_kpis(frame, [KpiThreshold("K", max_delta_vs_baseline=0.5)], baseline=None)
    assert issues and issues[0].kind == IssueKind.BASELINE_REGRESSION
    assert issues[0].severity == Severity.WARNING
    assert "no baseline" in issues[0].message


def test_grade_kpi_fail_then_pass_with_verifiable_receipt(tmp_path):
    (tmp_path / "kpi_broken.json").write_text(json.dumps(
        {"samples": [{"kpi": "RM.RegInitSuccRate", "value": 0.91, "samples": 5000}]}))
    (tmp_path / "kpi_fixed.json").write_text(json.dumps(
        {"samples": [{"kpi": "RM.RegInitSuccRate", "value": 0.995, "samples": 5000}]}))
    thresholds = {"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 200}}

    bad = grade_kpi(str(tmp_path), metrics="kpi_broken.json", thresholds=thresholds)
    assert bad.verdict == Verdict.FAIL
    assert bad.run_receipt is not None and verify_signature(bad.run_receipt)
    # grounded: names the canonical counter and cites the clause
    assert any("RM.RegInitSuccRate" in (i.locator or "") for i in bad.issues)
    assert any("28.552" in i.detail.get("clause", "") for i in bad.issues)

    good = grade_kpi(str(tmp_path), metrics="kpi_fixed.json", thresholds=thresholds)
    assert good.verdict == Verdict.PASS
    # the two receipts are bound to different inputs → different digests (no replay)
    assert bad.run_receipt.inputs_digest != good.run_receipt.inputs_digest


def test_bom_prefixed_artifact_still_gates(tmp_path):
    # security (red-team R3): a UTF-8 BOM (Excel/PowerShell emit it by default) must NOT downgrade a
    # real FAIL to a non-gating WARN by defeating format autodetect
    body = json.dumps([{"kpi": "RM.RegInitSuccRate", "value": 0.5, "samples": 9000}])
    (tmp_path / "bom.json").write_text("\ufeff" + body, encoding="utf-8")
    rep = grade_kpi(str(tmp_path), metrics="bom.json",
                    thresholds={"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 200}})
    assert rep.verdict == Verdict.FAIL
    # and the leading-NUL variant
    (tmp_path / "nul.json").write_text("\x00" + body, encoding="utf-8")
    assert grade_kpi(str(tmp_path), metrics="nul.json",
                     thresholds={"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 200}}).verdict == Verdict.FAIL


def test_nonempty_zero_sample_artifact_fails_closed(tmp_path):
    # a non-empty artifact that parses to zero samples is a format failure → gate ERROR, never WARN-pass
    (tmp_path / "junk.csv").write_text("not,a,valid,metrics,file\nfoo,bar,baz,qux,quux\n")
    rep = grade_kpi(str(tmp_path), metrics="junk.csv", thresholds={"RM.RegInitSuccRate": {"min": 0.99}})
    assert rep.verdict == Verdict.FAIL
    assert any(i.severity == Severity.ERROR for i in rep.issues)


def test_malformed_json_fails_closed_not_crash(tmp_path):
    import pytest
    (tmp_path / "bad.json").write_text('{"samples": [ {"kpi": ')  # truncated JSON
    with pytest.raises(ValueError, match="invalid JSON"):
        grade_kpi(str(tmp_path), metrics="bad.json", thresholds={"a": {"min": 1}})


def test_deeply_nested_json_fails_closed_not_recursionerror(tmp_path):
    # red-team R4: a deeply-nested JSON array must fail closed as a clean ValueError, not a raw
    # RecursionError traceback (RecursionError is not a JSONDecodeError → must be caught explicitly)
    import pytest
    (tmp_path / "deep.json").write_text("[" * 20000)
    with pytest.raises(ValueError, match="invalid JSON"):
        grade_kpi(str(tmp_path), metrics="deep.json", thresholds={"a": {"min": 1}})


def test_grade_kpi_path_traversal_refused(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="escapes the repo"):
        grade_kpi(str(tmp_path), metrics="../../../etc/passwd", thresholds={"a": {"min": 1}})


def test_nan_inf_value_is_unmeasurable_not_pass():
    # security: a NaN metric makes every comparison False → would silently PASS. Must be treated as
    # absent/unmeasurable → WARNING, never a gating-clean PASS.
    for bad in ("nan", "inf", "-inf", "NaN"):
        f = frame_from_json(json.dumps([{"kpi": "RM.RegInitSuccRate", "value": bad, "samples": 9000}]))
        issues = evaluate_kpis(f, [KpiThreshold("RM.RegInitSuccRate", min=0.99, min_samples=200)])
        assert issues and issues[0].severity == Severity.WARNING
        assert "unmeasurable" in issues[0].message


def test_garbage_bound_fails_closed():
    # security (Finding C): a PRESENT-but-uncoercible bound must RAISE, never silently disable the gate
    import pytest
    for bad in ("nan", "inf", "abc", "1e999"):
        with pytest.raises(ValueError):
            load_thresholds([{"kpi": "a", "max": bad}])


def test_no_bound_rule_rejected():
    # a rule with neither min/max nor a delta is a no-op gate → reject it (Finding C)
    import pytest
    with pytest.raises(ValueError, match="no bound"):
        load_thresholds([{"kpi": "a", "direction": "higher_is_better"}])


def test_ceiling_with_default_direction_still_catches_worst_cell():
    # security (Finding A): a max ceiling declared WITHOUT direction:lower_is_better must still catch
    # the highest cell (the old direction-only 'worst' returned the lowest cell → 5x breach passed)
    frame = MetricFrame(samples=[
        MetricSample("RRU.PrbTotDl", 10.0, samples=900, dims={"cell": "idle"}),
        MetricSample("RRU.PrbTotDl", 500.0, samples=900, dims={"cell": "hot"})])
    issues = evaluate_kpis(frame, [KpiThreshold("RRU.PrbTotDl", max=100.0)])  # default direction
    assert issues and issues[0].severity == Severity.ERROR
    assert "cell=hot" in (issues[0].locator or "")


def test_negative_denominator_clamped_to_zero():
    # security (Finding B): a negative injected 'samples' must not drag a well-sampled total below the
    # min_samples floor to downgrade a real breach — the adapter clamps it to 0 at parse time
    f = frame_from_json(json.dumps([{"kpi": "k", "value": 1, "samples": -100000}]))
    assert f.samples[0].samples == 0


def test_float_denominator_does_not_crash():
    # Finding E: Prometheus/JSON export counts as floats — accept, don't crash
    f = frame_from_json(json.dumps([{"kpi": "k", "value": 1, "samples": "100.0"}]))
    assert f.samples[0].samples == 100


def test_openmetrics_parse_bounded_on_adversarial_input():
    # ReDoS / resource guard: a large pathological scrape parses quickly and doesn't hang
    import time
    esc = "\\" * 50
    line = 'x_metric{a="' + esc + 'b"} 1'
    blob = "\n".join(line for _ in range(20000))
    t0 = time.monotonic()
    frame_from_openmetrics(blob)  # unmapped names → dropped; must not backtrack catastrophically
    assert time.monotonic() - t0 < 5.0


def test_builtin_profile_has_ran_and_core():
    prof = builtin_profile()
    domains = {m.domain for m in prof.values()}
    assert "ran" in domains and "core" in domains
    assert prof["RM.RegInitSuccRate"].clause.startswith("3GPP TS 28.552")
