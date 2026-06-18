"""Gate semantics (§7.1): dead-gate, hollow-gate attestation, advisory ceiling, precise gating."""

from verel.verdict import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    Report,
    RunReceipt,
    Severity,
    Verdict,
    assign,
    gate,
    sign_receipt,
)


def _report(grader, issues, *, errored=False, receipt=None):
    r = Report(verdict=Verdict.FAIL, summary="", issues=issues, grader=grader,
               errored=errored, run_receipt=receipt)
    return assign(r)


def _issue(kind, sev, source, conf=Confidence.MEDIUM, msg="x", loc="#a"):
    return Issue(kind=kind, severity=sev, message=msg, locator=loc, source=source, confidence=conf)


# ---- advisory ceiling -------------------------------------------------------
def test_vision_critical_cannot_escalate_past_warn():
    rep = _report(GraderKind.VISION, [_issue(IssueKind.LAYOUT, Severity.CRITICAL, GraderKind.VISION)])
    assert gate([rep]).verdict == Verdict.WARN


def test_dom_error_gates_to_fail():
    rep = _report(GraderKind.DOM, [_issue(IssueKind.OVERFLOW, Severity.ERROR, GraderKind.DOM)])
    assert gate([rep]).verdict == Verdict.FAIL


def test_low_confidence_precise_issue_is_clamped():
    rep = _report(GraderKind.DOM, [_issue(IssueKind.OVERFLOW, Severity.ERROR, GraderKind.DOM,
                                          conf=Confidence.LOW)])
    assert gate([rep]).verdict == Verdict.WARN


def test_clean_reports_pass():
    rep = _report(GraderKind.DOM, [_issue(IssueKind.CONTRAST, Severity.INFO, GraderKind.DOM)])
    assert gate([rep]).verdict == Verdict.PASS


# ---- dead gate --------------------------------------------------------------
def test_required_grader_absent_fails():
    rep = _report(GraderKind.DOM, [])
    res = gate([rep], required={GraderKind.SECURITY})
    assert res.verdict == Verdict.FAIL and "absent" in res.reason


def test_required_grader_errored_fails():
    rep = _report(GraderKind.SECURITY, [], errored=True)
    res = gate([rep], required={GraderKind.SECURITY})
    assert res.verdict == Verdict.FAIL


# ---- hollow gate (attestation) ---------------------------------------------
def _signed_receipt(suite_sha, files):
    rr = RunReceipt(suite_sha=suite_sha, inputs_digest="d",
                    coverage_assertion=f"scanned files: {','.join(files)}",
                    runner_identity="runner-x", signature="")
    rr.signature = sign_receipt(rr)
    return rr


def test_hollow_security_pass_without_receipt_fails():
    rep = _report(GraderKind.SECURITY, [])  # PASS, issues=[] but NO receipt
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.FAIL and "receipt" in res.reason


def test_attested_security_grader_passes():
    rr = _signed_receipt("abc", ["src/a.py"])
    rep = _report(GraderKind.SECURITY, [], receipt=rr)
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.PASS


def test_stale_suite_sha_fails():
    rr = _signed_receipt("OLD", ["src/a.py"])
    rep = _report(GraderKind.SECURITY, [], receipt=rr)
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "NEW"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.FAIL and "suite_sha" in res.reason


def test_grader_not_covering_diff_fails():
    rr = _signed_receipt("abc", ["src/other.py"])
    rep = _report(GraderKind.SECURITY, [], receipt=rr)
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.FAIL and "cover" in res.reason


def test_forged_signature_fails():
    rr = _signed_receipt("abc", ["src/a.py"])
    rr.signature = "deadbeef"  # tamper
    rep = _report(GraderKind.SECURITY, [], receipt=rr)
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.FAIL
