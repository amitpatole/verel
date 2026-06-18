"""Progressed = STRICT subset shrinkage of the gating-failure set (§7.2). Equal-cardinality
swaps and growth are NOT progress; a new gating issue is a regression."""

from verel.verdict import (
    GraderKind,
    Issue,
    IssueKind,
    Report,
    Severity,
    Verdict,
    assign,
    gating_failures,
    progressed,
)


def _rep(*fingerprint_msgs):
    issues = [
        Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR, message=m, locator=f"#{m}",
              source=GraderKind.DOM)
        for m in fingerprint_msgs
    ]
    return assign(Report(verdict=Verdict.FAIL, summary="", issues=issues, grader=GraderKind.DOM))


def test_strict_shrink_is_progress():
    prev, curr = _rep("a", "b", "c"), _rep("a", "b")
    assert progressed(curr, prev)


def test_no_change_is_not_progress():
    prev, curr = _rep("a", "b"), _rep("a", "b")
    assert not progressed(curr, prev)


def test_equal_cardinality_swap_is_not_progress():
    prev, curr = _rep("a", "b"), _rep("a", "c")  # one fixed, one new — same size
    assert not progressed(curr, prev)


def test_growth_is_regression_not_progress():
    prev, curr = _rep("a"), _rep("a", "b")
    assert not progressed(curr, prev)


def test_gating_failures_ignores_sub_gating_severity():
    r = Report(
        verdict=Verdict.WARN, summary="", grader=GraderKind.DOM,
        issues=[
            Issue(kind=IssueKind.CONTRAST, severity=Severity.WARNING, message="warn", source=GraderKind.DOM),
            Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR, message="err", source=GraderKind.DOM),
        ],
    )
    assign(r)
    assert len(gating_failures(r)) == 1  # only the ERROR counts toward the gating set
