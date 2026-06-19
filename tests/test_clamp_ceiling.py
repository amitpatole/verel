"""The clamp_ceiling unit-test table — shipped WITH the function (§7.1).

The advisory clamp is the single most load-bearing safety line. min-by-key only happens to
work because WARNING sits between INFO and ERROR; these cases pin the explicit-ceiling
semantics so a refactor to min-by-key fails loudly.
"""

from verel.verdict import Severity, clamp_ceiling

C, E, W, INFO = Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO


def test_advisory_critical_clamps_to_warning():
    assert clamp_ceiling(C, W) == W


def test_advisory_error_clamps_to_warning():
    assert clamp_ceiling(E, W) == W


def test_info_not_raised_to_warning():
    assert clamp_ceiling(INFO, W) == INFO


def test_precise_critical_not_clamped():
    assert clamp_ceiling(C, C) == C


def test_warning_at_ceiling_unchanged():
    assert clamp_ceiling(W, W) == W
