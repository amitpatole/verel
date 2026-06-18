"""Fingerprint stability invariant (§7.2): same logical failure across reruns -> stable
fingerprint; genuinely different failure -> different fingerprint."""

import json

from verel.verdict import GraderKind, Issue, IssueKind, Severity, canonicalize
from verel.verdict.fingerprint import fingerprint


def _test_issue(test_id: str, msg: str) -> Issue:
    return Issue(
        kind=IssueKind.OTHER, severity=Severity.ERROR, message=msg,
        source=GraderKind.TEST, detail_json=json.dumps({"test_id": test_id}),
    )


def test_canonicalize_scrubs_volatile_tokens():
    a = canonicalize("Overflow by 37px at 0xDEADBEEF on /src/app/x.css line 12 at 1.5rem")
    b = canonicalize("Overflow by 9px at 0xCAFEBABE on /src/app/y.css line 88 at 2.0rem")
    assert a == b  # same logical message, different volatile numbers/paths/addresses


def test_same_logical_failure_stable_across_reruns():
    a = fingerprint(_test_issue("t::login", "assert 401 == 200 (took 0.31s)"))
    b = fingerprint(_test_issue("t::login", "assert 401 == 200 (took 0.92s)"))
    assert a == b


def test_different_failure_different_fingerprint():
    a = fingerprint(_test_issue("t::login", "assert 401 == 200"))
    b = fingerprint(_test_issue("t::logout", "assert 401 == 200"))
    assert a != b


def test_dom_kind_fingerprint_keys_on_kind_locator_message():
    i1 = Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR, message="overflow by 12px",
               locator="#hero", source=GraderKind.DOM)
    i2 = Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR, message="overflow by 40px",
               locator="#hero", source=GraderKind.DOM)
    assert fingerprint(i1) == fingerprint(i2)  # scrubbed px -> same component, same issue
