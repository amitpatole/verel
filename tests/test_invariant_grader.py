"""C — business-rule/invariant grader: declared invariants → property checks → gate on a violation."""

import textwrap

from verel.ci.invariants import Invariant, grade_invariants, load_invariants
from verel.verdict import GraderKind, Severity, Verdict

_INV = "total_with_tax(prices, rate) is never less than sum(prices)"
_CHECK = ("from taxes import total_with_tax\n\ndef test_inv():\n"
          "    assert total_with_tax([10, 20], 0.1) >= sum([10, 20])\n")


def _chat(msgs):
    return _CHECK  # the generated property check for the invariant


def _repo(tmp_path, body):
    (tmp_path / "taxes.py").write_text(textwrap.dedent(body))
    return str(tmp_path)


def test_load_invariants_from_file(tmp_path):
    (tmp_path / "verel_invariants.yaml").write_text(
        "# business rules\n"
        "tax_floor: total is never less than subtotal\n"
        "a refund never exceeds the original charge\n")
    invs = load_invariants(str(tmp_path))
    assert len(invs) == 2
    assert invs[0].id == "tax_floor" and "less than subtotal" in invs[0].statement
    assert invs[1].statement.startswith("a refund")  # no id: prefix → auto id


def test_load_invariants_absent_is_empty(tmp_path):
    assert load_invariants(str(tmp_path)) == []


def test_grade_invariants_passes_when_upheld(tmp_path):
    repo = _repo(tmp_path, "def total_with_tax(p, r):\n    return round(sum(p) * (1 + r), 2)\n")
    rep = grade_invariants(repo, [_INV], ["taxes.py"], chat=_chat, n=2, isolation="subprocess")
    assert rep.verdict == Verdict.PASS and rep.grader == GraderKind.CONTRACT
    assert rep.run_receipt is not None and not rep.issues


def test_grade_invariants_gates_when_violated(tmp_path):
    repo = _repo(tmp_path, "def total_with_tax(p, r):\n    return sum(p) - 1  # violates the floor\n")
    rep = grade_invariants(repo, [_INV], ["taxes.py"], chat=_chat, n=2, isolation="subprocess")
    assert rep.verdict == Verdict.FAIL
    viol = [i for i in rep.issues if i.severity == Severity.ERROR]
    assert viol and "business rule violated" in viol[0].message
    assert viol[0].source == GraderKind.CONTRACT and rep.run_receipt is not None


def test_grade_invariants_accepts_invariant_objects(tmp_path):
    repo = _repo(tmp_path, "def total_with_tax(p, r):\n    return round(sum(p) * (1 + r), 2)\n")
    rep = grade_invariants(repo, [Invariant("floor", _INV)], ["taxes.py"], chat=_chat,
                           isolation="subprocess")
    assert rep.verdict == Verdict.PASS


def test_grade_invariants_unverifiable_is_advisory(tmp_path):
    repo = _repo(tmp_path, "def total_with_tax(p, r):\n    return sum(p)\n")
    rep = grade_invariants(repo, ["the code should feel elegant"], ["taxes.py"],
                           chat=lambda m: "not a test", n=2, isolation="subprocess")
    assert rep.verdict == Verdict.WARN
    assert all(i.severity != Severity.ERROR for i in rep.issues)
