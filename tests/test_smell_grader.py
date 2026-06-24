"""D — over-engineering / scope-creep smell grader (deterministic AST analysis)."""

import ast  # noqa: E402
import textwrap

from verel.smell import cyclomatic_complexity, file_complexity, grade_smell
from verel.verdict import GraderKind, IssueKind, Severity, Verdict
from verel.verdict.constants import ADVISORY_GRADERS, PRECISE_GRADERS


def test_cyclomatic_complexity_counts_branches():
    simple = ast.parse("def f(x):\n    return x + 1\n").body[0]
    assert cyclomatic_complexity(simple) == 1
    branchy = ast.parse(
        "def g(x):\n"
        "    if x and x > 0:\n"          # +1 if, +1 boolop
        "        for i in range(x):\n"   # +1 for
        "            if i % 2:\n"        # +1 if
        "                pass\n"
        "    return x\n").body[0]
    assert cyclomatic_complexity(branchy) == 5


def test_file_complexity_map():
    cx = file_complexity("def a(x):\n    return x\n\ndef b(x):\n    return x if x else 0\n")
    assert cx == {"a": 1, "b": 2}


def test_smell_is_precise_and_gates():
    assert GraderKind.SMELL in PRECISE_GRADERS and GraderKind.SMELL not in ADVISORY_GRADERS


def _over_budget_fn():
    body = "def tangled(x):\n    r = 0\n"
    for i in range(15):  # 15 if-branches → complexity 16 > budget 12
        body += f"    if x == {i}:\n        r += {i}\n"
    return body + "    return r\n"


def test_grade_smell_gates_over_complex_function(tmp_path):
    (tmp_path / "m.py").write_text(_over_budget_fn())
    rep = grade_smell(str(tmp_path), ["m.py"], complexity_budget=12, flag_speculative=False)
    assert rep.verdict == Verdict.FAIL and rep.grader == GraderKind.SMELL
    err = [i for i in rep.issues if i.severity == Severity.ERROR]
    assert err and err[0].kind == IssueKind.COMPLEXITY and "cyclomatic complexity" in err[0].message


def test_grade_smell_passes_simple_code(tmp_path):
    (tmp_path / "m.py").write_text("def add(a, b):\n    return a + b\n")
    rep = grade_smell(str(tmp_path), ["m.py"], flag_speculative=False)
    assert rep.verdict == Verdict.PASS and not rep.issues


def test_grade_smell_flags_speculative_abstraction(tmp_path):
    # A public class defined in the changed file and referenced NOWHERE → advisory speculative warning.
    (tmp_path / "used.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "main.py").write_text("from used import helper\n\ndef run():\n    return helper()\n")
    (tmp_path / "new.py").write_text(textwrap.dedent(
        "class AbstractFrobnicatorFactory:\n    def make(self):\n        return None\n"))
    rep = grade_smell(str(tmp_path), ["new.py"], complexity_budget=12)
    spec = [i for i in rep.issues if "speculative generality" in i.message]
    assert spec and "AbstractFrobnicatorFactory" in spec[0].message
    assert all(i.severity != Severity.ERROR for i in rep.issues)  # advisory only


def test_grade_smell_does_not_flag_referenced_abstraction(tmp_path):
    (tmp_path / "lib.py").write_text("class Cart:\n    def total(self):\n        return 0\n")
    (tmp_path / "app.py").write_text("from lib import Cart\n\ndef run():\n    return Cart().total()\n")
    rep = grade_smell(str(tmp_path), ["lib.py"], complexity_budget=12)
    assert not any("speculative" in i.message for i in rep.issues)  # Cart is used in app.py
