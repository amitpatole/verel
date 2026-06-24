"""Test-effectiveness grader (mutation) — the AST mutator, the parser, the full grader path, and a
real weak-tests-FAIL / strong-tests-PASS integration. Survivors gate (ERROR, PRECISE)."""

import json
import textwrap

from verel.ci import mutation_spec, parse_mutation, run_grader
from verel.ci.mutation import generate_mutants, run_mutation
from verel.verdict import GraderKind, IssueKind, Severity, Verdict
from verel.verdict.constants import ADVISORY_GRADERS, PRECISE_GRADERS


def _runner(rc, out, err=""):
    return lambda cmd, cwd=None: (rc, out, err)


# ---- the AST mutator ----
def test_generate_mutants_covers_operator_set():
    src = "def f(a, b):\n    if a >= b and a > 0:\n        return a + b\n    return True\n"
    ops = {m.op for m in generate_mutants(src)}
    assert ">=→<" in ops and "and→or" in ops and "+→-" in ops
    assert any(o == "return→None" for o in ops) and any("→True" in o or "→False" in o for o in ops)


def test_each_mutant_is_a_single_change_and_valid_python():
    src = "def f(a, b):\n    return a + b\n"
    muts = generate_mutants(src)
    assert muts and all("a - b" in m.source for m in muts if m.op == "+→-")
    for m in muts:
        compile(m.source, "<m>", "exec")  # every mutant parses


def test_diff_scoping_limits_to_changed_lines():
    src = "def f(a, b):\n    x = a + b\n    y = a - b\n    return x > y\n"
    only_line3 = generate_mutants(src, lines={3})
    assert only_line3 and all(m.lineno == 3 for m in only_line3)


def test_cap_bounds_the_number_of_mutants():
    src = "def f(a):\n" + "".join(f"    z{i} = a + {i}\n" for i in range(50)) + "    return a\n"
    assert len(generate_mutants(src, cap=5)) == 5


# ---- the parser ----
def test_parse_mutation_survivor_is_gating_error():
    out = json.dumps({"baseline_pass": True, "total": 3,
                      "survivors": [{"file": "calc.py", "line": 2, "op": "+→-"}]})
    issues = parse_mutation(out, "")
    assert len(issues) == 1
    i = issues[0]
    assert i.kind == IssueKind.SURVIVED_MUTANT and i.severity == Severity.ERROR
    assert i.source == GraderKind.MUTATION and i.locator == "calc.py:2" and i.locator_precise


def test_parse_mutation_red_baseline_is_error():
    issues = parse_mutation(json.dumps({"baseline_pass": False, "total": 0, "survivors": []}), "")
    assert len(issues) == 1 and issues[0].severity == Severity.ERROR
    assert "baseline" in issues[0].message


def test_parse_mutation_clean_is_no_issues():
    assert parse_mutation(json.dumps({"baseline_pass": True, "total": 4, "survivors": []}), "") == []


def test_parse_mutation_garbage_output_is_error_not_crash():
    assert parse_mutation("totally not json", "")[0].severity == Severity.ERROR


# ---- gating semantics ----
def test_mutation_is_precise_and_gates_not_advisory():
    assert GraderKind.MUTATION in PRECISE_GRADERS  # ERROR issues gate
    assert GraderKind.MUTATION not in ADVISORY_GRADERS  # never clamped to WARNING


# ---- full grader path with an injected runner (no real subprocess) ----
def test_run_grader_fails_and_attests_on_survivor():
    out = json.dumps({"baseline_pass": True, "total": 2,
                      "survivors": [{"file": "calc.py", "line": 2, "op": "+→-"}]})
    rep = run_grader(mutation_spec("/repo", ["calc.py"]), _runner(0, out))
    assert rep.grader == GraderKind.MUTATION and rep.verdict == Verdict.FAIL
    assert rep.run_receipt is not None and not rep.errored
    assert all(i.fingerprint for i in rep.issues)


def test_run_grader_passes_when_no_survivors():
    out = json.dumps({"baseline_pass": True, "total": 4, "survivors": []})
    rep = run_grader(mutation_spec("/repo", ["calc.py"]), _runner(0, out))
    assert rep.verdict == Verdict.PASS and not rep.issues


# ---- real integration: weak tests leak a survivor; strong tests kill them ----
_CALC = "def add(a, b):\n    return a + b\n\ndef is_adult(age):\n    return age >= 18\n"


def _write(repo, calc, test):
    (repo / "calc.py").write_text(textwrap.dedent(calc))
    (repo / "test_calc.py").write_text(textwrap.dedent(test))


def test_weak_tests_produce_survivors(tmp_path):
    _write(tmp_path, _CALC, "from calc import add, is_adult\n\ndef test_weak():\n"
                            "    add(1, 2)\n    is_adult(20)\n")  # no assertions
    res = run_mutation(str(tmp_path), ["calc.py"], cap_per_file=10)
    assert res.baseline_pass and res.survivors  # the toothless suite catches nothing
    assert (tmp_path / "calc.py").read_text() == _CALC  # file restored exactly


def test_strong_tests_kill_all_mutants(tmp_path):
    _write(tmp_path, _CALC,
           "from calc import add, is_adult\n\ndef test_add():\n    assert add(2, 3) == 5\n\n"
           "def test_adult():\n    assert is_adult(18) is True\n    assert is_adult(17) is False\n")
    res = run_mutation(str(tmp_path), ["calc.py"], cap_per_file=10)
    assert res.baseline_pass and res.survivors == []  # real assertions catch every mutant


def test_red_baseline_assesses_nothing(tmp_path):
    _write(tmp_path, _CALC, "from calc import add\n\ndef test_broken():\n    assert add(1, 1) == 99\n")
    res = run_mutation(str(tmp_path), ["calc.py"], cap_per_file=5)
    assert res.baseline_pass is False and res.survivors == []


def test_total_budget_stops_before_outer_timeout(tmp_path):
    # A zero budget must start NO mutants (so the process always finishes + restores before the
    # outer subprocess timeout could SIGKILL it mid-mutation), and leave the file pristine.
    _write(tmp_path, _CALC, "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    res = run_mutation(str(tmp_path), ["calc.py"], cap_per_file=10, total_budget_s=0.0)
    assert res.baseline_pass and res.total == 0 and res.survivors == []
    assert (tmp_path / "calc.py").read_text() == _CALC  # never mutated → restored intact


def test_path_traversal_target_is_refused(tmp_path):
    # A target escaping the repo must NEVER be written to (we mutate files in place).
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, _CALC, "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    outside = tmp_path / "secret.py"
    outside.write_text("UNTOUCHED = True\n")
    before = outside.read_text()
    res = run_mutation(str(repo), ["../secret.py", str(outside)], cap_per_file=5)
    assert res.total == 0 and res.survivors == []  # both escaping targets skipped
    assert outside.read_text() == before  # the outside file was never mutated
