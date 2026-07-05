"""Adoption-audit regression pins: the first-run UX fixes (P0) must not silently regress —
an errored grader must PRINT its reason, and the test grader must run the RIGHT interpreter."""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

from verel.ci.__main__ import _print
from verel.ci.graders import mutation_spec, pytest_spec
from verel.ci.pipeline import StageResult
from verel.verdict.models import GateResult, GraderKind, Report, Verdict


def test_test_and_mutation_graders_use_sys_executable():
    # adoption P0: bare "python" ran the WRONG interpreter (python3-only host / pipx) → wrong verdicts.
    assert pytest_spec(".").command[0] == sys.executable
    assert mutation_spec(".", ["m"]).command[0] == sys.executable
    assert pytest_spec(".").command[0] != "python"  # not the bare literal


def test_errored_grader_prints_its_reason_and_gate_reason():
    # adoption P0: an errored grader used to print a bare "ERRORED" — the reason lived in the Report but
    # was never shown. Now the summary + the gate's overall reason must appear.
    rep = Report(verdict=Verdict.FAIL, summary="lint: tool missing (ruff)", grader=GraderKind.LINT,
                 errored=True)
    result = StageResult(
        name="inner_loop:python", verdict=Verdict.FAIL,
        gate=GateResult(verdict=Verdict.FAIL, reason="required grader(s) absent/errored: lint"),
        reports=[rep])
    buf = io.StringIO()
    with redirect_stdout(buf):
        _print(result)
    out = buf.getvalue()
    assert "lint: tool missing (ruff)" in out           # the WHY, not just "ERRORED"
    assert "required grader(s) absent/errored: lint" in out  # the gate's overall reason
    assert "ERRORED" in out


def test_sandbox_warns_when_resource_module_absent(monkeypatch):
    # adoption P1 / security: on a platform without `resource` (Windows) the subprocess sandbox is
    # timeout-only — that degradation must WARN, never be silent (project rule).
    import importlib.util
    import warnings

    from verel.toolsmith import sandbox
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec",
                        lambda n, *a, **k: None if n == "resource" else real(n, *a, **k))
    monkeypatch.setattr(sandbox, "exec_child", lambda *a, **k: None)  # don't actually spawn

    class _Tool:
        name = "t"
        def verify(self):
            return True
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        sandbox.run_sandboxed(_Tool())
    assert any(issubclass(x.category, RuntimeWarning) and "timeout" in str(x.message).lower() for x in w)


def test_pass_does_not_print_gate_reason_noise():
    # on a clean pass, no spurious gate-reason line
    result = StageResult(name="s", verdict=Verdict.PASS,
                         gate=GateResult(verdict=Verdict.PASS, reason="all graders passed"), reports=[])
    buf = io.StringIO()
    with redirect_stdout(buf):
        _print(result)
    assert "→" not in buf.getvalue()
