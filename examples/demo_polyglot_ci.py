"""Polyglot senses on one verdict bus (§7.4) — Python, JS/TS, Go, perf, security.

Every language's tests/lint/types, plus perf-budget and security scanners, become Reports on the
SAME bus with the SAME gate. Parsers are pure over tool output, so this runs offline: we inject a
canned runner instead of installing node/go/bandit. No key, no tools.

Run:  python examples/demo_polyglot_ci.py
"""

from __future__ import annotations

import json

from verel.ci import inner_loop_stage, perf_spec, premerge_stage, run_stage

# Canned tool output keyed by the binary the stage invokes — the injected runner returns it.
OUT = {
    "go": json.dumps({"Action": "fail", "Package": "pkg/auth", "Test": "TestLogin"}),
    "node": "TAP version 13\nok 1 - renders\nnot ok 2 - submit posts the form\n",
    "bench": json.dumps({"metrics": {"p95_ms": 240, "rps": 1500}}),
    "bandit": json.dumps({"results": [{"filename": "app.py", "line_number": 42,
              "issue_severity": "HIGH", "issue_text": "subprocess with shell=True", "test_id": "B602"}]}),
}


def canned(cmd, cwd=None):
    head = cmd[0]
    if head == "go":
        return (1, OUT["go"], "") if "test" in cmd else (0, "", "")     # vet clean
    if head == "node":
        return (1, OUT["node"], "")
    if head in ("bench",):
        return (0, OUT["bench"], "")
    if head == "bandit":
        return (1, OUT["bandit"], "")
    return (0, "", "")  # pytest/ruff/npx/etc. — clean


def show(title, res):
    print(f"\n{title}: {res.verdict.value.upper()}")
    for r in res.reports:
        n = len(r.issues)
        flag = " (errored)" if r.errored else ""
        print(f"  {r.grader.value:9} [{getattr(r, 'model', None) or '-'}] "
              f"{n} issue(s){flag}" + (f" — {r.issues[0].message}" if n else ""))


def main() -> None:
    # Go: a failing test parsed from `go test -json`.
    show("Go inner-loop", run_stage(inner_loop_stage("/repo", language="go"), runner=canned))

    # JS/TS: a failing TAP test + (clean) eslint/tsc.
    show("JS pre-merge", run_stage(premerge_stage("/repo", language="js"), runner=canned))

    # Python pre-merge with a perf budget and a security scan — both PRECISE, so they gate.
    perf = perf_spec("/repo", ["bench"], budgets={"p95_ms": 150})  # 240 > 150 → gating perf regression
    show("Python pre-merge + perf + security",
         run_stage(premerge_stage("/repo", security=True, perf=perf), runner=canned))

    print("\nAll senses share one schema, one gate, one stuck/progress signal.")


if __name__ == "__main__":
    main()
