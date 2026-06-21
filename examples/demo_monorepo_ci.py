"""Monorepo CI demo (§7.4) — separate stage per package, unified gate.

In a monorepo, different packages might use different languages or tools.
We can run a separate stage per package (e.g. one Python, one Node) and
then gate the entire build on the combined results.

Run:  python examples/demo_monorepo_ci.py
"""

from __future__ import annotations

import json

from verel.ci import inner_loop_stage, premerge_stage, run_stage
from verel.verdict import Verdict

# Canned tool output keyed by the binary the stage invokes — the injected runner returns it.
OUT = {
    "node": "TAP version 13\nok 1 - renders\nnot ok 2 - submit posts the form\n",
    "bandit": json.dumps({"results": []}),
}

def canned(cmd, cwd=None):
    head = cmd[0]
    if head == "node":
        return (1, OUT["node"], "")
    if head == "bandit":
        return (0, OUT["bandit"], "")
    # ruff/eslint/etc. — clean
    return (0, "", "")

def show(pkg, res):
    print(f"\nPackage [{pkg}] ({res.name}): {res.verdict.value.upper()}")
    for r in res.reports:
        n = len(r.issues)
        flag = " (errored)" if r.errored else ""
        print(f"  {r.grader.value:9} [{getattr(r, 'model', None) or '-'}] "
              f"{n} issue(s){flag}" + (f" — {r.issues[0].message}" if n else ""))

def main() -> None:
    # A monorepo with a Python backend and a JS frontend.
    packages = [
        {"name": "frontend", "path": "/repo/packages/frontend", "language": "js"},
        {"name": "backend", "path": "/repo/packages/backend", "language": "python"},
    ]

    print("── Monorepo CI: Running separate stages per package ──")
    results = []
    overall_verdict = Verdict.PASS

    for pkg in packages:
        # We can configure stages differently per package
        if pkg["language"] == "python":
            stage = premerge_stage(pkg["path"], language="python", security=True)
        else:
            stage = inner_loop_stage(pkg["path"], language=pkg["language"])
            
        # run_stage accepts a runner that intercepts grader shell commands
        res = run_stage(stage, runner=canned)
        show(pkg["name"], res)
        results.append(res)
        
        # Any failing package fails the entire monorepo build
        if res.verdict == Verdict.FAIL:
            overall_verdict = Verdict.FAIL

    print("\n── Unified Monorepo Gate ──")
    print(f"Overall Monorepo Verdict: {overall_verdict.value.upper()}")

if __name__ == "__main__":
    main()
