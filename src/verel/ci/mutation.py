"""Test-effectiveness via mutation testing (§ Verified Review, grader A).

A green suite proves nothing if it asserts nothing. This injects small faults ("mutants") into the
*changed* source and re-runs the suite: a mutant the suite still **passes** is a **survivor** — the
tests don't actually constrain that line. Survivors are hard, deterministic evidence (not an LLM
hunch), so the grader gates (`GraderKind.MUTATION` ∈ `PRECISE_GRADERS`).

Zero-dependency: a tiny `ast`-based mutator over a focused, high-signal operator set. Diff-scoped
(mutate only changed lines) to stay under the CI budget. The suite is the user's OWN tests — same
trust model as the existing TEST grader — so no new sandbox surface.

`python -m verel.ci.mutation --repo R --targets a.py,b.py` prints one JSON line for the grader.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from dataclasses import dataclass

# High-signal, syntax-safe operators. Each maps a node type to its swap.
_COMPARE_SWAP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt,
                 ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
_BINOP_SWAP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div, ast.Div: ast.Mult}
_BOOL_SWAP = {ast.And: ast.Or, ast.Or: ast.And}


@dataclass
class Mutant:
    lineno: int
    op: str  # human label, e.g. "==→!=", "and→or", "True→False", "return→None"
    source: str  # the full mutated module source


def _site_kind(node: ast.AST) -> str | None:
    """The mutation kind for a node, or None if it isn't a (single-op) mutation site."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _COMPARE_SWAP:
        return "compare"
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAP:
        return "binop"
    if isinstance(node, ast.BoolOp) and type(node.op) in _BOOL_SWAP:
        return "bool"
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return "bool_const"
    if isinstance(node, ast.Return) and node.value is not None and not (
            isinstance(node.value, ast.Constant) and node.value.value is None):
        return "return_none"
    return None


def _sites(tree: ast.AST) -> list[tuple[ast.AST, str, int]]:
    """All mutation sites in deterministic `ast.walk` order: (node, kind, lineno)."""
    out: list[tuple[ast.AST, str, int]] = []
    for node in ast.walk(tree):
        kind = _site_kind(node)
        if kind is not None:
            out.append((node, kind, getattr(node, "lineno", 0)))
    return out


def _apply(node: ast.AST, kind: str) -> str:
    """Mutate `node` in place; return a short human label of the change."""
    if kind == "compare":
        old = type(node.ops[0])  # type: ignore[attr-defined]
        node.ops[0] = _COMPARE_SWAP[old]()  # type: ignore[attr-defined]
        return f"{_SYM.get(old, old.__name__)}→{_SYM.get(_COMPARE_SWAP[old], '')}"
    if kind == "binop":
        old = type(node.op)  # type: ignore[attr-defined]
        node.op = _BINOP_SWAP[old]()  # type: ignore[attr-defined]
        return f"{_SYM.get(old, old.__name__)}→{_SYM.get(_BINOP_SWAP[old], '')}"
    if kind == "bool":
        old = type(node.op)  # type: ignore[attr-defined]
        node.op = _BOOL_SWAP[old]()  # type: ignore[attr-defined]
        return "and→or" if old is ast.And else "or→and"
    if kind == "bool_const":
        label = f"{node.value}→{not node.value}"  # type: ignore[attr-defined]  # label before flip
        node.value = not node.value  # type: ignore[attr-defined]
        return label
    if kind == "return_none":
        node.value = ast.Constant(value=None)  # type: ignore[attr-defined]
        return "return→None"
    return kind


_SYM = {ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.GtE: ">=", ast.Gt: ">", ast.LtE: "<=",
        ast.Is: "is", ast.IsNot: "is not", ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/"}


def generate_mutants(source: str, *, lines: set[int] | None = None, cap: int = 25) -> list[Mutant]:
    """Generate up to `cap` single-point mutants of `source`. If `lines` is given, only mutate sites
    on those (changed) lines. Each mutant re-parses a fresh tree and mutates exactly one site, so the
    others stay pristine."""
    base = ast.parse(source)
    n = len(_sites(base))
    mutants: list[Mutant] = []
    for i in range(n):
        _, _, lineno = _sites(base)[i]
        if lines is not None and lineno not in lines:
            continue
        fresh = ast.parse(source)
        node, kind, _ = _sites(fresh)[i]
        label = _apply(node, kind)
        ast.fix_missing_locations(fresh)
        try:
            mutated = ast.unparse(fresh)
        except Exception:  # pragma: no cover - unparse is robust for our operator set
            continue
        mutants.append(Mutant(lineno=lineno, op=label, source=mutated))
        if len(mutants) >= cap:
            break
    return mutants


def _run_pytest(repo: str, test_args: list[str], timeout: int) -> int:
    """Return pytest's exit code (0 = all pass). The suite is the user's own — same trust as `verel
    ci`. Cache disabled so a mutant can't be masked by a stale .pyc."""
    cmd = ["python", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *test_args]
    try:
        r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=timeout)
        return r.returncode
    except subprocess.TimeoutExpired:
        return 1  # a mutant that hangs the suite is "caught" (non-zero), not a survivor


@dataclass
class MutationResult:
    baseline_pass: bool
    total: int  # mutants evaluated
    survivors: list[dict]  # {file, line, op}


def run_mutation(repo: str, targets: list[str], *, lines_by_file: dict[str, set[int]] | None = None,
                 test_args: list[str] | None = None, cap_per_file: int = 25,
                 timeout: int = 60, total_budget_s: float = 240.0) -> MutationResult:
    """Mutate each target file's changed lines, run the suite per mutant, collect survivors.

    Requires a GREEN baseline: test-effectiveness is meaningless on a red suite, so if the unmutated
    suite doesn't pass we report `baseline_pass=False` and assess nothing. Files are always restored.

    `total_budget_s` bounds the WHOLE run's wall-clock and MUST stay safely under the grader's outer
    subprocess timeout (300s): a new mutant is only started if its worst case (`timeout`) still fits
    the budget, so the process always reaches its restore loop and exits cleanly — it can never be
    SIGKILL'd by the outer timeout mid-mutation, which would leave a mutated file on disk.
    """
    import os
    import time

    # Anchor the deadline at entry so the WHOLE run (baseline + every mutant + restore) fits the
    # budget, which stays well under the grader's 300s outer subprocess timeout (≥60s margin).
    deadline = time.monotonic() + total_budget_s
    test_args = test_args or []
    if _run_pytest(repo, test_args, timeout) != 0:
        return MutationResult(baseline_pass=False, total=0, survivors=[])

    repo_root = os.path.realpath(repo)
    survivors: list[dict] = []
    total = 0
    for rel in targets:
        # We WRITE to `path`, so refuse any target that escapes the repo (path traversal / abs path),
        # even though targets are operator-supplied — never mutate a file outside the graded tree.
        path = os.path.realpath(os.path.join(repo_root, rel))
        if os.path.commonpath([repo_root, path]) != repo_root or not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            original = fh.read()
        try:
            mutants = generate_mutants(
                original, lines=(lines_by_file or {}).get(rel), cap=cap_per_file)
        except SyntaxError:
            continue  # not parseable Python — skip, don't crash the gate
        try:
            for m in mutants:
                # Only start a mutant if its worst-case run still fits the total budget — guarantees
                # we finish (and restore) before the outer timeout can SIGKILL us.
                if time.monotonic() + timeout > deadline:
                    break
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(m.source)
                total += 1
                if _run_pytest(repo, test_args, timeout) == 0:  # suite still passed ⇒ mutant SURVIVED
                    survivors.append({"file": rel, "line": m.lineno, "op": m.op})
        finally:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)  # ALWAYS restore, even on exception/timeout
        if time.monotonic() + timeout > deadline:
            break  # budget exhausted — stop launching new files too
    return MutationResult(baseline_pass=True, total=total, survivors=survivors)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m verel.ci.mutation",
                                 description="mutation testing — surviving mutants reveal weak tests")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--targets", required=True, help="comma-separated source files (relative to repo)")
    ap.add_argument("--cap", type=int, default=25, help="max mutants per file")
    ap.add_argument("--timeout", type=int, default=120, help="per-suite-run timeout (s)")
    ap.add_argument("--test-args", default="", help="extra args passed to pytest")
    a = ap.parse_args(argv)
    targets = [t.strip() for t in a.targets.split(",") if t.strip()]
    res = run_mutation(a.repo, targets, test_args=a.test_args.split() if a.test_args else [],
                       cap_per_file=a.cap, timeout=a.timeout)
    # one JSON line for the grader parser (parse_mutation reads the LAST json object)
    print(json.dumps({"baseline_pass": res.baseline_pass, "total": res.total,
                      "survivors": res.survivors}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
