"""Over-engineering / scope-creep smell grader (Verified Review, grader D) — "random abstractions
for problems nobody was trying to solve".

This is eventually the **smell organ `olfel`**'s job (ORGANISM.md). Until `olfel` is scheduled it
lives here as a self-contained, dependency-free module that emits standard verdict-bus Reports, so it
lifts into `olfel` later unchanged. It is **deterministic `ast` analysis only — no code execution**,
so it carries no sandbox/injection surface (unlike the spec/invariant graders):

- **Cyclomatic complexity** per changed function. Over the budget → a gating `SMELL`/`COMPLEXITY`
  ERROR (deterministic, in `PRECISE_GRADERS`).
- **Speculative generality** — a new top-level class/function in the changed files that is referenced
  **nowhere** in the repo (an abstraction nobody needed yet) → an advisory WARNING.

The optional "this abstraction solves a problem not in the ticket" judgment is left to an LLM layer
(advisory); the gating signal is the hard, countable complexity metric.
"""

from __future__ import annotations

import ast
import os

from .verdict.fingerprint import assign
from .verdict.models import (
    GraderKind,
    Issue,
    IssueKind,
    Report,
    Severity,
    Verdict,
)

# ast nodes that each add one independent path (McCabe).
_DECISION = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith,
             ast.IfExp, ast.comprehension, ast.Assert)


def cyclomatic_complexity(fn: ast.AST) -> int:
    """McCabe complexity of a function node: 1 + one per decision point (branch / loop / boolean
    operand beyond the first / comprehension clause)."""
    score = 1
    for node in ast.walk(fn):
        if isinstance(node, _DECISION):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1  # `a and b and c` = 2 extra paths
        elif isinstance(node, ast.comprehension):
            score += len(node.ifs)
    return score


def _functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            yield node


def file_complexity(source: str) -> dict[str, int]:
    """`{function_name: complexity}` for a module source ({} if it doesn't parse)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    return {fn.name: cyclomatic_complexity(fn) for fn in _functions(tree)}


def _top_level_defs(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return [n.name for n in tree.body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and not n.name.startswith("_")]


def _all_referenced_names(repo: str, exclude: set[str]) -> set[str]:
    """Every Name/Attribute identifier used across the repo's .py files (except the `exclude` paths) —
    so we can tell whether a newly-added abstraction is actually used anywhere."""
    names: set[str] = set()
    for root, _dirs, files in os.walk(repo):
        if any(p in root for p in (os.sep + ".", "/node_modules", "/.venv", "/venv")):
            continue
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            if os.path.realpath(path) in exclude:
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    names.add(node.attr)
    return names


def grade_smell(repo: str, changed_files: list[str], *, complexity_budget: int = 12,
                flag_speculative: bool = True) -> Report:
    """Grade the changed files for over-engineering. A function over `complexity_budget` gates
    (deterministic ERROR); a new public def/class referenced nowhere in the repo is an advisory
    WARNING (speculative generality)."""
    repo_r = os.path.realpath(repo)
    targets = [f for f in changed_files if f.endswith(".py")]
    changed_paths = {os.path.realpath(os.path.join(repo_r, f)) for f in targets}
    issues: list[Issue] = []

    referenced = _all_referenced_names(repo_r, exclude=changed_paths) if flag_speculative else set()
    for rel in targets:
        path = os.path.join(repo_r, rel)
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
        except OSError:
            continue
        for name, score in file_complexity(source).items():
            if score > complexity_budget:
                issues.append(Issue(
                    kind=IssueKind.COMPLEXITY, severity=Severity.ERROR, source=GraderKind.SMELL,
                    message=f"{name}() has cyclomatic complexity {score} > budget {complexity_budget} "
                            f"— likely over-complex; split it",
                    locator=f"{rel}:{name}", locator_precise=True))
        if flag_speculative:
            for name in _top_level_defs(source):
                # referenced within its own module is fine; unreferenced ANYWHERE = speculative.
                if name not in referenced and source.count(name) <= 1:
                    from .verdict.models import Confidence
                    issues.append(Issue(
                        kind=IssueKind.COMPLEXITY, severity=Severity.WARNING, confidence=Confidence.LOW,
                        source=GraderKind.SMELL, locator=f"{rel}:{name}",
                        message=f"speculative generality: '{name}' is defined but referenced nowhere "
                                f"— an abstraction for a problem not yet present?"))
    verdict = (Verdict.FAIL if any(i.severity == Severity.ERROR for i in issues)
               else (Verdict.WARN if issues else Verdict.PASS))
    n_over = sum(i.severity == Severity.ERROR for i in issues)
    report = Report(verdict=verdict, grader=GraderKind.SMELL,
                    summary=f"smell: {n_over} over-budget function(s), {len(issues) - n_over} advisory")
    return assign(report.model_copy(update={"issues": issues}))
