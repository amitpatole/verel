"""Container tool runner + embeddings-backed tool reuse + LLM-enriched medic."""

import pytest

from verel.ci import Action, enrich_diagnoses, triage
from verel.memory import HashEmbedder, LocalMemory
from verel.toolsmith import (
    SideEffect,
    ToolCase,
    ToolRecord,
    ToolRegistry,
    ToolSmith,
    ToolSpec,
    bwrap_available,
    run_container,
)
from verel.verdict import GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign

needs_bwrap = pytest.mark.skipif(not bwrap_available(), reason="bwrap (bubblewrap) not installed")


# ---- container runner (§7.7) ----
@needs_bwrap
def test_container_runs_pure_function():
    t = ToolRecord(name="mul", code="def mul(a, b):\n    return a * b\n",
                   side_effect=SideEffect.READ_ONLY).sign()
    assert run_container(t, [6, 7]) == 42


@needs_bwrap
def test_container_blocks_network():
    code = ("def f():\n    import socket\n"
            "    socket.create_connection(('1.1.1.1', 80), timeout=2)\n    return 'OPEN'\n")
    t = ToolRecord(name="f", code=code, side_effect=SideEffect.READ_ONLY).sign()
    with pytest.raises(Exception):  # noqa: B017 — SandboxError on network-unreachable
        run_container(t)


@needs_bwrap
def test_toolsmith_container_isolation_builds_verified():
    reg = ToolRegistry(LocalMemory(), scope="global")
    code = "```python\ndef rev(s):\n    return s[::-1]\n```"
    smith = ToolSmith(reg, chat=lambda m: code, isolation="container")
    res = smith.build(ToolSpec(name="rev", capability="reverse a string",
                               cases=[ToolCase(args=["abc"], expected="cba")]))
    assert res.passed and res.trust.value == "verified"


# ---- embeddings-backed tool reuse ----
def _register(reg, name, code, capability, trust):

    reg.register(ToolRecord(name=name, code=code, capability=capability,
                            side_effect=SideEffect.READ_ONLY, eval_score=1.0).sign(), trust=trust)


def test_find_uses_cosine_when_embedder_present():
    from verel.memory import Trust

    mem = LocalMemory(embedder=HashEmbedder(dim=128))
    reg = ToolRegistry(mem, scope="global")
    _register(reg, "slugify", "def slugify(s):\n    return s\n", "convert a title to a url slug", Trust.VERIFIED)
    # exact capability -> cosine 1.0 -> reused above the 0.5 threshold
    assert reg.find("convert a title to a url slug", min_relevance=0.5)
    # clearly different capability -> low cosine -> not reused (no false match)
    assert reg.find("add sales tax to a price", min_relevance=0.5) == []


# ---- LLM-enriched medic ----
def _issue(msg, fp="f1"):
    i = Issue(kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.TEST, message=msg)
    i.fingerprint = fp
    return i


def test_enrich_only_touches_fix_branch_and_keeps_action():
    report = Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.TEST,
                    issues=[_issue("assert 1 == 2", "a"), _issue("Connection reset", "b")])
    assign(report)
    diags = triage(report)
    enrich_diagnoses(diags, chat=lambda m: "root cause: off-by-one in compute(); fix calc.py")
    by_action = {d.action: d for d in diags}
    # the genuine-regression diagnosis got a hint; the transient (RETRY) did not
    assert by_action[Action.FIX_BRANCH].hint.startswith("root cause")
    assert by_action[Action.RETRY].hint == ""
    # classification is unchanged by enrichment (LLM never decides retry-vs-fix)
    assert by_action[Action.FIX_BRANCH].action == Action.FIX_BRANCH
