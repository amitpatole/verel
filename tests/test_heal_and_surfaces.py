"""Self-healing CI + code-fixer + MCP dispatch + CLI doctor — offline (fake chat/runner)."""

import json
from pathlib import Path

from verel.agents.code_fixer import _parse_files, fix_code
from verel.ci import Stage, self_heal
from verel.ci.graders import pytest_spec
from verel.mcp_server import TOOLS, dispatch
from verel.verdict import GraderKind


# ---- code-fixer ----
def test_parse_files_extracts_json_map():
    reply = 'sure:\n{"files": {"app.py": "def add(a,b):\\n    return a+b\\n"}}'
    files = _parse_files(reply)
    assert files["app.py"].startswith("def add")


def test_fix_code_writes_only_source_not_tests(tmp_path: Path):
    (tmp_path / "app.py").write_text("def add(a,b):\n    return a-b\n")
    (tmp_path / "test_app.py").write_text("def test_x():\n    assert True\n")
    reply = json.dumps({"files": {
        "app.py": "def add(a,b):\n    return a+b\n",
        "test_app.py": "HACKED",  # must be ignored — never edit tests
    }})
    changed = fix_code(tmp_path, [], chat=lambda m: reply)
    assert changed == {"app.py"}
    assert (tmp_path / "app.py").read_text().strip().endswith("a+b")
    assert "HACKED" not in (tmp_path / "test_app.py").read_text()


def test_fix_code_blocks_path_escape(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n")
    reply = json.dumps({"files": {"../evil.py": "boom"}})
    changed = fix_code(tmp_path, [], chat=lambda m: reply)
    assert changed == set() and not (tmp_path.parent / "evil.py").exists()


# ---- self-heal loop (fake runner: fail until the fixer "patches", then pass) ----
def test_self_heal_drives_to_pass():
    state = {"fixed": False}
    FAIL = "FAILED test_app.py::test_add - assert -1 == 5\n1 failed\n"

    def runner(cmd, cwd=None):
        return (0, "", "") if state["fixed"] else (1, FAIL, "")

    def fix(repo, reports):
        state["fixed"] = True
        return {"app.py"}

    stage = Stage("inner_loop", [pytest_spec("/repo")], required={GraderKind.TEST})
    res = self_heal("/repo", stage, fix=fix, runner=runner, max_rounds=3)
    assert res.healed and res.terminated_on == "passed"
    assert any(r.changed == ["app.py"] for r in res.rounds)


def test_self_heal_escalates_when_fixer_gives_up():
    FAIL = "FAILED test_app.py::test_add - assert 1 == 2\n1 failed\n"
    stage = Stage("inner_loop", [pytest_spec("/repo")], required={GraderKind.TEST})
    res = self_heal("/repo", stage, fix=lambda r, reps: set(),  # never patches
                    runner=lambda cmd, cwd=None: (1, FAIL, ""), max_rounds=3)
    assert not res.healed and res.terminated_on == "escalate"


# ---- MCP dispatch (no `mcp` package needed) ----
def test_mcp_gate_tool():
    out = dispatch("verel_gate", {"reports": [
        {"verdict": "fail", "summary": "", "grader": "test",
         "issues": [{"kind": "other", "severity": "error", "message": "x", "source": "test",
                     "fingerprint": "f1"}]}]})
    assert out["verdict"] == "fail"


def test_mcp_recall_tool_roundtrips_via_memory():
    # empty in-memory store -> no hits, but the tool runs and returns the shape
    out = dispatch("verel_recall", {"query": "anything", "store": ":memory:"})
    assert out == {"records": []}


def test_mcp_unknown_tool_raises():
    import pytest

    with pytest.raises(KeyError):
        dispatch("nope", {})


def test_mcp_tool_catalog_is_complete():
    assert {"verel_gate", "verel_ci_check", "verel_recall", "verel_build_tool"} <= set(TOOLS)


# ---- CLI ----
def test_cli_doctor_and_version_run():
    from verel.cli import main

    assert main(["version"]) == 0
    assert main(["doctor"]) == 0
