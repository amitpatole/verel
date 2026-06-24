"""R3 — agent-SDK shims: the universal gate callable + function-calling schemas + dispatcher."""

import json

from verel.integrations.sdk import (
    anthropic_tools,
    gate,
    openai_tools,
    run_tool_call,
)


def _repo(tmp_path, body, test):
    (tmp_path / "m.py").write_text(body)
    (tmp_path / "test_m.py").write_text(test)
    return str(tmp_path)


def test_gate_callable_runs_ci(tmp_path):
    repo = _repo(tmp_path, "def ok():\n    return 1\n",
                 "from m import ok\n\ndef test_ok():\n    assert ok() == 1\n")
    out = gate(repo, lint=False)
    assert out["verdict"] == "pass" and "issues" in out and "ci" in out


def test_gate_callable_fails_on_broken_repo(tmp_path):
    repo = _repo(tmp_path, "def ok():\n    return 2\n",
                 "from m import ok\n\ndef test_ok():\n    assert ok() == 1\n")
    out = gate(repo, lint=False)
    assert out["verdict"] == "fail" and out["issues"]


def test_gate_folds_in_spec_worst_of_two(monkeypatch):
    # CI passes but the spec grader fails → combined verdict is the worst (fail).
    import verel.mcp_server as mcp

    def fake_dispatch(name, args):
        if name == "verel_ci_check":
            return {"verdict": "pass", "issues": []}
        if name == "verel_spec":
            return {"verdict": "fail", "issues": [{"message": "intent not met"}]}
        return {}
    monkeypatch.setattr(mcp, "dispatch", fake_dispatch)
    out = gate(".", criteria="must do X", files=["m.py"])
    assert out["verdict"] == "fail" and out["spec"]["verdict"] == "fail"
    assert any("intent not met" in i.get("message", "") for i in out["issues"])


def test_openai_tool_schema_shape():
    tools = openai_tools()
    assert tools[0]["type"] == "function"
    fn = tools[0]["function"]
    assert fn["name"] == "verel_gate" and "parameters" in fn
    assert fn["parameters"]["type"] == "object" and "repo" in fn["parameters"]["properties"]


def test_anthropic_tool_schema_shape():
    t = anthropic_tools()[0]
    assert t["name"] == "verel_gate" and t["input_schema"]["type"] == "object"
    assert "criteria" in t["input_schema"]["properties"]


def test_run_tool_call_dispatches(tmp_path, monkeypatch):
    import verel.mcp_server as mcp
    monkeypatch.setattr(mcp, "dispatch", lambda n, a: {"verdict": "pass", "issues": []})
    # accepts both a JSON string and a dict (different SDKs hand one or the other)
    assert run_tool_call("verel_gate", json.dumps({"repo": "."}))["verdict"] == "pass"
    assert run_tool_call("verel_gate", {"repo": "."})["verdict"] == "pass"


def test_run_tool_call_unknown_tool():
    assert "error" in run_tool_call("nope", {})


def test_lazy_reexport_from_integrations():
    import verel.integrations as I
    assert callable(I.gate) and callable(I.openai_tools)
