"""Tests for DC-05: MCP per-tool ACL — verel_build_tool requires VEREL_ALLOW_BUILD_TOOL=1."""


from verel.mcp_server import _PRIVILEGED_TOOLS, _check_tool_authz, dispatch


def test_privileged_tools_dict_contains_build_tool():
    assert "verel_build_tool" in _PRIVILEGED_TOOLS
    assert _PRIVILEGED_TOOLS["verel_build_tool"] == "VEREL_ALLOW_BUILD_TOOL"


def test_check_tool_authz_denied_without_env(monkeypatch):
    monkeypatch.delenv("VEREL_ALLOW_BUILD_TOOL", raising=False)
    err = _check_tool_authz("verel_build_tool")
    assert err is not None
    assert "VEREL_ALLOW_BUILD_TOOL" in err


def test_check_tool_authz_allowed_with_env(monkeypatch):
    monkeypatch.setenv("VEREL_ALLOW_BUILD_TOOL", "1")
    err = _check_tool_authz("verel_build_tool")
    assert err is None


def test_check_tool_authz_non_privileged_tools_always_pass():
    for name in ("verel_gate", "verel_verify", "verel_recall", "verel_remember",
                 "verel_sight", "verel_ci_check", "verel_smell"):
        assert _check_tool_authz(name) is None


def test_dispatch_build_tool_denied_without_env(monkeypatch):
    monkeypatch.delenv("VEREL_ALLOW_BUILD_TOOL", raising=False)
    result = dispatch("verel_build_tool", {"name": "x", "capability": "y"})
    assert "error" in result
    assert "VEREL_ALLOW_BUILD_TOOL" in result["error"]


def test_dispatch_build_tool_denied_does_not_execute(monkeypatch):
    """The fn must never be called — confirm by checking the error is the ACL error, not a tool error."""
    monkeypatch.delenv("VEREL_ALLOW_BUILD_TOOL", raising=False)
    result = dispatch("verel_build_tool", {})
    assert "error" in result
    # If the tool had been called it would fail with "name and capability ... required" — not the ACL msg
    assert "VEREL_ALLOW_BUILD_TOOL" in result["error"]


def test_dispatch_gate_not_affected_by_acl(tmp_path):
    """ACL must not gate non-privileged tools even when VEREL_ALLOW_BUILD_TOOL is unset."""
    result = dispatch("verel_gate", {"repo": str(tmp_path)})
    # tmp_path exists but has no code — gate will run and return a verdict (or unsupported language)
    # The point is: no "VEREL_ALLOW_BUILD_TOOL" error appears.
    assert "VEREL_ALLOW_BUILD_TOOL" not in result.get("error", "")


def test_dispatch_unknown_tool_returns_error():
    result = dispatch("verel_nonexistent", {})
    assert "error" in result
    assert "unknown tool" in result["error"]
