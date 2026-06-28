"""Phase 4 — the MCP surfaces for graded conversational memory (dispatch-level, no brain/LLM)."""

from verel.mcp_server import TOOLS, _tool_remember_conversation


def test_tools_registered_with_schemas():
    assert "verel_remember_conversation" in TOOLS
    rc = TOOLS["verel_recall"]["schema"]["properties"]
    assert "token_budget" in rc  # budgeted graded-first recall is exposed on verel_recall
    conv = TOOLS["verel_remember_conversation"]["schema"]
    assert conv["required"] == ["transcript"] and "transcript" in conv["properties"]


def test_remember_conversation_validates_transcript_before_touching_brain_or_llm():
    # a missing/empty transcript fails closed with a clear error — no brain or LLM key needed
    for bad in ({}, {"transcript": ""}, {"transcript": []}, {"transcript": 123}):
        out = _tool_remember_conversation(bad)
        assert "error" in out
