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


def test_remember_conversation_scope_allowlist_blocks_shared_and_evasions():
    # round-6 F-MCP2: an untrusted transcript may only write team / repo:* / session:* — global, org,
    # meta:, and ANOTHER user's scope are refused, including case/whitespace evasions that make_key
    # would normalize back into the protected namespace. Refusal happens before any brain/LLM touch.
    t = [{"role": "user", "content": "hi"}]
    for bad_scope in ("global", "org", "meta:authors", "user:bob", "User:bob", " user:bob ",
                      "GLOBAL", " Org ", "everyone"):
        out = _tool_remember_conversation({"transcript": t, "scope": bad_scope})
        assert "error" in out, f"scope {bad_scope!r} should be refused"


def test_remember_conversation_list_transcript_is_size_capped():
    # round-5/6 F3: a list-form transcript is capped on BOTH turns and total content chars
    over_turns = [{"role": "user", "content": "x"}] * 1001
    assert "error" in _tool_remember_conversation({"transcript": over_turns, "scope": "team"})
    big = [{"role": "user", "content": "x" * 20001}]
    assert "error" in _tool_remember_conversation({"transcript": big, "scope": "team"})
