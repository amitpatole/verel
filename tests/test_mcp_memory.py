"""Phase 4 — the MCP surfaces for graded conversational memory (dispatch-level, no brain/LLM)."""

from verel.mcp_server import TOOLS, _tool_recall, _tool_remember_conversation


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
    # round-7 F-R7-2: a giant `role` (which _normalize ALSO renders) must not dodge the cap
    role_amplified = [{"role": "R" * 50_000, "content": "x"}] * 1000
    assert "error" in _tool_remember_conversation({"transcript": role_amplified, "scope": "team"})


def test_recall_without_scope_does_not_leak_other_scopes():
    # round-11 Finding A: a missing / empty / non-string scope must NOT become an unfiltered full-store
    # read. It defaults to the least-privilege `team` scope (fenced to team + global via the lattice),
    # never exposing user:/repo:/org/other-principal memory.
    import verel.mcp_server as M
    from verel.memory.view import MemoryKind, MemoryRecord, make_id, make_key
    mem = M._brain()
    for sc in ("team", "org", "global", "user:alice", "repo:secret"):
        k = make_key("x", "secret_in", sc)
        mem.write(MemoryRecord(id=make_id(k), kind=MemoryKind.FACT, subject="x", predicate="secret_in",
                               text=sc, scope=sc, subj_pred_key=k))
    allowed = {"team", "global"}
    for args in ({"query": "x secret_in"},                       # no scope
                 {"query": "x secret_in", "scope": 123},         # non-string scope
                 {"query": "x secret_in", "scope": ""},          # empty scope
                 {"query": "x secret_in", "token_budget": 500}):  # budgeted, no scope
        out = _tool_recall(args)
        got = {r["scope"] for r in out["records"]}
        assert got <= allowed, f"leaked scopes {got - allowed} for args {args}"
