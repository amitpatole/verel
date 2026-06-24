"""G — the action gateway: classify → gate/approve → forward/block/dry-run, fail-closed."""

from verel.gateway import ActionClass, Decision, Gateway, Policy


class _Invoker:
    """Records every real invocation so a test can assert an action did NOT forward."""
    def __init__(self):
        self.calls = []

    def __call__(self, tool, args):
        self.calls.append((tool, args))
        return f"did:{tool}"


# ---- classification ----
def test_classify_by_name():
    p = Policy()
    assert p.classify("read_file") is ActionClass.SAFE
    assert p.classify("list_dirs") is ActionClass.SAFE
    assert p.classify("write_file") is ActionClass.CONSEQUENTIAL
    assert p.classify("create_pr") is ActionClass.CONSEQUENTIAL
    assert p.classify("delete_branch") is ActionClass.IRREVERSIBLE
    assert p.classify("deploy_prod") is ActionClass.IRREVERSIBLE
    assert p.classify("git_push") is ActionClass.IRREVERSIBLE


def test_unknown_tool_fails_closed_to_consequential():
    assert Policy().classify("frobnicate") is ActionClass.CONSEQUENTIAL  # never assumed read-only


def test_destructive_verb_with_safe_token_is_not_safe():
    # Regression (MEDIUM): a destructive verb must NOT ride a SAFE token into the ungated SAFE bucket.
    p = Policy()
    for tool in ("list_then_purge", "get_and_wipe", "read_then_kill", "fetch_and_flush",
                 "search_then_reset", "view_and_format", "deleteBranch", "deploy-prod"):
        assert p.classify(tool) is ActionClass.IRREVERSIBLE, tool


def test_token_matching_avoids_substring_false_positives():
    # Regression (LOW): token matching, not substring — benign names must NOT mis-classify as
    # IRREVERSIBLE just because a destructive verb is a substring of a token.
    p = Policy()
    assert p.classify("get_information") is ActionClass.SAFE   # 'information' ⊅ token 'format'
    assert p.classify("run_skill") is ActionClass.CONSEQUENTIAL  # 'skill' ⊅ 'kill' (no safe/conseq verb → fail closed)
    assert p.classify("get_preset") is ActionClass.SAFE       # 'preset' ⊅ 'reset'
    assert p.classify("read_clearance") is ActionClass.SAFE   # 'clearance' ⊅ 'clear'
    assert p.classify("list_skills") is ActionClass.SAFE      # 'skills' ⊅ 'kill'
    # but the real destructive tokens still fire:
    assert p.classify("clear_cache") is ActionClass.IRREVERSIBLE
    assert p.classify("reset_db") is ActionClass.IRREVERSIBLE


def test_overrides_and_permitted():
    p = Policy(overrides={"read_secrets": ActionClass.IRREVERSIBLE},
               deny={"rm_rf"}, allow={"read_file", "write_file"})
    assert p.classify("read_secrets") is ActionClass.IRREVERSIBLE
    assert not p.permitted("rm_rf")                 # deny wins
    assert p.permitted("read_file")
    assert not p.permitted("create_pr")             # allowlist excludes it


# ---- safe actions forward ----
def test_safe_action_forwards():
    inv = _Invoker()
    r = Gateway(inv).handle("read_file", {"path": "x"})
    assert r.decision is Decision.FORWARD and r.result == "did:read_file"
    assert inv.calls == [("read_file", {"path": "x"})]


# ---- consequential actions are gated ----
def test_consequential_forwards_on_gate_pass():
    inv = _Invoker()
    gw = Gateway(inv, gate=lambda t, a: {"verdict": "pass"})
    r = gw.handle("write_file", {"path": "x"})
    assert r.decision is Decision.FORWARD and r.verdict["verdict"] == "pass"
    assert inv.calls  # invoked


def test_consequential_blocked_on_gate_fail():
    inv = _Invoker()
    gw = Gateway(inv, gate=lambda t, a: {"verdict": "fail", "issues": [{"message": "broken"}]})
    r = gw.handle("write_file", {"path": "x"})
    assert r.decision is Decision.BLOCKED and not inv.calls  # NOT performed
    assert r.verdict["verdict"] == "fail"


def test_consequential_without_gate_fails_closed():
    inv = _Invoker()
    r = Gateway(inv).handle("create_pr", {})  # no gate configured
    assert r.decision is Decision.BLOCKED and not inv.calls  # fail closed — unverified write refused


def test_only_pass_forwards_a_consequential_action():
    # Regression (HIGH): only PASS forwards. warn/error/missing/None/non-dict are advisory or missing
    # evidence → BLOCKED (fail closed). A case/whitespace-variant of pass still forwards (defensive).
    for verdict in [{"verdict": "warn"}, {}, {"verdict": None}, {"verdict": "error"},
                    {"verdict": "fail"}, "not-a-dict", {"verdict": "warning"}]:
        inv = _Invoker()
        gw = Gateway(inv, gate=lambda t, a, v=verdict: v)
        assert gw.handle("write_file", {}).decision is Decision.BLOCKED and not inv.calls, verdict
    for ok in [{"verdict": "pass"}, {"verdict": " pass "}, {"verdict": "PASS"}]:
        inv = _Invoker()
        assert Gateway(inv, gate=lambda t, a, v=ok: v).handle("write_file", {}).decision is Decision.FORWARD


def test_gate_that_raises_fails_closed():
    inv = _Invoker()

    def boom(t, a):
        raise RuntimeError("ci timed out")
    r = Gateway(inv, gate=boom).handle("write_file", {})
    assert r.decision is Decision.BLOCKED and not inv.calls  # crashing gate → blocked, not crash/forward


# ---- irreversible actions: dry-run + human approval ----
def test_irreversible_dry_run_by_default():
    inv = _Invoker()
    r = Gateway(inv).handle("deploy_prod", {})
    assert r.decision is Decision.DRY_RUN and not inv.calls  # planned, NOT applied


def test_irreversible_applies_only_on_human_approval():
    inv = _Invoker()
    gw = Gateway(inv, approve=lambda t, a: True)
    r = gw.handle("delete_branch", {"name": "main"})
    assert r.decision is Decision.FORWARD and inv.calls  # approved → applied


def test_irreversible_needs_approval_when_dry_run_off_and_unapproved():
    inv = _Invoker()
    gw = Gateway(inv, policy=Policy(dry_run=False), approve=lambda t, a: False)
    r = gw.handle("drop_table", {})
    assert r.decision is Decision.NEEDS_APPROVAL and not inv.calls  # never auto-applies


def test_denied_tool_blocked_even_if_safe():
    inv = _Invoker()
    gw = Gateway(inv, policy=Policy(deny={"read_file"}))
    r = gw.handle("read_file", {})
    assert r.decision is Decision.BLOCKED and not inv.calls


def test_repo_gate_adapter(tmp_path, monkeypatch):
    import verel.mcp_server as mcp
    monkeypatch.setattr(mcp, "dispatch", lambda n, a: {"verdict": "pass", "issues": []})
    from verel.gateway import repo_gate
    assert repo_gate(str(tmp_path))("write_file", {})["verdict"] == "pass"
