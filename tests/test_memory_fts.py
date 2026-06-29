"""v1.3.0 — FTS5 BM25 lexical retrieval in LocalMemory (the real retrieval-quality upgrade).

Acceptance: recall uses term-weighted BM25 over subject+predicate+text with SQL-side scope/kind
filtering; the index stays in sync on supersede + prune; verified-first ranking is preserved; and an
UNTRUSTED query is sanitized so FTS5 operators can't inject, error the matcher, or scan wide."""

from verel.memory import LocalMemory
from verel.memory.local import _fts_match
from verel.memory.view import MemoryKind, MemoryRecord, Trust, make_id, make_key


def _fact(s, p, t, scope="user:dana", trust=Trust.CANDIDATE):
    k = make_key(s, p, scope)
    return MemoryRecord(id=make_id(k), kind=MemoryKind.FACT, subject=s, predicate=p, text=t,
                        scope=scope, subj_pred_key=k, trust=trust)


def _seed(mem, *facts):
    for f in facts:
        mem.write(f)


def test_fts_is_enabled_on_this_build():
    # the default path needs FTS5; if a build lacks it, the suite still runs on the token-overlap
    # fallback, but we assert it IS available here so the FTS path is actually exercised.
    assert LocalMemory()._fts is True


def test_bm25_matches_a_term_in_the_text_not_just_subject_predicate():
    mem = LocalMemory()
    _seed(mem, _fact("Dana", "editor", "uses neovim with a custom tmux config"),
          _fact("Dana", "theme", "dark mode"))
    hits = mem.recall("neovim", scope="user:dana", k=5)
    assert [h.predicate for h in hits] == ["editor"]   # found via the text body


def test_verified_first_preserved_under_bm25():
    mem = LocalMemory()
    _seed(mem, _fact("role", "access", "needs prod database read", trust=Trust.CANDIDATE),
          _fact("team", "access", "needs prod database read", trust=Trust.VERIFIED))
    hits = mem.recall("prod database read access", scope="user:dana", k=5)
    assert hits[0].trust == Trust.VERIFIED   # trust re-rank wins at equal relevance


def test_scope_and_kind_filtered_in_sql():
    mem = LocalMemory()
    _seed(mem, _fact("x", "topic", "alpha signal", scope="team"),
          _fact("y", "topic", "alpha signal", scope="user:bob"),
          _fact("z", "topic", "alpha signal", scope="global"))
    got = {h.scope for h in mem.recall("alpha signal", scope="team", k=10)}
    assert got <= {"team", "global"}    # never leaks user:bob via recall scope filtering


def test_index_stays_in_sync_on_supersede():
    mem = LocalMemory()
    _seed(mem, _fact("Dana", "prefers", "dark mode"))
    mem.write(_fact("Dana", "prefers", "light mode"))   # supersede: text changes
    assert mem.recall("light", scope="user:dana", k=5)          # new text is searchable
    assert mem.recall("dark", scope="user:dana", k=5) == []     # old text no longer matches


def test_index_cleared_on_prune():
    mem = LocalMemory()
    _seed(mem, _fact("ephemeral", "note", "transient detail", trust=Trust.CANDIDATE))
    rid = make_id(make_key("ephemeral", "note", "user:dana"))
    for _ in range(6):
        mem.contradict(rid)            # drive below the floor so decay prunes it
    mem.decay(now=10**12, half_life_s=1.0)
    assert mem.recall("transient", scope="user:dana", k=5) == []   # gone from the FTS index too


def test_untrusted_query_operators_are_neutralized():
    mem = LocalMemory()
    _seed(mem, _fact("Dana", "prefers", "dark mode"))
    # every one of these would be valid FTS5 syntax (and could error or scan wide) if passed raw;
    # the sanitizer reduces each to word tokens, so none errors and none over-matches.
    for hostile in ('dark" OR 1=1', "dark NEAR/5 mode", "prefers:dark", "dark*", "(dark OR x)",
                    "dark AND NOT mode", '"', "*", "^dark$", "dark -mode", "" , "   "):
        hits = mem.recall(hostile, scope="user:dana", k=5)   # must not raise
        assert isinstance(hits, list)
    assert mem.recall("dark", scope="user:dana", k=5)        # a real term still works


def test_fts_match_sanitizer_is_quote_safe_and_bounded():
    assert _fts_match('a" OR "1"="1') == '"a" OR "or" OR "1" OR "1"'   # operators become literals
    assert _fts_match("") == "" and _fts_match("!!!") == ""            # nothing to match
    assert _fts_match("x " * 100).count(" OR ") <= 31                  # term count capped (≤32 terms)
    assert all(len(t.strip('"')) <= 64 for t in _fts_match("z" * 500).split(" OR "))  # term length capped


def test_huge_query_does_not_blow_up():
    import time
    mem = LocalMemory()
    _seed(mem, _fact("Dana", "prefers", "dark mode"))
    t = time.perf_counter()
    mem.recall("word " * 5000, scope="user:dana", k=5)   # 5000-term query → capped, linear
    assert time.perf_counter() - t < 2.0


def test_recall_k_is_clamped_and_bounded():
    # v1.3.0 security: a large caller k drove both the SQL fetch AND a committed write per result.
    # k is now clamped (mirrors pg_backend) and reinforcement is batched into one transaction.
    import time
    mem = LocalMemory()
    for i in range(2000):
        mem.write(_fact(f"s{i}", "note", "alpha signal", scope="team"))
    t = time.perf_counter()
    hits = mem.recall("alpha signal", scope="team", k=100000)   # absurd k
    assert len(hits) <= 1000                                    # clamped
    assert time.perf_counter() - t < 3.0                       # bounded (was ~55s unclamped)


def test_partial_fts_index_is_reconciled_on_open(tmp_path):
    # v1.3.0: a partial/stale FTS index (e.g. legacy surgery) must be rebuilt on open so orphaned
    # memory rows can't stay invisible to recall.
    p = str(tmp_path / "brain.db")
    mem = LocalMemory(p)
    for i in range(10):
        mem.write(_fact(f"x{i}", "n", "findme token", scope="team"))
    mem._db.execute("DELETE FROM memory_fts WHERE id IN (SELECT id FROM memory_fts LIMIT 7)")
    mem._db.commit()
    mem._db.close()
    reopened = LocalMemory(p)
    assert len(reopened.recall("findme", scope="team", k=20)) == 10   # all reconciled
