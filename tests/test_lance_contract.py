"""LanceMemory — the shared MemoryView contract (lexical AND ANN) + security proofs, against a real
EMBEDDED LanceDB dataset in a tmp dir. No server needed, so these RUN whenever lancedb is installed
(skip otherwise, like the mem0/sight tests).

Each check gets a fresh dataset and the backend is closed before pytest removes the tmp dir (Lance can
segfault if its directory is torn down while still open).
"""

from __future__ import annotations

import pytest
from memory_contract import CONTRACT_CHECKS, make_fact

from verel.memory.embed import HashEmbedder

lancedb = pytest.importorskip("lancedb", reason="pip install verel[lancedb]")


def _mem(tmp_path, embedder=None, sub="ds"):
    from verel.memory.lance_backend import LanceMemory

    return LanceMemory(str(tmp_path / sub), embedder=embedder)


# ---- the full contract, lexical AND ANN (HashEmbedder) ----------------------
@pytest.mark.parametrize("embedder", [None, HashEmbedder()], ids=["lexical", "hash-ann"])
@pytest.mark.parametrize("check", CONTRACT_CHECKS, ids=lambda c: c.__name__)
def test_contract(check, embedder, tmp_path):
    mem = _mem(tmp_path, embedder)
    try:
        check(mem)
    finally:
        mem.close()


# ---- security: a `.where()` SQL-injection payload as a record id is escaped, not executed ----
def test_where_injection_via_id_is_escaped(tmp_path):
    mem = _mem(tmp_path)
    try:
        a = mem.write(make_fact())
        mem.write(make_fact(text="second", subject="other", predicate="p"))
        # a crafted id that, unescaped, would break out of the string literal and drop/return all rows
        evil = "' OR '1'='1"
        assert mem.get(evil) is None            # matches nothing (treated as a literal id)
        assert len(mem.all()) == 2              # table intact, nothing leaked/destroyed
        assert mem.get(a.id) is not None        # the real id still resolves
    finally:
        mem.close()


def test_lit_escapes_quotes_and_rejects_control_chars():
    from verel.memory.lance_backend import _lit

    assert _lit("a'b") == "'a''b'"              # single-quote doubled (SQL escape)
    assert _lit("repo:x") == "'repo:x'"
    with pytest.raises(ValueError):
        _lit("a\nb")                            # control char rejected
    with pytest.raises(TypeError):
        _lit(123)                               # non-str rejected


# ---- red-team HIGH: ANN recall must filter BEFORE the vector limit (no crowding) ----
def test_ann_recall_filters_before_limit(tmp_path):
    # Seed MANY relevant-but-rejected records (more than the ANN window max(k*4,20)) plus one valid
    # in-scope record. A correct backend (prefilter) still returns the valid one; the old post-filter
    # bug returned [] because the rejected neighbours saturated the window.
    from verel.memory import Trust

    mem = _mem(tmp_path, HashEmbedder())
    try:
        for i in range(40):
            r = mem.write(make_fact(text="button color theme", subject=f"bad{i}", predicate="p"))
            for _ in range(6):
                mem.contradict(r.id)                      # drive each to REJECTED
            assert mem.get(r.id).trust is Trust.REJECTED
        good = mem.write(make_fact(text="button color theme", subject="good", predicate="p"))
        hits = mem.recall("button color theme", scope="repo:x", k=5)
        assert any(h.id == good.id for h in hits)         # the valid record is NOT crowded out
        assert all(h.trust is not Trust.REJECTED for h in hits)
    finally:
        mem.close()


def test_recall_scope_filter_is_injection_safe(tmp_path):
    # scope now reaches the ANN prefilter predicate → it must be escaped (a crafted scope can't break
    # the filter or leak other scopes).
    mem = _mem(tmp_path, HashEmbedder())
    try:
        mem.write(make_fact(scope="repo:x"))
        mem.write(make_fact(text="other", subject="o", predicate="p", scope="repo:secret"))
        evil = "repo:x' OR '1'='1"
        assert mem.recall("max-width card width", scope=evil) == []   # matches nothing; no leak
        assert len(mem.all()) == 2                                    # intact
    finally:
        mem.close()


@pytest.mark.parametrize("embedder", [None, HashEmbedder()], ids=["lexical", "hash-ann"])
def test_persists_across_reopen(tmp_path, embedder):
    # Red-team HIGH: a persisted dataset must REOPEN cleanly (process restart / second from_env).
    # The single-process create-only tests missed this — reopening used to crash "table already
    # exists" because the table-existence check was always False.
    path = str(tmp_path / "ds")
    from verel.memory.lance_backend import LanceMemory

    m1 = LanceMemory(path, embedder=embedder)
    rec = m1.write(make_fact())
    m1.close()
    m2 = LanceMemory(path, embedder=embedder)   # reopen the SAME dataset
    try:
        got = m2.get(rec.id)
        assert got is not None and got.text == rec.text   # prior rows survive the reopen
        assert len(m2.all()) == 1
        m2.write(make_fact())                              # and it stays writable
        assert len(m2.all()) == 1                          # same key → corroborated, not duplicated
    finally:
        m2.close()


@pytest.mark.parametrize("first,second", [
    (HashEmbedder(256), None),                 # had embedder → reopened without (would silently degrade)
    (None, HashEmbedder(256)),                 # no embedder → reopened with (vector column absent → write crash)
    (HashEmbedder(256), HashEmbedder(128)),    # dim change (would crash opaquely on write/recall)
], ids=["drop-embedder", "add-embedder", "dim-change"])
def test_reopen_with_changed_embedder_fails_closed(tmp_path, first, second):
    # Red-team HIGH: switching VEREL_EMBEDDER over the same dataset must raise a CLEAR error in
    # __init__, not crash opaquely on the first write/recall (or silently drop to lexical).
    from verel.memory.lance_backend import LanceMemory

    path = str(tmp_path / "ds")
    m1 = LanceMemory(path, embedder=first)
    m1.write(make_fact())
    m1.close()
    with pytest.raises(RuntimeError, match="vector dim|embedder"):
        LanceMemory(path, embedder=second)


def test_lance_rejects_bad_embedder_dim(tmp_path):
    # Red-team LOW: a custom embedder whose .dim is None/non-int/<=0 must fail with a CLEAR error at
    # construction, not an opaque int(None) TypeError.
    from verel.memory.lance_backend import LanceMemory

    class _BadDim:
        dim = None
        def embed(self, texts):
            return [[0.0] for _ in texts]

    with pytest.raises(RuntimeError, match="dim must be a positive int"):
        LanceMemory(str(tmp_path / "ds"), embedder=_BadDim())


def test_lance_catches_lying_embedder_dim_at_write(tmp_path):
    # Red-team HIGH: an embedder whose reported .dim disagrees with what embed() returns (e.g. an
    # OpenAI model dim mismatch) must raise a CLEAR error at write, not an opaque pyarrow mismatch.
    from verel.memory.lance_backend import LanceMemory

    class _Liar:
        dim = 4                                   # claims 4 …
        def embed(self, texts):
            return [[0.1, 0.2, 0.3] for _ in texts]   # … but returns 3

    mem = LanceMemory(str(tmp_path / "ds"), embedder=_Liar())
    try:
        with pytest.raises(RuntimeError, match="does not match its reported .dim|vector but the dataset"):
            mem.write(make_fact())
    finally:
        mem.close()


def test_use_after_close_raises_clear_error(tmp_path):
    # Confirming red-team: a closed backend must raise a clear RuntimeError, not an opaque
    # AttributeError from a nulled handle.
    mem = _mem(tmp_path)
    mem.write(make_fact())
    mem.close()
    for call in (lambda: mem.get("x"), lambda: mem.all(),
                 lambda: mem.recall("q", scope="repo:x"), lambda: mem.write(make_fact())):
        with pytest.raises(RuntimeError, match="closed"):
            call()


def test_contradict_is_atomic_under_lock(tmp_path):
    # The two-step lower-EC-then-maybe-reject runs as one critical section (regression: it used to
    # drop the lock between steps). Sanity: contradict still drives to REJECTED deterministically.
    from verel.memory import Trust

    mem = _mem(tmp_path)
    try:
        r = mem.write(make_fact())
        last = r
        for _ in range(5):
            last = mem.contradict(r.id)
        assert last.trust is Trust.REJECTED
    finally:
        mem.close()


# ---- decay tolerates malformed detail_json (Python apply_decay reads via r.detail) ----
def test_malformed_detail_json_does_not_break_decay(tmp_path):
    from verel.memory import Trust

    mem = _mem(tmp_path)
    try:
        poison = make_fact(text="poison", subject="bad", predicate="json")
        poison.detail_json = "not json{{"
        mem.apply_replica(poison)
        weak = make_fact(text="weak", subject="weak", predicate="p")
        weak.trust, weak.support_count, weak.epistemic_confidence, weak.retrieval_strength = (
            Trust.CANDIDATE, 1, 0.3, 0.1)
        mem.apply_replica(weak)
        mem.decay(now=10_000_000.0)             # completes; poison treated as flag-less
        assert mem.get(weak.id) is None         # the eligible row was pruned (pass ran)
    finally:
        mem.close()
