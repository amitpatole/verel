"""PostgresMemory — the shared MemoryView contract + concurrency + security proofs, against a LIVE
Postgres. Gated behind `VEREL_PG_SMOKE=1` (like the mem0 smoke) so the default offline run skips it.

Bring a Postgres+pgvector up first, e.g.:
    docker run -d --name verel-pg -p 5433:5432 -e POSTGRES_PASSWORD=verel -e POSTGRES_DB=verel \
        pgvector/pgvector:pg16
    psql postgresql://postgres:verel@127.0.0.1:5433/verel -c 'CREATE EXTENSION IF NOT EXISTS vector'
Then: VEREL_PG_SMOKE=1 pytest tests/test_pg_contract.py
"""

from __future__ import annotations

import os
import threading

import pytest
from memory_contract import CONTRACT_CHECKS, make_fact

from verel.memory.embed import HashEmbedder

# Tests that need a LIVE Postgres carry @requires_pg; the pure security/unit tests below run always.
requires_pg = pytest.mark.skipif(
    not os.environ.get("VEREL_PG_SMOKE"), reason="set VEREL_PG_SMOKE=1 with a live Postgres")

DSN = os.environ.get("VEREL_POSTGRES_URL", "postgresql://postgres:verel@127.0.0.1:5433/verel")


def _fresh(embedder=None):
    """A PostgresMemory on a TRUNCATEd table — a clean, empty store per check."""
    from verel.memory.pg_backend import PostgresMemory

    mem = PostgresMemory(DSN, embedder=embedder)
    with mem._conn.cursor() as cur:
        cur.execute("TRUNCATE memory")
    mem._conn.commit()
    return mem


# ---- the full contract, lexical AND ANN (HashEmbedder) ----------------------
@requires_pg
@pytest.mark.parametrize("embedder", [None, HashEmbedder()],
                         ids=["lexical", "hash-ann"])
@pytest.mark.parametrize("check", CONTRACT_CHECKS, ids=lambda c: c.__name__)
def test_contract(check, embedder):
    check(_fresh(embedder))


# ---- concurrency proof: no lost corroboration under N concurrent writers -----
@requires_pg
def test_concurrent_same_text_corroboration_is_exact():
    # N threads each (own connection) assert the IDENTICAL claim K times. Every write after the first
    # is a corroboration; the advisory-locked merge must serialize them, so support_count == N*K
    # exactly and there is exactly ONE row — no lost update.
    _fresh()  # truncate
    n, k = 8, 5
    barrier = threading.Barrier(n)

    def worker():
        from verel.memory.pg_backend import PostgresMemory
        mem = PostgresMemory(DSN)
        barrier.wait()  # maximize contention
        for _ in range(k):
            mem.write(make_fact())
        mem.close()

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from verel.memory.pg_backend import PostgresMemory
    m = PostgresMemory(DSN)
    rows = m.all()
    assert len(rows) == 1
    assert rows[0].support_count == n * k  # every concurrent corroboration counted, none lost
    m.close()


@requires_pg
def test_concurrent_distinct_text_supersession_loses_nothing():
    # N threads each supersede the same key with a DISTINCT value. Serialized, the result is exactly
    # one row whose correction chain records the OTHER N-1 superseded values (none silently dropped).
    _fresh()
    n = 8
    barrier = threading.Barrier(n)

    def worker(i):
        from verel.memory.pg_backend import PostgresMemory
        mem = PostgresMemory(DSN)
        barrier.wait()
        mem.write(make_fact(text=f"value-{i}"))
        mem.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from verel.memory.pg_backend import PostgresMemory
    m = PostgresMemory(DSN)
    rows = m.all()
    assert len(rows) == 1
    chain = rows[0].detail.get("corrections", [])
    assert len(chain) == n - 1  # current value + N-1 in the chain = N writes, nothing lost
    m.close()


# ---- security: SQL injection via scope/kind is bound, never interpolated -----
@requires_pg
def test_scope_value_is_bound_not_interpolated():
    m = _fresh()
    m.write(make_fact(scope="repo:x"))
    # a classic injection payload as the scope value must be treated as a literal (no rows, no error,
    # table intact) — proof the WHERE filter binds values rather than string-building SQL.
    evil = "repo:x'; DROP TABLE memory; --"
    assert m.recall("max-width", scope=evil) == []
    assert m.all(scope=evil) == []
    assert len(m.all()) == 1  # table NOT dropped
    m.close()


# ---- security: a routable host without validating TLS is refused (fail closed) -
# Red-team cluster A: the guard must resolve the host the way libpq actually connects — every shape
# below reaches a routable host, so every one must be REFUSED without verify-full/verify-ca.
@pytest.mark.parametrize("dsn", [
    "postgresql://user:pw@db.example.com:5432/verel",
    "postgresql://db.example.com/verel",                 # NO userinfo
    "host=db.example.com dbname=verel user=postgres",    # keyword form
    "hostaddr=10.0.0.5 dbname=verel user=verel",         # hostaddr=, no host= (the CRITICAL bypass)
    "postgresql:///verel?hostaddr=10.0.0.5",             # hostaddr= in URL query
    "host=\tdb.example.com dbname=verel",                # tab after host=
    "host=localhost,db.example.com dbname=verel",        # comma-list: 2nd host is routable
    "host=db1.example.com host=db2.example.com dbname=verel",  # duplicate host= (libpq uses last)
])
def test_routable_host_without_tls_refused(dsn):
    from verel.memory.pg_backend import PostgresMemory

    with pytest.raises(ValueError, match="validating TLS"):
        PostgresMemory(dsn)


def test_pghost_env_target_is_guarded(monkeypatch):
    # Red-team cluster A: PGHOST/PGHOSTADDR/PGSSLMODE env supply the target/mode libpq uses even when
    # the DSN omits them — the guard must see them too, not just the DSN string.
    from verel.memory.pg_backend import PostgresMemory

    monkeypatch.setenv("PGHOST", "db.example.com")
    with pytest.raises(ValueError, match="validating TLS"):
        PostgresMemory("dbname=verel user=verel")  # no host in the DSN at all


def test_routable_host_allowed_with_validating_tls():
    # The guard must NOT over-refuse: a routable host WITH verify-full is allowed (it will then fail to
    # connect, scrubbed — but it must get past the TLS guard, i.e. not raise the guard ValueError).
    from verel.memory.pg_backend import PostgresMemory

    with pytest.raises(RuntimeError):  # connect failure (scrubbed), NOT the guard ValueError
        PostgresMemory("host=db.invalid.example port=5599 sslmode=verify-full dbname=verel connect_timeout=1")


def test_loopback_shapes_not_over_refused(monkeypatch):
    import verel.memory.pg_backend as pg
    from verel.memory.pg_backend import _routable_hosts

    # genuinely-local targets resolve to no routable host (guard correctly skipped)
    monkeypatch.delenv("PGHOST", raising=False)
    monkeypatch.delenv("PGHOSTADDR", raising=False)
    assert [h for h in _routable_hosts("dbname=verel") if not pg.is_loopback(h)] == []
    assert [h for h in _routable_hosts("postgresql://127.0.0.1:5432/verel") if not pg.is_loopback(h)] == []
    # but routable shapes are surfaced
    assert "db.example.com" in _routable_hosts("postgresql://db.example.com/verel")
    assert "10.0.0.5" in _routable_hosts("hostaddr=10.0.0.5 dbname=verel")


# ---- security: the DSN/password never appears in any error (cluster E) --------
def test_dsn_scrubbed_from_connection_error():
    from verel.memory.pg_backend import PostgresMemory

    secret = "postgresql://postgres:sup3rs3cret@127.0.0.1:5599/nope"  # nosec B105 — test literal, unreachable port
    with pytest.raises(RuntimeError) as ei:
        PostgresMemory(secret)
    assert "sup3rs3cret" not in str(ei.value) and secret not in str(ei.value)


def test_scrub_redacts_url_userinfo_and_keyword_passwords():
    from verel.memory.pg_backend import _scrub

    dsn = "postgresql://app:Sup3rS3cret@[bad"
    # simulate a libpq parse error that echoes the DSN verbatim (the from_env make_conninfo leak path)
    assert "Sup3rS3cret" not in _scrub(ValueError(f'bad URI: "{dsn}"'), dsn)
    # and forms where only a fragment of the credential is echoed (not the whole DSN)
    assert "Sup3rS3cret" not in _scrub(ValueError("conn user=app password=Sup3rS3cret host=x"), "other")
    assert "Sup3rS3cret" not in _scrub(ValueError("postgresql://app:Sup3rS3cret@h/db failed"), "other")


def test_from_env_make_conninfo_error_is_scrubbed(monkeypatch):
    # Red-team cluster E/#1: a malformed credentialed DSN made make_conninfo raise OUTSIDE any
    # try/except, leaking the password. from_env must scrub it.
    from verel.memory.pg_backend import PostgresMemory

    monkeypatch.setenv("VEREL_POSTGRES_URL", "postgresql://app:Sup3rS3cret@[bad")
    monkeypatch.setenv("VEREL_PG_SSLMODE", "verify-full")  # forces the make_conninfo branch
    with pytest.raises(RuntimeError) as ei:
        PostgresMemory.from_env()
    assert "Sup3rS3cret" not in str(ei.value)


# ---- security/correctness: one failed op must NOT brick the shared connection (cluster B) ----
@requires_pg
def test_error_does_not_brick_connection():
    m = _fresh()
    m.write(make_fact())
    # force a statement error inside a txn (invalid kind value can't deserialize / bad query)
    with pytest.raises(Exception):
        with m._txn(dict_rows=False) as cur:
            cur.execute("SELECT * FROM no_such_table_xyz")
    # the connection must still be usable — the rollback in _txn cleared the aborted transaction
    assert len(m.all()) == 1
    r = m.write(make_fact(text="still works"))
    assert r is not None
    m.close()


# ---- correctness: decay is concurrency-safe and never clobbers a racing write (cluster C) ----
@requires_pg
def test_decay_does_not_clobber_concurrent_corroboration():
    import threading
    m = _fresh()
    r = m.write(make_fact())          # support_count == 1, weak
    # drive it weak so decay would consider it, but corroborate concurrently so it must survive intact
    barrier = threading.Barrier(2)

    def corroborate_hard():
        from verel.memory.pg_backend import PostgresMemory
        w = PostgresMemory(DSN)
        barrier.wait()
        for _ in range(10):
            w.write(make_fact())       # same text → corroborates: support++, strength=1.0
        w.close()

    t = threading.Thread(target=corroborate_hard)
    t.start()
    barrier.wait()
    for _ in range(10):
        m.decay(now=10_000_000.0)      # hammer decay concurrently
    t.join()
    got = m.get(r.id)
    assert got is not None             # never wrongly pruned (it was being reinforced)
    assert got.support_count == 11     # 1 + 10 corroborations, none lost to a decay clobber
    m.close()


# ---- confirming red-team: post-connect TLS verification requires VALIDATING TLS ----
def test_verify_transport_requires_validating_tls_on_routable_peer():
    # The authoritative check reads the EFFECTIVE sslmode libpq used (get_parameters reports it even
    # from a service file). A routable peer must use verify-full/verify-ca; encrypted-but-unvalidated
    # (require/prefer/disable/default) is refused — closing the service-file MITM the round-5 fix missed.
    from types import SimpleNamespace

    from verel.memory.pg_backend import _verify_transport

    def fake(host, sslmode):
        state = {"closed": False}
        return SimpleNamespace(
            info=SimpleNamespace(host=host, hostaddr=host,
                                 get_parameters=lambda: {"sslmode": sslmode} if sslmode else {}),
            close=lambda: state.__setitem__("closed", True)), state

    for bad in (None, "disable", "allow", "prefer", "require"):   # routable + non-validating → refuse
        conn, state = fake("203.0.113.7", bad)
        with pytest.raises(ValueError, match="validating TLS"):
            _verify_transport(conn)
        assert state["closed"] is True, bad
    _verify_transport(fake("203.0.113.7", "verify-full")[0])      # routable + verify-full → ok
    _verify_transport(fake("203.0.113.7", "verify-ca")[0])        # routable + verify-ca → ok
    _verify_transport(fake("127.0.0.1", None)[0])                 # loopback → ok (zero-config)
    _verify_transport(fake("", None)[0])                          # unix socket / no host → ok


def test_canonical_detail_totality():
    # Red-team R6: flags must be canonicalized so the decay jsonb access can never abort and never
    # diverges from Python truthiness. Non-object JSON → '{}'; flags → real bools; bad ttl dropped.
    import json as _json

    from verel.memory.pg_backend import _canonical_detail

    assert _canonical_detail("[1,2,3]") == "{}"          # array → {}
    assert _canonical_detail("42") == "{}"               # scalar → {}
    assert _canonical_detail("not json{{") == "{}"       # garbage → {}
    assert _json.loads(_canonical_detail('{"pinned":"yes"}'))["pinned"] is True   # truthy str → True
    assert _json.loads(_canonical_detail('{"pinned":"false"}'))["pinned"] is True  # non-empty str → True (Python)
    assert _json.loads(_canonical_detail('{"pinned":0}'))["pinned"] is False       # 0 → False
    assert "ttl_s" not in _json.loads(_canonical_detail('{"ttl_s":"abc"}'))         # non-numeric ttl dropped
    assert _json.loads(_canonical_detail('{"ttl_s":"3600"}'))["ttl_s"] == 3600.0    # numeric-ish coerced
    assert _json.loads(_canonical_detail('{"corrections":[{"text":"x"}]}'))["corrections"]  # other keys kept


@requires_pg
def test_live_loopback_connection_passes_transport_check():
    # The fixed __init__ runs _verify_transport on every connect; the loopback contract DSN must still
    # connect (regression: the new guard must not over-refuse the zero-config local path).
    m = _fresh()
    assert m.get("nope") is None
    m.close()


# ---- confirming red-team: NO detail_json value class can wedge the decay pass (#3/#4/#5/#6) ----
@requires_pg
@pytest.mark.parametrize("poison_detail", [
    "this is not json{{",      # unparseable
    "[1,2,3]",                 # valid JSON, array (jsonb_set 'cannot set path' / boolean cast)
    "42",                      # valid JSON, scalar
    '{"pinned":"yes"}',        # non-canonical boolean (::boolean cast abort)
    '{"pinned":1}',            # number-as-bool
    '{"volatile":"maybe"}',    # non-canonical volatile
    '{"ttl_s":"not-a-number"}',  # non-numeric ttl (::float cast abort)
    '{"ttl_s":[1]}',           # array ttl
], ids=["garbage", "array", "scalar", "pinned-str", "pinned-num", "volatile-str", "ttl-str", "ttl-arr"])
def test_no_detail_value_class_wedges_decay(poison_detail):
    m = _fresh()
    poison = make_fact(text="poison", subject="bad", predicate="json")
    poison.detail_json = poison_detail                  # a corrupt/non-canonical replicated row
    m.apply_replica(poison)
    weak = _weak_seed(m, "weak", "p")                   # an eligible-to-prune row
    m.decay(now=10_000_000.0)                           # must COMPLETE, never abort the whole pass
    assert m.get(weak.id) is None                       # the eligible row WAS pruned (pass ran to completion)
    m.close()


def _weak_seed(m, subject, predicate):
    from verel.memory import Trust
    rec = make_fact(text="weak", subject=subject, predicate=predicate)
    rec.trust, rec.support_count, rec.epistemic_confidence, rec.retrieval_strength = (
        Trust.CANDIDATE, 1, 0.3, 0.1)
    return m.apply_replica(rec)


# ---- confirming red-team: attacker-controlled recall k is clamped (#2) ----
@requires_pg
@pytest.mark.parametrize("embedder", [None, HashEmbedder()], ids=["lexical", "hash-ann"])
def test_recall_k_is_clamped(embedder):
    # An absurd k (e.g. from an unclamped HTTP /recall body) must NOT drive an unbounded LIMIT/fetch.
    m = _fresh(embedder)
    m.write(make_fact())
    hits = m.recall("max-width card width", scope="repo:x", k=10**9)
    assert len(hits) <= 1000           # clamped to _MAX_RECALL_K, not a billion-row fetch
    m.close()


@requires_pg
@pytest.mark.parametrize("bad_k", [float("inf"), float("-inf"), float("nan"), "lots", None])
def test_recall_degenerate_k_does_not_raise(bad_k):
    # Red-team R6: k=1e999 parses to float('inf'); int(inf) raises OverflowError (NOT ValueError) which
    # the clamp must catch, falling back to the default instead of a 500/unhandled exception.
    m = _fresh()
    m.write(make_fact())
    assert m.recall("max-width card width", scope="repo:x", k=bad_k) is not None
    m.close()
