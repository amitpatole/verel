"""RedisMemory — the shared MemoryView contract (lexical AND ANN) + concurrency + security proofs.

Live tests run against a Redis reachable at `VEREL_REDIS_URL` (default redis://127.0.0.1:6379/15, a
throwaway db that is flushed per test); they skip if no Redis is reachable. The pure security/unit
tests (URL guard, credential scrub) run whenever redis-py is installed.

Spin one up with: `docker run -d -p 6379:6379 redis:7` (or any local redis-server).
"""

from __future__ import annotations

import os
import threading

import pytest
from memory_contract import CONTRACT_CHECKS, make_fact

from verel.memory.embed import HashEmbedder

redis = pytest.importorskip("redis", reason="pip install verel[redis]")

URL = os.environ.get("VEREL_REDIS_URL", "redis://127.0.0.1:6379/15")


def _redis_up() -> bool:
    try:
        redis.Redis.from_url(URL, socket_connect_timeout=1).ping()
        return True
    except Exception:
        return False


requires_redis = pytest.mark.skipif(not _redis_up(), reason=f"no Redis reachable at {URL}")


def _fresh(embedder=None):
    from verel.memory.redis_backend import RedisMemory

    redis.Redis.from_url(URL).flushdb()
    return RedisMemory(URL, embedder=embedder)


# ---- the full contract, lexical AND ANN (HashEmbedder) ----------------------
@requires_redis
@pytest.mark.parametrize("embedder", [None, HashEmbedder()], ids=["lexical", "hash-ann"])
@pytest.mark.parametrize("check", CONTRACT_CHECKS, ids=lambda c: c.__name__)
def test_contract(check, embedder):
    check(_fresh(embedder))


# ---- concurrency proof: no lost corroboration under N concurrent writers -----
@requires_redis
def test_concurrent_same_text_corroboration_is_exact():
    _fresh()
    n, k = 8, 5
    barrier = threading.Barrier(n)

    def worker():
        from verel.memory.redis_backend import RedisMemory
        mem = RedisMemory(URL)
        barrier.wait()
        for _ in range(k):
            mem.write(make_fact())
        mem.close()

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from verel.memory.redis_backend import RedisMemory
    m = RedisMemory(URL)
    rows = m.all()
    assert len(rows) == 1
    assert rows[0].support_count == n * k   # WATCH/MULTI retry → every corroboration counted, none lost
    m.close()


@requires_redis
def test_concurrent_distinct_text_supersession_loses_nothing():
    _fresh()
    n = 8
    barrier = threading.Barrier(n)

    def worker(i):
        from verel.memory.redis_backend import RedisMemory
        mem = RedisMemory(URL)
        barrier.wait()
        mem.write(make_fact(text=f"value-{i}"))
        mem.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from verel.memory.redis_backend import RedisMemory
    m = RedisMemory(URL)
    rows = m.all()
    assert len(rows) == 1
    assert len(rows[0].detail.get("corrections", [])) == n - 1   # nothing lost
    m.close()


@requires_redis
def test_decay_does_not_clobber_concurrent_corroboration():
    m = _fresh()
    r = m.write(make_fact())
    barrier = threading.Barrier(2)

    def corroborate_hard():
        from verel.memory.redis_backend import RedisMemory
        w = RedisMemory(URL)
        barrier.wait()
        for _ in range(10):
            w.write(make_fact())
        w.close()

    t = threading.Thread(target=corroborate_hard)
    t.start()
    barrier.wait()
    for _ in range(10):
        m.decay(now=10_000_000.0)
    t.join()
    got = m.get(r.id)
    assert got is not None and got.support_count == 11   # decay never clobbered a corroboration
    m.close()


# ---- security: a routable host without TLS+AUTH is refused (fail closed) ------
@pytest.mark.parametrize("url,match", [
    ("redis://db.example.com:6379/0", "without TLS"),               # routable, no TLS
    ("rediss://db.example.com:6379/0", "without AUTH"),             # routable TLS but no password
])
def test_routable_redis_requires_tls_and_auth(url, match):
    from verel.memory.redis_backend import RedisMemory

    with pytest.raises(ValueError, match=match):
        RedisMemory(url)


def test_loopback_is_zero_config():
    # a loopback URL must NOT be refused by the TLS/AUTH guard (it may still fail to connect if no
    # server, but not with the guard's ValueError).
    from verel.memory.redis_backend import RedisMemory

    try:
        RedisMemory("redis://127.0.0.1:6390/0")   # unused port → connect error, not guard error
    except ValueError as e:
        pytest.fail(f"loopback wrongly refused by guard: {e}")
    except RuntimeError:
        pass   # connect failure (scrubbed) is fine


@pytest.mark.parametrize("url", [
    "rediss://u:pw@db.example.com:6379/0?ssl_cert_reqs=none",        # disables cert validation
    "rediss://u:pw@db.example.com:6379/0?ssl_cert_reqs=optional",
    "rediss://u:pw@db.example.com:6379/0?ssl_check_hostname=false",  # disables hostname check
    "rediss://u:pw@db.example.com:6379/0?ssl_check_hostname=f",      # redis-py to_bool false-form
    "rediss://u:pw@db.example.com:6379/0?ssl_check_hostname=N",
    "rediss://u:pw@db.example.com:6379/0?ssl_ca_certs=/tmp/attacker-ca.pem",  # swaps the trust root
    "rediss://u:pw@db.example.com:6379/0?ssl_certfile=/tmp/x.pem",
])
def test_rediss_tls_options_in_url_are_refused(url):
    # Red-team HIGH/LOW: redis-py's from_url lets a URL `ssl*` query param override our hardened
    # kwargs (a blocklist missed to_bool forms like 'f'/'n'; ssl_ca_certs swapped the trust root).
    # Allowlist: ANY ssl* query param in a rediss:// URL is refused — TLS config comes from env only.
    from verel.memory.redis_backend import RedisMemory

    with pytest.raises(ValueError, match="TLS options in the URL"):
        RedisMemory(url)


@requires_redis
def test_scan_is_bounded_by_cap(monkeypatch):
    # Red-team MEDIUM: _SCAN_CAP must actually bound the client-side scan (SSCAN, not a post-SMEMBERS
    # slice). With the cap lowered, recall/all see at most _SCAN_CAP records even if more exist.
    import verel.memory.redis_backend as rb

    m = _fresh()
    for i in range(15):
        m.write(make_fact(text=f"t{i}", subject=f"s{i}", predicate="p"))
    monkeypatch.setattr(rb, "_SCAN_CAP", 5)
    assert len(m.all()) == 5          # bounded, not 15
    m.close()


def test_url_password_scrubbed_from_error():
    from verel.memory.redis_backend import RedisMemory

    secret = "rediss://user:sup3rs3cret@127.0.0.1:6391/0"  # nosec B105 — test literal, unused port
    with pytest.raises(RuntimeError) as ei:
        RedisMemory(secret)
    assert "sup3rs3cret" not in str(ei.value)
