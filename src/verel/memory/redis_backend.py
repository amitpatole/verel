"""RedisMemory — a Redis `MemoryView` (a networked, shared brain store).

Like the Postgres backend, this is a **networked, multi-writer** store: many agents on different
machines point at one Redis and the trust-layer's read-modify-write rules stay correct under
concurrent writers. Each record is a Redis HASH at `{prefix}:mem:{id}`, enumerated via a SET index
`{prefix}:ids`. Every mutator is atomic by **optimistic concurrency** — `WATCH` the key, read,
compute the merge in Python, `MULTI`/`EXEC`, and retry on a concurrent change (bounded) — so two
agents asserting the same `(subject,predicate,scope)` never lose an update, without a global lock.

Recall scans the index, filters scope/kind/trust + ranks in Python (Verel's documented `rank()`),
with cosine relevance when an embedder is configured (vectors stored per record) and lexical overlap
otherwise. (Server-side ANN via RediSearch is a future optimization; this v1 works on ANY Redis.)

Security (a networked store with credentials):
- **Redis's RESP protocol is injection-safe** (length-prefixed args — no string-interpolated query
  language like SQL), so there is no command-injection surface from record ids/scope/kind.
- A **routable host requires TLS *and* AUTH** — a non-loopback `VEREL_REDIS_URL` must be `rediss://`
  (validated cert) with a password, else the connection is refused (fail closed). Loopback is
  zero-config.
- The URL/password is **scrubbed from every error**; the connection pool is bounded and timeouts set.

`pip install verel[redis]`. Config: `VEREL_REDIS_URL`, `VEREL_REDIS_PREFIX`, `VEREL_REDIS_CACERT`,
`VEREL_EMBEDDER`.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import parse_qs, urlsplit

from ..transport import is_loopback
from .view import (
    STALE_AFTER_S,
    VOLATILE_TTL_S,
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    apply_decay,
    make_id,
    make_key,
    rank,
)
from .view import (
    relevance as _relevance,
)

_MAX_RETRIES = 64       # WATCH/MULTI optimistic-lock attempts before failing a contended write
_MAX_RECALL_K = 1000    # clamp caller-supplied k
_SCAN_CAP = 20000       # bound the index scan so a huge brain can't OOM the client
_DELETE = object()  # sentinel a mutate() returns to delete (prune) the record

_FLOAT_FIELDS = ("epistemic_confidence", "retrieval_strength", "created_ts", "last_recall_ts")
_STR_FIELDS = ("id", "kind", "subject", "predicate", "text", "scope", "subj_pred_key", "source",
               "provenance", "trust", "detail_json")


def _scrub(exc: Exception, url: str) -> str:
    """An error message with the URL and any password removed — a connection error can echo the URL."""
    msg = str(exc)
    if url and url in msg:
        msg = msg.replace(url, "<redis-url>")
    msg = re.sub(r"(://[^:/@\s]+:)[^@\s]+(@)", r"\1<redacted>\2", msg)  # URL userinfo password
    return msg


class RedisMemory(MemoryView):
    def __init__(self, url: str, *, embedder=None, prefix: str = "verel", cacert: str | None = None,
                 max_connections: int = 32):
        import redis

        self._url = url
        self.embedder = embedder
        self._prefix = prefix
        self._mem = f"{prefix}:mem:"
        self._index = f"{prefix}:ids"
        # Fail closed: a routable Redis must use validated TLS AND AUTH so a credential + payloads
        # never cross the network in cleartext or unauthenticated.
        parts = urlsplit(url)
        host = parts.hostname or ""
        if host and not is_loopback(host):
            if parts.scheme != "rediss":
                raise ValueError(
                    f"refusing to connect to routable Redis host {host!r} without TLS — use a "
                    "rediss:// URL (validated cert) or a loopback host")
            if not parts.password:
                raise ValueError(
                    f"refusing to connect to routable Redis host {host!r} without AUTH — set a "
                    "password in the rediss:// URL or use a loopback host")
        # A rediss:// URL query can WEAKEN TLS — redis-py's from_url forwards any `ssl*` query param
        # and the URL value WINS over our kwargs (ssl_cert_reqs=none, ssl_check_hostname=f, even a
        # swapped ssl_ca_certs), silently disabling validation → MITM. Allowlist, not blocklist:
        # refuse ANY ssl* query param so TLS config comes only from the trusted kwargs/env, never the
        # (attacker-influenceable) URL. (A value-matching blocklist misses redis-py's to_bool forms
        # like 'f'/'n'.)
        if parts.scheme == "rediss":
            ssl_params = sorted(k for k in parse_qs(parts.query) if k.lower().startswith("ssl"))
            if ssl_params:
                raise ValueError(
                    f"refusing rediss:// with TLS options in the URL query ({', '.join(ssl_params)}) — "
                    "cert validation, hostname check and CA bundle must come from VEREL_REDIS_CACERT / "
                    "the trusted defaults, not the URL")
        try:
            kw: dict = {"decode_responses": True, "socket_timeout": 10,
                        "socket_connect_timeout": 10, "max_connections": max_connections}
            if parts.scheme == "rediss":
                import ssl
                kw["ssl_cert_reqs"] = ssl.CERT_REQUIRED  # validate the server certificate
                kw["ssl_check_hostname"] = True
                if cacert:
                    kw["ssl_ca_certs"] = cacert
            self._r = redis.Redis.from_url(url, **kw)
            self._r.ping()
        except Exception as e:  # connection errors must not leak the URL/password
            raise RuntimeError(f"RedisMemory connect failed: {_scrub(e, url)}") from None

    @classmethod
    def from_env(cls) -> RedisMemory:
        """Build from operator env (`VEREL_MEMORY_BACKEND=redis`). Fails closed without a URL."""
        try:
            import redis  # noqa: F401
        except ImportError as e:
            raise RuntimeError("redis backend needs `pip install verel[redis]`") from e
        from .embed import embedder_from_env

        url = os.environ.get("VEREL_REDIS_URL")
        if not url:
            raise RuntimeError("redis backend requires VEREL_REDIS_URL")
        return cls(url, embedder=embedder_from_env(),
                   prefix=os.environ.get("VEREL_REDIS_PREFIX", "verel"),
                   cacert=os.environ.get("VEREL_REDIS_CACERT"))

    # ---- (de)serialization ----
    def _key(self, record_id: str) -> str:
        return self._mem + record_id

    def _to_hash(self, r: MemoryRecord, *, vector: str | None = None) -> dict:
        h = {
            "id": r.id, "kind": r.kind.value, "subject": r.subject, "predicate": r.predicate,
            "text": r.text, "scope": r.scope, "subj_pred_key": r.subj_pred_key, "source": r.source,
            "provenance": "\x1f".join(r.provenance), "trust": r.trust.value,
            "epistemic_confidence": repr(float(r.epistemic_confidence)),
            "retrieval_strength": repr(float(r.retrieval_strength)),
            "support_count": str(int(r.support_count)),
            "created_ts": repr(float(r.created_ts)), "last_recall_ts": repr(float(r.last_recall_ts)),
            "detail_json": r.detail_json,
        }
        if self.embedder is not None:
            # reuse a precomputed/unchanged vector when given (avoids re-embedding on every
            # corroboration — and keeps a slow OpenAI embed out of the WATCH/MULTI window).
            h["vector"] = vector if vector is not None else json.dumps(self._embed(r))
        return h

    def _from_hash(self, h: dict) -> MemoryRecord:
        d: dict = {k: h.get(k, "") for k in _STR_FIELDS}
        d["provenance"] = d["provenance"].split("\x1f") if d["provenance"] else []
        d["trust"] = Trust(d["trust"])
        d["kind"] = MemoryKind(d["kind"])
        for f in _FLOAT_FIELDS:
            d[f] = float(h.get(f, 0.0) or 0.0)
        d["support_count"] = int(h.get("support_count", 1) or 1)
        return MemoryRecord(**d)

    def _embed(self, r: MemoryRecord):
        return [float(x) for x in self.embedder.embed([f"{r.subject} {r.predicate} {r.text}".strip()])[0]]

    # ---- atomic optimistic read-modify-write ----
    def _run_atomic(self, record_id: str, mutate):
        """WATCH the key, read the current record, compute `mutate(existing)`, then MULTI/EXEC — retry
        on a concurrent change so no update is lost. `mutate` returns a MemoryRecord to write,
        `_DELETE` to prune it, or None to leave it untouched. Returns the raw result (record/_DELETE/
        None) so callers can distinguish a prune from a no-op."""
        import random
        import time

        import redis

        key = self._key(record_id)
        try:
            with self._r.pipeline() as pipe:
                for attempt in range(_MAX_RETRIES):
                    try:
                        pipe.watch(key)
                        raw = pipe.hgetall(key)  # immediate in watch mode
                        existing = self._from_hash(raw) if raw else None
                        result = mutate(existing)
                        if result is None:
                            pipe.unwatch()
                            return None
                        if result is _DELETE:
                            pipe.multi()
                            pipe.delete(key)
                            pipe.srem(self._index, record_id)
                        else:
                            # text unchanged → reuse the stored vector (no re-embed); build the hash
                            # BEFORE multi() so any embed work isn't interleaved with the buffered cmds.
                            reuse = None
                            if (existing is not None and existing.text == result.text
                                    and raw.get("vector") is not None):
                                reuse = str(raw["vector"])  # decode_responses → str
                            mapping = self._to_hash(result, vector=reuse)
                            pipe.multi()
                            pipe.hset(key, mapping=mapping)
                            pipe.sadd(self._index, record_id)
                        pipe.execute()
                        return result
                    except redis.WatchError:
                        # concurrent writer committed first — back off with jitter to break the
                        # thundering herd, then re-read and re-merge (no update is lost).
                        time.sleep(min(0.05, 0.0005 * (2 ** min(attempt, 6))) * random.random())  # nosec B311 — jitter, not crypto
                        continue
            raise RuntimeError(f"redis: too much contention on key {record_id!r}")
        except redis.RedisError as e:
            raise RuntimeError(f"redis op failed: {_scrub(e, self._url)}") from None

    def _atomic(self, record_id: str, mutate) -> MemoryRecord | None:
        """`_run_atomic` for the normal mutators — a deleted/absent record both surface as None."""
        result = self._run_atomic(record_id, mutate)
        return None if (result is None or result is _DELETE) else result

    # ---- MemoryView API ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        record.created_ts = record.created_ts or ts

        def mutate(existing):
            if existing is not None:
                if existing.text.strip().lower() == record.text.strip().lower():
                    existing.support_count += 1
                    existing.epistemic_confidence = min(1.0, existing.epistemic_confidence + 0.1)
                    existing.retrieval_strength = 1.0
                    for p in record.provenance:
                        if p not in existing.provenance:
                            existing.provenance.append(p)
                    if record.detail:
                        existing.with_detail(**record.detail)
                    existing.with_detail(volatile=False)
                    return existing
                chain = [*existing.detail.get("corrections", []),
                         {"text": existing.text, "ec": existing.epistemic_confidence,
                          "ts": existing.created_ts, "superseded_at": ts}]
                record.support_count = 1
                record.retrieval_strength = 1.0
                record.with_detail(corrections=chain, superseded=existing.text)
            return record

        return self._atomic(record.id, mutate) or record  # mutate never returns None for write

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        return self._atomic(record.id, lambda _existing: record) or record

    def get(self, record_id: str) -> MemoryRecord | None:
        try:
            raw = self._r.hgetall(self._key(record_id))
        except Exception as e:
            raise RuntimeError(f"redis op failed: {_scrub(e, self._url)}") from None
        return self._from_hash(raw) if raw else None

    def _scan_all(self) -> list[MemoryRecord]:
        try:
            # SSCAN (cursor-paged), stopping at the cap — so neither the network reply nor the client
            # list ever exceeds _SCAN_CAP. SMEMBERS would materialize the WHOLE index first (the cap
            # would then bound nothing). SSCAN is also safe under concurrent writes.
            # SSCAN may yield the same id more than once (rehashing/concurrent writes) — dedup, else
            # recall returns duplicate records and double-reinforces them.
            ids: list[str] = []
            seen: set[str] = set()
            for rid in self._r.sscan_iter(self._index, count=1000):
                rid = str(rid)
                if rid in seen:
                    continue
                seen.add(rid)
                ids.append(rid)
                if len(ids) >= _SCAN_CAP:
                    break
            if not ids:
                return []
            pipe = self._r.pipeline(transaction=False)
            for rid in ids:
                pipe.hgetall(self._key(rid))
            return [self._from_hash(h) for h in pipe.execute() if h]
        except Exception as e:
            raise RuntimeError(f"redis op failed: {_scrub(e, self._url)}") from None

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        try:
            k = max(1, min(int(k), _MAX_RECALL_K))
        except (TypeError, ValueError, OverflowError):
            k = 5
        pool = self._scan_all()
        if scope is not None:
            pool = [c for c in pool if c.scope == scope or c.scope == "global"]
        if kind is not None:
            pool = [c for c in pool if c.kind == kind]
        pool = [c for c in pool if c.trust != Trust.REJECTED]
        if self.embedder is not None:
            from .embed import cosine

            qv = self.embedder.embed([query])[0]
            vecs = self._vectors([c.id for c in pool])
            relevance_of = lambda c: cosine(qv, vecs.get(c.id) or [])  # noqa: E731
        else:
            relevance_of = lambda c: _relevance(query, c)  # noqa: E731
        scored = sorted(pool, key=lambda c: rank(c, relevance_of(c)), reverse=True)
        top = [c for c in scored if relevance_of(c) > 0.0][:k]
        for c in top:  # recall reinforces retrieval_strength ONLY (testing effect), atomically
            updated = self._adjust(c.id, reinforce=ts)
            if updated is not None:  # mirror the PERSISTED value, not the stale scan snapshot
                c.retrieval_strength = updated.retrieval_strength
                c.last_recall_ts = updated.last_recall_ts
        return top

    def _vectors(self, ids: list[str]) -> dict:
        if not ids:
            return {}
        pipe = self._r.pipeline(transaction=False)
        for rid in ids:
            pipe.hget(self._key(rid), "vector")
        out = {}
        for rid, raw in zip(ids, pipe.execute(), strict=False):
            if raw:
                out[rid] = [float(x) for x in json.loads(raw)]
        return out

    # ---- trust mutators (atomic optimistic RMW) ----
    def _adjust(self, record_id: str, *, ec: float = 0.0, support: int = 0,
                trust: Trust | None = None, confirm: bool = False,
                reinforce: float | None = None) -> MemoryRecord | None:
        def mutate(r):
            if r is None:
                return None
            if reinforce is not None:  # recall reinforcement: strength only, never confidence
                r.retrieval_strength = min(1.0, r.retrieval_strength + 0.3)
                r.last_recall_ts = reinforce or r.last_recall_ts
                return r
            r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
            r.support_count += support
            if trust is not None:
                r.trust = trust
            if confirm:
                r.with_detail(volatile=False)
            return r

        return self._atomic(record_id, mutate)

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._adjust(record_id, ec=delta, support=1, confirm=True)

    def contradict(self, record_id, *, delta: float = 0.25):
        def mutate(r):
            if r is None:
                return None
            r.epistemic_confidence = max(0.0, r.epistemic_confidence - delta)
            if r.epistemic_confidence < 0.2:
                r.trust = Trust.REJECTED
            return r

        return self._atomic(record_id, mutate)

    def promote(self, record_id):
        return self._adjust(record_id, trust=Trust.VERIFIED, confirm=True)

    def demote(self, record_id):
        return self._adjust(record_id, trust=Trust.CANDIDATE)

    def annotate(self, record_id: str, **detail) -> MemoryRecord | None:
        def mutate(r):
            if r is None:
                return None
            r.with_detail(**detail)
            return r

        return self._atomic(record_id, mutate)

    def set_flags(self, record_id: str, *, pinned=None, volatile=None, ttl_s=None):
        def mutate(r):
            if r is None:
                return None
            if pinned is not None:
                r.with_detail(pinned=bool(pinned))
            if volatile is not None:
                r.with_detail(volatile=bool(volatile))
            if ttl_s is not None:
                r.with_detail(ttl_s=float(ttl_s))
            return r

        return self._atomic(record_id, mutate)

    def pin(self, record_id):
        return self.set_flags(record_id, pinned=True)

    def unpin(self, record_id):
        return self.set_flags(record_id, pinned=False)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0,
              stale_after_s: float = STALE_AFTER_S, volatile_ttl_s: float = VOLATILE_TTL_S) -> int:
        # Per-key atomic: re-read each record under WATCH and decay/prune it, so the librarian pass
        # never clobbers a concurrent corroborate (the optimistic retry re-applies decay to the new
        # state). Maintenance op — slower per key, but correct under concurrent writers.
        pruned = 0

        def mutate(r):
            if r is None:
                return None
            return _DELETE if apply_decay(
                r, now=now, half_life_s=half_life_s, stale_after_s=stale_after_s,
                volatile_ttl_s=volatile_ttl_s) else r
        try:
            # Stream the index with SSCAN and process each key inline. Dedup: SSCAN may yield an id
            # more than once, and apply_decay is NOT idempotent (it multiplies the persisted strength)
            # — a double visit would over-decay and could spuriously PRUNE a healthy record.
            seen: set[str] = set()
            for rid in self._r.sscan_iter(self._index, count=500):
                rid = str(rid)
                if rid in seen:
                    continue
                seen.add(rid)
                if self._run_atomic(rid, mutate) is _DELETE:
                    pruned += 1
        except Exception as e:
            raise RuntimeError(f"redis op failed: {_scrub(e, self._url)}") from None
        return pruned

    def all(self, *, scope=None, kind=None):
        recs = self._scan_all()
        if scope is not None:
            recs = [r for r in recs if r.scope == scope]
        if kind is not None:
            recs = [r for r in recs if r.kind == kind]
        return recs

    def close(self) -> None:
        try:
            self._r.close()
        except Exception:
            pass
