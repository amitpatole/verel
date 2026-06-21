"""Replicated memory (§5, §6.3) — a highly-available, fault-tolerant shared brain.

One node of a leader-fenced cluster:

* exactly **one leader** at a time, held by a fencing lease (`fleet.lease`'s monotonic token);
* the leader applies each mutation locally, then **replicates the resulting record state** (verbatim,
  via `apply_replica`) to its peers — state-based, so replication is idempotent and a follower
  mirrors the leader exactly;
* replication is **fault-tolerant**: an unreachable follower does NOT fail the write (it falls
  behind and catches up later); a write is durable once a `write_quorum` of nodes hold it;
* a **deposed leader is fenced** — `NotLeaderError` on write, `FencingError` on a stale in-flight
  replicate — so there is no split-brain;
* a lagging or recovered follower **catches up** with `sync_from(leader)`.

Reads are served from any node's local replica (eventual consistency). The lease store — in-memory
in one process, or the hosted control plane across machines — is the single source of fencing truth.
A peer is anything with `apply_replica_fenced(record_dict, token)`: another `ReplicatedMemory`, or a
`ReplicaClient` to a remote node (hosted.py).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..fleet.lease import FencingError, Lease, LeaseStore
from .view import MemoryRecord, MemoryView


class NotLeaderError(RuntimeError):
    """A mutation was attempted on a node that is not the current leader of the cluster."""


_VERSION_STRIDE = 1_000_000_000  # the per-leader sequence space below each fencing token


def version_of(record: MemoryRecord) -> int:
    """The record's replication version (0 if unversioned). The leader stamps a monotonic version
    `token * STRIDE + seq`, so versions increase within a leader AND across failovers (a new leader
    has a higher token) — letting any replica tell which copy of a record is freshest."""
    return int(record.detail.get("_v", 0))


class ReplicationError(RuntimeError):
    """A write could not reach the configured `write_quorum` of replicas."""


@dataclass
class ReplicationStatus:
    acks: int       # nodes that hold the last write (incl. the leader)
    lagging: int    # peers that were unreachable on the last write
    quorum: int


class ReplicatedMemory(MemoryView):
    """One node of a replicated, fencing-led memory cluster. `local` is this node's durable store;
    `leases` + `cluster_key` elect the single leader; `peers` receive replicated state. A write is
    acknowledged once `write_quorum` nodes (incl. the leader) hold it — default 1 (leader-durable,
    tolerant of every follower being down)."""

    def __init__(self, local: MemoryView, *, leases: LeaseStore, cluster_key: str, owner: str,
                 peers: list | None = None, write_quorum: int = 1, ttl: float = 30.0,
                 sources: dict[str, MemoryView] | None = None,
                 read_consistency: str = "eventual", read_quorum: int = 1,
                 clock: Callable[[], float] = time.monotonic):
        self.local = local
        self.leases = leases
        self.key = cluster_key
        self.owner = owner
        self.peers: list = list(peers) if peers is not None else []
        self.write_quorum = max(1, write_quorum)
        self.ttl = ttl
        # `read_consistency`: "eventual" (default) reads this node's local replica — fast, may lag;
        # "strong" routes reads to the CURRENT leader (the single writer, so it holds every committed
        # write) for read-your-writes / linearizable-ish reads. Needs `sources` (owner -> readable
        # view) to reach the leader; falls back to local if the leader can't be resolved.
        self.sources = dict(sources) if sources is not None else {}
        self.read_consistency = read_consistency
        self.read_quorum = max(1, read_quorum)
        self._clock = clock
        self._seq = 0  # per-leader sequence under the fencing token → monotonic record versions
        self._last = ReplicationStatus(0, 0, self.write_quorum)

    # ---- leadership (fenced by the shared lease store) ----
    def _lead(self) -> Lease:
        lease = self.leases.acquire(self.key, self.owner, now=self._clock(), ttl=self.ttl)
        if lease is None:
            raise NotLeaderError(f"{self.owner!r} is not the leader of {self.key!r} — write to the leader")
        return lease

    def is_leader(self) -> bool:
        try:
            self._lead()
        except NotLeaderError:
            return False
        return True

    def replication_status(self) -> ReplicationStatus:
        """Acks / lagging peers / quorum from the most recent write."""
        return self._last

    # ---- replication target (called on a FOLLOWER by the leader) ----
    def apply_replica_fenced(self, record: dict, token: int) -> None:
        """Apply a leader's record verbatim — FENCED: a token below the cluster's current (a stale
        leader's) is rejected, so a deposed leader can't overwrite the successor's state."""
        current = self.leases.current_token(self.key)
        if token < current:
            raise FencingError(f"stale replicate token {token} < current {current} for {self.key!r}")
        rec = MemoryRecord(**record)
        existing = self.local.get(rec.id)
        if existing is not None and version_of(existing) > version_of(rec):
            return  # incoming copy is older than what we hold — don't regress (reorder/dup safety)
        self.local.apply_replica(rec)

    def _mutate(self, local_call: Callable[[], MemoryRecord | None]) -> MemoryRecord | None:
        lease = self._lead()                       # fence: only the current leader proceeds
        result = local_call()                      # apply locally — the resulting record state
        acks, lagging = 1, 0                        # the leader holds it
        if result is not None:
            self._seq += 1                          # stamp a monotonic version (token-prefixed)
            result = self.local.annotate(result.id, _v=lease.token * _VERSION_STRIDE + self._seq) or result
            payload = result.model_dump()
            for p in self.peers:
                try:
                    p.apply_replica_fenced(payload, lease.token)
                    acks += 1
                except FencingError as e:           # we were superseded mid-write — abort
                    raise NotLeaderError(f"lost leadership mid-write: {e}") from e
                except Exception:                   # noqa: BLE001 — unreachable follower: best-effort
                    lagging += 1
        self._last = ReplicationStatus(acks, lagging, self.write_quorum)
        if acks < self.write_quorum:
            raise ReplicationError(f"write reached {acks} replica(s), below quorum {self.write_quorum}")
        return result

    # ---- catch-up ----
    def sync_from(self, source: MemoryView) -> int:
        """Pull every record from `source` (the leader) and apply it verbatim locally — for a
        follower that fell behind or just recovered. Returns the number of records synced."""
        n = 0
        for r in source.all():
            self.local.apply_replica(r)
            n += 1
        return n

    # ---- MemoryView: mutations are leader-only + replicated ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        return self._mutate(lambda: self.local.write(record, ts=ts))  # type: ignore[return-value]

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        return self.local.apply_replica(record)

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._mutate(lambda: self.local.corroborate(record_id, delta=delta))

    def contradict(self, record_id, *, delta: float = 0.25):
        return self._mutate(lambda: self.local.contradict(record_id, delta=delta))

    def promote(self, record_id):
        return self._mutate(lambda: self.local.promote(record_id))

    def demote(self, record_id):
        return self._mutate(lambda: self.local.demote(record_id))

    def pin(self, record_id):
        return self._mutate(lambda: self.local.pin(record_id))

    def unpin(self, record_id):
        return self._mutate(lambda: self.local.unpin(record_id))

    def annotate(self, record_id, **detail):
        return self._mutate(lambda: self.local.annotate(record_id, **detail))

    def set_flags(self, record_id, *, pinned=None, volatile=None, ttl_s=None):
        return self._mutate(lambda: self.local.set_flags(
            record_id, pinned=pinned, volatile=volatile, ttl_s=ttl_s))

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0) -> int:
        # per-node maintenance: each replica decays its own copy on its own schedule; nodes converge.
        return self.local.decay(half_life_s=half_life_s, now=now)

    # ---- reads: local (eventual) by default, or routed to the leader (strong) ----
    def leader_view(self) -> MemoryView:
        """The view to read from: this node's local replica, unless `read_consistency='strong'`, in
        which case the CURRENT leader's view (read-your-writes). Falls back to local if the leader
        can't be resolved (no leader, or no source for it)."""
        if self.read_consistency != "strong":
            return self.local
        owner = self.leases.holder(self.key, now=self._clock())
        if owner is None or owner == self.owner:
            return self.local  # no leader, or we ARE the leader → our local is authoritative
        return self.sources.get(owner, self.local)

    def get(self, record_id):
        if self.read_consistency == "quorum":
            return self._quorum_get(record_id)
        return self.leader_view().get(record_id)

    def _quorum_get(self, record_id):
        """Read the record from up to `read_quorum` replicas (this node + its sources) and return
        the FRESHEST by version — so a point read returns the latest committed value even when the
        leader is unavailable, as long as a quorum of replicas hold it."""
        best, reads = None, 0
        for view in (self.local, *self.sources.values()):
            try:
                r = view.get(record_id)
            except Exception:  # noqa: BLE001 — an unreachable replica just doesn't count
                continue
            reads += 1
            if r is not None and (best is None or version_of(r) > version_of(best)):
                best = r
            if reads >= self.read_quorum:
                break
        return best

    def recall(self, query, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        return self.leader_view().recall(query, scope=scope, kind=kind, k=k, ts=ts)

    def all(self, *, scope=None, kind=None):
        return self.leader_view().all(scope=scope, kind=kind)


class AntiEntropy:
    """Background reconciler: a follower periodically pulls the CURRENT leader's state, so a node
    that fell behind — or just recovered from a crash — self-heals without an operator. It resolves
    the leader from the lease store (`holder`), maps it to a readable source via `sources`, and
    `sync_from`s it. A no-op while this node IS the leader (it's the source of truth) or when no
    leader holds the lease. Best-effort: a failed cycle never crashes the loop."""

    def __init__(self, node: ReplicatedMemory, sources: dict[str, MemoryView], *,
                 interval: float = 5.0, sleep: Callable[[float], None] = time.sleep):
        self.node = node
        self.sources = sources
        self.interval = interval
        self._sleep = sleep
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def leader_source(self) -> MemoryView | None:
        owner = self.node.leases.holder(self.node.key, now=self.node._clock())
        if owner is None or owner == self.node.owner:
            return None  # no leader, or we are the leader — nothing to pull
        return self.sources.get(owner)

    def tick(self) -> int:
        """Run one reconciliation cycle; return the number of records synced (0 if this node is the
        leader or no leader is reachable)."""
        src = self.leader_source()
        return self.node.sync_from(src) if src is not None else 0

    def start(self) -> AntiEntropy:
        def loop():
            while not self._stop.wait(0):  # check stop without blocking the first tick
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 — best effort; never crash the reconciler
                    pass
                if self._stop.wait(self.interval):
                    break
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
