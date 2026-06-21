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

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..fleet.lease import FencingError, Lease, LeaseStore
from .view import MemoryRecord, MemoryView


class NotLeaderError(RuntimeError):
    """A mutation was attempted on a node that is not the current leader of the cluster."""


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
                 clock: Callable[[], float] = time.monotonic):
        self.local = local
        self.leases = leases
        self.key = cluster_key
        self.owner = owner
        self.peers: list = list(peers) if peers is not None else []
        self.write_quorum = max(1, write_quorum)
        self.ttl = ttl
        self._clock = clock
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
        self.local.apply_replica(MemoryRecord(**record))

    def _mutate(self, local_call: Callable[[], MemoryRecord | None]) -> MemoryRecord | None:
        lease = self._lead()                       # fence: only the current leader proceeds
        result = local_call()                      # apply locally — the resulting record state
        acks, lagging = 1, 0                        # the leader holds it
        if result is not None:
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

    # ---- reads: served from this node's local replica ----
    def get(self, record_id):
        return self.local.get(record_id)

    def recall(self, query, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        return self.local.recall(query, scope=scope, kind=kind, k=k, ts=ts)

    def all(self, *, scope=None, kind=None):
        return self.local.all(scope=scope, kind=kind)
