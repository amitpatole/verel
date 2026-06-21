"""Replicated memory (§5, §6.3) — make the shared brain highly available.

The hosted `MemoryServer` is a single writer: no split-brain by construction, but a single point of
failure. This wraps a local store as one node of a REPLICATED cluster:

* exactly **one node is the leader** at a time, held by a fencing lease — the same monotonic-token
  primitive the fleet uses (`fleet.lease`);
* the leader applies every mutation locally and **replicates** it to its peers;
* a **stale leader is fenced** — once its lease lapses and a peer takes over (with a higher token),
  the old leader can no longer write (`NotLeaderError`), and any in-flight replicate it sends is
  rejected (`FencingError`). No split-brain, no SPOF.

Reads are served from any node's local replica (eventual consistency — a follower is current once
replication lands; nodes self-maintain via their own `decay`). The lease store — `InMemoryLeaseStore`
for one process, or the hosted control plane (`RemoteLeaseStore`) across machines — is the single
source of fencing truth every node consults. A peer is anything with a `replicate(op, token,
payload)` method: another `ReplicatedMemory`, or a `ReplicaClient` to a remote node (see hosted.py).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from ..fleet.lease import FencingError, Lease, LeaseStore
from .view import MemoryRecord, MemoryView


class NotLeaderError(RuntimeError):
    """A mutation was attempted on a node that is not the current leader of the cluster."""


# A peer accepts replicated mutations: replicate(op, token, payload) -> None.
Peer = object


class ReplicatedMemory(MemoryView):
    """One node of a replicated, fencing-led memory cluster. `local` is this node's durable store;
    `leases` + `cluster_key` elect the single leader; `peers` receive replicated mutations."""

    def __init__(self, local: MemoryView, *, leases: LeaseStore, cluster_key: str, owner: str,
                 peers: list[Peer] | None = None, ttl: float = 30.0,
                 clock: Callable[[], float] = time.monotonic):
        self.local = local
        self.leases = leases
        self.key = cluster_key
        self.owner = owner
        self.peers: list = list(peers) if peers is not None else []
        self.ttl = ttl
        self._clock = clock

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

    # ---- replication target (called on a FOLLOWER by the leader) ----
    def replicate(self, op: str, token: int, payload: dict) -> None:
        """Apply a leader's mutation locally — FENCED: a token below the cluster's current (a stale
        leader's) is rejected, so a deposed leader can't overwrite the successor's state."""
        current = self.leases.current_token(self.key)
        if token < current:
            raise FencingError(f"stale replicate token {token} < current {current} for {self.key!r}")
        self._apply(op, payload)

    def _apply(self, op: str, payload: dict) -> None:
        if op == "write":
            self.local.write(MemoryRecord(**payload["record"]), ts=payload.get("ts", 0.0))
        elif op == "corroborate":
            self.local.corroborate(payload["id"], delta=payload["delta"])
        elif op == "contradict":
            self.local.contradict(payload["id"], delta=payload["delta"])
        elif op in ("promote", "demote", "pin", "unpin"):
            getattr(self.local, op)(payload["id"])
        elif op == "annotate":
            self.local.annotate(payload["id"], **payload["detail"])
        elif op == "set_flags":
            self.local.set_flags(payload["id"], pinned=payload.get("pinned"),
                                 volatile=payload.get("volatile"), ttl_s=payload.get("ttl_s"))

    def _mutate(self, op: str, payload: dict, local_call: Callable):
        lease = self._lead()              # fence: only the current leader proceeds
        result = local_call()             # apply locally
        for p in self.peers:              # then replicate to followers, carrying the fencing token
            try:
                p.replicate(op, lease.token, payload)
            except FencingError as e:
                raise NotLeaderError(f"lost leadership mid-write: {e}") from e
        return result

    # ---- MemoryView: mutations are leader-only + replicated ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        return self._mutate("write", {"record": record.model_dump(), "ts": ts},
                            lambda: self.local.write(record, ts=ts))

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._mutate("corroborate", {"id": record_id, "delta": delta},
                            lambda: self.local.corroborate(record_id, delta=delta))

    def contradict(self, record_id, *, delta: float = 0.25):
        return self._mutate("contradict", {"id": record_id, "delta": delta},
                            lambda: self.local.contradict(record_id, delta=delta))

    def promote(self, record_id):
        return self._mutate("promote", {"id": record_id}, lambda: self.local.promote(record_id))

    def demote(self, record_id):
        return self._mutate("demote", {"id": record_id}, lambda: self.local.demote(record_id))

    def pin(self, record_id):
        return self._mutate("pin", {"id": record_id}, lambda: self.local.pin(record_id))

    def unpin(self, record_id):
        return self._mutate("unpin", {"id": record_id}, lambda: self.local.unpin(record_id))

    def annotate(self, record_id, **detail):
        return self._mutate("annotate", {"id": record_id, "detail": detail},
                            lambda: self.local.annotate(record_id, **detail))

    def set_flags(self, record_id, *, pinned=None, volatile=None, ttl_s=None):
        payload = {"id": record_id, "pinned": pinned, "volatile": volatile, "ttl_s": ttl_s}
        return self._mutate("set_flags", payload, lambda: self.local.set_flags(
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
