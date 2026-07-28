"""Memory mutation audit — a hash-chained, append-only log of every trust-layer mutation.

Closes the "mutation audit" gap: correction chains (view.py `corrections`) preserve WHAT a record
used to say, but not WHO/WHAT changed it. `MemoryAudit` records every mutation as
`{seq, ts, actor, action, record_id, before, after}`, hash-chained (each entry commits to its
predecessor via SHA-256) so the log is tamper-evident — the same WORM discipline as
`verel.verdict.store.ReceiptStore`, applied to memory.

`AuditedMemory` wraps ANY `MemoryView` backend (local/postgres/lancedb/redis/mem0/remote) and logs
mutations at the Protocol seam, so no backend needs changes and every backend gets the same audit.

What is (and isn't) audited — a deliberate line:
- Audited: `write`, `apply_replica`, `corroborate`, `contradict`, `promote`, `demote`, `annotate`,
  `set_flags`, `pin`, `unpin`, `decay` — everything that moves belief, trust, or lifecycle.
- NOT audited: `recall`'s retrieval_strength reinforcement. That is reachability bookkeeping (the
  testing effect), not a belief mutation — logging every recall would flood the log and let a hostile
  query stream inflate it (an amplification the v1.3.0 cadence closed for writes).

Entry fields are BOUNDED (actor/action/record_id truncated; before/after snapshots carry a
`canonical_text` 120-char preview + counters, never the raw value) so attacker-length fact text
cannot bloat one entry. Appends are plain JSONL `a`-mode writes: a torn line does not corrupt prior
entries and is DETECTED by `verify()` (fail-visible, like ReceiptStore). Multi-process appenders can
fork the chain; ordering is best-effort but every entry remains tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .view import MemoryKind, MemoryRecord, MemoryView, canonical_text

_GENESIS = "genesis"
_MAX_ACTOR = 120
_MAX_ACTION = 40
_MAX_ID = 64
_MAX_PREVIEW = 120
_MAX_EXTRA = 400


def _snapshot(r: MemoryRecord | None) -> dict | None:
    """A BOUNDED before/after view of a record: trust + the two orthogonal signals + a canonical
    text preview. Never the raw value — canonical_text kills control/zero-width smuggling and the
    truncation decouples entry size from attacker-controlled value length."""
    if r is None:
        return None
    return {
        "trust": r.trust.value,
        "ec": round(r.epistemic_confidence, 4),
        "support": r.support_count,
        "text": canonical_text(r.text)[:_MAX_PREVIEW],
    }


def _entry_hash(prev_hash: str, entry: dict) -> str:
    """SHA-256 over the canonical JSON of the entry (minus its own hash), chained to `prev_hash`."""
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}\n{body}".encode()).hexdigest()


class MemoryAudit:
    """Append-only, hash-chained JSONL audit log for memory mutations."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._head: str | None = None  # lazily read from the last valid line

    @classmethod
    def from_env(cls) -> MemoryAudit:
        """`VEREL_MEMORY_AUDIT` else `$XDG_CONFIG_HOME/verel/memory_audit.jsonl` (default `~/.config`)."""
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        path = os.environ.get("VEREL_MEMORY_AUDIT") or os.path.join(base, "verel", "memory_audit.jsonl")
        return cls(path)

    # ------------------------------------------------------------------
    def _load_head(self) -> str:
        if self._head is not None:
            return self._head
        head = _GENESIS
        try:
            with self.path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        head = json.loads(line).get("hash", head) or head
                    except json.JSONDecodeError:
                        continue  # torn tail line — verify() reports it; chain restarts detectably
        except FileNotFoundError:
            pass
        self._head = head
        return head

    def append(self, *, actor: str, action: str, record_id: str,
               before: MemoryRecord | None = None, after: MemoryRecord | None = None,
               extra: dict | None = None, ts: float = 0.0) -> str:
        """Append one mutation entry; returns its hash (the new chain head)."""
        prev = self._load_head()
        entry: dict = {
            "ts": ts or time.time(),
            "actor": canonical_text(actor)[:_MAX_ACTOR],
            "action": action[:_MAX_ACTION],
            "record_id": record_id[:_MAX_ID],
            "before": _snapshot(before),
            "after": _snapshot(after),
            "prev_hash": prev,
        }
        if extra:
            entry["extra"] = json.dumps(extra, sort_keys=True, default=str)[:_MAX_EXTRA]
        h = _entry_hash(prev, entry)
        entry["hash"] = h
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        self._head = h
        return h

    def entries(self, record_id: str | None = None) -> list[dict]:
        """All (valid) entries, oldest first; filtered to one record when `record_id` is given."""
        out: list[dict] = []
        try:
            with self.path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record_id is None or e.get("record_id") == record_id:
                        out.append(e)
        except FileNotFoundError:
            pass
        return out

    def verify(self) -> tuple[bool, str]:
        """Walk the log and verify every entry's hash + prev_hash linkage.

        Returns (True, "ok") for an intact chain, else (False, reason). A torn/unparseable line or
        a broken link is a verification FAILURE — tampering and torn writes are fail-visible."""
        prev = _GENESIS
        n = 0
        try:
            with self.path.open(encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        return False, f"unparseable entry at line {i}"
                    stated_hash = e.pop("hash", "")
                    if e.get("prev_hash") != prev:
                        return False, f"chain break at line {i}: prev_hash mismatch"
                    if _entry_hash(prev, e) != stated_hash:
                        return False, f"tampered entry at line {i}: hash mismatch"
                    prev = stated_hash
                    n += 1
        except FileNotFoundError:
            return True, "ok"
        return True, "ok"


class AuditedMemory(MemoryView):
    """Wrap any `MemoryView` so every mutation is appended to a `MemoryAudit` with an actor.

    Drop-in: satisfies the same Protocol, so anything that takes a `MemoryView` takes this.
    `actor` names the mutating principal (e.g. "cli:alice", "mcp:verel_remember", "loop")."""

    def __init__(self, inner: MemoryView, audit: MemoryAudit, *, actor: str = "system") -> None:
        self.inner = inner
        self.audit = audit
        self.actor = actor

    def _log(self, action: str, record_id: str, before: MemoryRecord | None,
             after: MemoryRecord | None, ts: float = 0.0, **extra) -> None:
        self.audit.append(actor=self.actor, action=action, record_id=record_id,
                          before=before, after=after, ts=ts, extra=extra or None)

    # ---- mutating methods (audited) ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        from .view import make_id, make_key
        key = record.subj_pred_key or make_key(record.subject, record.predicate, record.scope)
        before = self.inner.get(record.id or make_id(key))
        out = self.inner.write(record, ts=ts)
        self._log("write", out.id, before, out, ts=ts)
        return out

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        before = self.inner.get(record.id) if record.id else None
        out = self.inner.apply_replica(record)
        self._log("apply_replica", out.id, before, out)
        return out

    def _audited(self, action: str, record_id: str, fn, **extra) -> MemoryRecord | None:
        before = self.inner.get(record_id)
        out = fn()
        if out is not None or before is not None:
            self._log(action, record_id, before, out if out is not None else self.inner.get(record_id),
                      **extra)
        return out

    def corroborate(self, record_id: str, *, delta: float = 0.15) -> MemoryRecord | None:
        return self._audited("corroborate", record_id,
                             lambda: self.inner.corroborate(record_id, delta=delta))

    def contradict(self, record_id: str, *, delta: float = 0.25) -> MemoryRecord | None:
        return self._audited("contradict", record_id,
                             lambda: self.inner.contradict(record_id, delta=delta))

    def promote(self, record_id: str) -> MemoryRecord | None:
        return self._audited("promote", record_id, lambda: self.inner.promote(record_id))

    def demote(self, record_id: str) -> MemoryRecord | None:
        return self._audited("demote", record_id, lambda: self.inner.demote(record_id))

    def annotate(self, record_id: str, **detail) -> MemoryRecord | None:
        return self._audited("annotate", record_id,
                             lambda: self.inner.annotate(record_id, **detail),
                             keys=sorted(detail))

    def set_flags(self, record_id: str, *, pinned: bool | None = None, volatile: bool | None = None,
                  ttl_s: float | None = None) -> MemoryRecord | None:
        return self._audited("set_flags", record_id,
                             lambda: self.inner.set_flags(record_id, pinned=pinned,
                                                          volatile=volatile, ttl_s=ttl_s))

    def pin(self, record_id: str) -> MemoryRecord | None:
        return self._audited("pin", record_id, lambda: self.inner.pin(record_id))

    def unpin(self, record_id: str) -> MemoryRecord | None:
        return self._audited("unpin", record_id, lambda: self.inner.unpin(record_id))

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0, **kw) -> int:
        pruned = self.inner.decay(half_life_s=half_life_s, now=now, **kw)
        if pruned:
            self._log("decay", "*", None, None, ts=now, pruned=pruned)
        return pruned

    # ---- read-only methods (pass-through; recall reinforcement is bookkeeping, not audited) ----
    def get(self, record_id: str) -> MemoryRecord | None:
        return self.inner.get(record_id)

    def recall(self, query: str, *, scope: str | None = None, kind: MemoryKind | None = None,
               k: int = 5, ts: float = 0.0) -> list[MemoryRecord]:
        return self.inner.recall(query, scope=scope, kind=kind, k=k, ts=ts)

    def all(self, *, scope: str | None = None, kind: MemoryKind | None = None) -> list[MemoryRecord]:
        return self.inner.all(scope=scope, kind=kind)
