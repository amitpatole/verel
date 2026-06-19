"""MemoryView — the trust layer Verel owns over a (rentable) memory backend (§5).

Faithful to the design's load-bearing rules:
- **Two orthogonal quantities, never multiplied into one stored field** (§5):
    * `epistemic_confidence` — how true we believe it is. Moved ONLY by corroboration(+)/
      contradiction(-). Retrieval NEVER touches it.
    * `retrieval_strength` — how reachable it is. Power-law decay with disuse; reset+extended
      by recall (the testing effect). Decay NEVER mutates truth.
- Ranking combines the two by a DOCUMENTED rule (`rank()` below); it does not collapse them.
- Prune ONLY when ALL hold: retrieval_strength < 0.15 AND epistemic_confidence < 0.4 AND
  support_count < 2 AND trust != verified.
- `subj_pred_key` is the interference key: a new value for the same (subject, predicate,
  scope) supersedes rather than silently duplicating.

`MemoryView` is a Protocol so the rented backend (mem0) and the bundled zero-dep
`LocalMemory` (sqlite) are interchangeable. Verel's value is THIS layer, not the storage.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

_WORD = re.compile(r"[a-z0-9]+")


def tokens(s: str) -> set[str]:
    return set(_WORD.findall(s.lower()))

# Ranking weights (documented; the v2 MMR assembler refines these — §11.2).
W_REL = 0.5  # lexical relevance to the query
W_REC = 0.2  # retrieval_strength (recency/use)
W_CONF = 0.3  # epistemic_confidence (belief in truth)

# Prune thresholds (§5).
PRUNE_RS = 0.15
PRUNE_EC = 0.4
PRUNE_SUPPORT = 2


class Trust(str, Enum):
    CANDIDATE = "candidate"  # written, not yet promoted
    VERIFIED = "verified"  # passed the held-out, attested eval gate (§7.1)
    REJECTED = "rejected"  # contradicted / failed promotion


class MemoryKind(str, Enum):
    FACT = "fact"
    DESIGN_RULE = "design_rule"  # consolidated cross-episode rule (§5.5 step 2b)
    FAILURE = "failure"  # failure-ledger entry (§7.5)
    SKILL = "skill"  # agent-built tool / skill — procedural memory (§7.6)


class MemoryRecord(BaseModel):
    id: str = ""  # content-addressed (subj_pred_key + scope) — stable identity
    kind: MemoryKind
    subject: str = ""
    predicate: str = ""
    text: str  # the object / content
    scope: str = "repo:default"  # repo:<name> | global | component:<x>
    subj_pred_key: str = ""  # interference key (subject|predicate|scope)
    source: str = "other"  # GraderKind value or "consolidation"
    provenance: list[str] = Field(default_factory=list)  # episode / percept refs
    trust: Trust = Trust.CANDIDATE
    epistemic_confidence: float = 0.5  # moved ONLY by corroborate/contradict
    retrieval_strength: float = 1.0  # power-law decay; reset on recall
    support_count: int = 1
    created_ts: float = 0.0
    last_recall_ts: float = 0.0
    detail_json: str = "{}"

    @property
    def detail(self) -> dict:
        try:
            return json.loads(self.detail_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def with_detail(self, **kv) -> MemoryRecord:
        d = self.detail
        d.update(kv)
        self.detail_json = json.dumps(d)
        return self


def make_key(subject: str, predicate: str, scope: str) -> str:
    return f"{subject.strip().lower()}|{predicate.strip().lower()}|{scope.strip().lower()}"


def make_id(subj_pred_key: str) -> str:
    return hashlib.blake2s(subj_pred_key.encode()).hexdigest()[:16]


def relevance(query: str, record: MemoryRecord) -> float:
    """Lexical token-overlap relevance (shared by all backends; embeddings are the v2
    upgrade behind the same interface)."""
    q = tokens(query)
    if not q:
        return 0.0
    hay = tokens(f"{record.subject} {record.predicate} {record.text}")
    if not hay:
        return 0.0
    return len(q & hay) / len(q)


def rank(record: MemoryRecord, relevance: float) -> float:
    """The DOCUMENTED ranking rule. Combines the two orthogonal signals + relevance; it
    never multiplies confidence into strength or vice-versa."""
    return W_REL * relevance + W_REC * record.retrieval_strength + W_CONF * record.epistemic_confidence


def should_prune(r: MemoryRecord) -> bool:
    return (
        r.retrieval_strength < PRUNE_RS
        and r.epistemic_confidence < PRUNE_EC
        and r.support_count < PRUNE_SUPPORT
        and r.trust != Trust.VERIFIED
    )


@runtime_checkable
class MemoryView(Protocol):
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord: ...
    def get(self, record_id: str) -> MemoryRecord | None: ...
    def recall(self, query: str, *, scope: str | None = None, kind: MemoryKind | None = None,
               k: int = 5, ts: float = 0.0) -> list[MemoryRecord]: ...
    def corroborate(self, record_id: str, *, delta: float = 0.15) -> MemoryRecord | None: ...
    def contradict(self, record_id: str, *, delta: float = 0.25) -> MemoryRecord | None: ...
    def promote(self, record_id: str) -> MemoryRecord | None: ...
    def demote(self, record_id: str) -> MemoryRecord | None: ...
    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0) -> int: ...
    def all(self, *, scope: str | None = None, kind: MemoryKind | None = None) -> list[MemoryRecord]: ...
