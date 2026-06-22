"""Verel memory — the trust layer Verel owns over a (rentable) backend (§5, §7.5).

Phase increment: MemoryView contract + zero-dep LocalMemory (sqlite) + the failure ledger /
regression guard + Ollama-backed cross-episode consolidation. mem0 is the documented
drop-in behind the same `MemoryView` Protocol.
"""

from __future__ import annotations

from .consolidate import (
    cluster_records,
    consolidate_across_scopes,
    consolidate_failures,
    induce_hierarchy,
    induce_schemas,
)
from .embed import Embedder, HashEmbedder, OpenAIEmbedder, cosine
from .failure_ledger import FailureLedger, regression_report
from .hosted import MemoryServer, RemoteMemory, ReplicaClient
from .lattice import ScopeLattice, graduate, lattice_recall
from .librarian import LibrarianReport, librarian_pass
from .local import LocalMemory
from .mem0_backend import Mem0Memory, make_ollama_mem0
from .principal import AuthnWrite, Principal, authenticated_remember, verify_write
from .promotion import (
    EvalCase,
    HeldOutCorpus,
    PromotionGate,
    PromotionResult,
    evaluate_rule,
)
from .replicated import (
    AntiEntropy,
    NotLeaderError,
    ReplicatedMemory,
    ReplicationError,
    ReplicationStatus,
    version_of,
)
from .revise import Revision, contradicts, propagate_revision, revise_with_counterexample
from .share import AuthorTrust, BeliefImport, author_of, import_belief
from .view import (
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    correction_chain,
    is_expired,
    is_pinned,
    is_volatile,
    make_id,
    make_key,
    rank,
    should_prune,
)

__all__ = [
    "consolidate_failures",
    "induce_schemas",
    "induce_hierarchy",
    "consolidate_across_scopes",
    "cluster_records",
    "revise_with_counterexample",
    "propagate_revision",
    "contradicts",
    "Revision",
    "ScopeLattice",
    "lattice_recall",
    "graduate",
    "MemoryServer",
    "RemoteMemory",
    "ReplicaClient",
    "import_belief",
    "AuthorTrust",
    "BeliefImport",
    "author_of",
    "Principal",
    "AuthnWrite",
    "authenticated_remember",
    "verify_write",
    "librarian_pass",
    "LibrarianReport",
    "ReplicatedMemory",
    "NotLeaderError",
    "ReplicationError",
    "ReplicationStatus",
    "AntiEntropy",
    "version_of",
    "FailureLedger",
    "regression_report",
    "LocalMemory",
    "Embedder",
    "HashEmbedder",
    "OpenAIEmbedder",
    "cosine",
    "Mem0Memory",
    "make_ollama_mem0",
    "EvalCase",
    "HeldOutCorpus",
    "PromotionGate",
    "PromotionResult",
    "evaluate_rule",
    "MemoryKind",
    "MemoryRecord",
    "MemoryView",
    "Trust",
    "make_id",
    "make_key",
    "rank",
    "should_prune",
    "is_pinned",
    "is_volatile",
    "is_expired",
    "correction_chain",
]
