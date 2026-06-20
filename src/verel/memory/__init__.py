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
from .local import LocalMemory
from .mem0_backend import Mem0Memory, make_ollama_mem0
from .promotion import (
    EvalCase,
    HeldOutCorpus,
    PromotionGate,
    PromotionResult,
    evaluate_rule,
)
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
