"""Verel memory — the trust layer Verel owns over a (rentable) backend (§5, §7.5).

Phase increment: MemoryView contract + zero-dep LocalMemory (sqlite) + the failure ledger /
regression guard + Ollama-backed cross-episode consolidation. mem0 is the documented
drop-in behind the same `MemoryView` Protocol.
"""

from __future__ import annotations

from .consolidate import consolidate_failures
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
    make_id,
    make_key,
    rank,
    should_prune,
)

__all__ = [
    "consolidate_failures",
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
]
