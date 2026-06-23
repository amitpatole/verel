"""Pluggable memory backends — select the brain's store by name, no code change (v0.41.0).

The shared brain is a `MemoryView`. Verel resolves it from `VEREL_MEMORY_BACKEND` through the
backend registry, so swapping SQLite for an external DB is one env var, not a code edit. The trust
layer (corroborate/supersede/recall) is identical whichever backend is selected — that's the whole
point of the contract.

Run:  python examples/demo_backend_registry.py
Needs: nothing (uses the zero-dep local SQLite backend, in-memory).
"""

from __future__ import annotations

import os

from verel.memory import MemoryKind, MemoryRecord, known_backends, load_backend

# Operator env picks the backend. Here we force the zero-dep local store, in-memory, so the demo
# runs anywhere; in production set VEREL_MEMORY_BACKEND=postgres (etc.) + that backend's URL.
os.environ["VEREL_MEMORY_BACKEND"] = "local"
os.environ["VEREL_MEMORY_STORE"] = ":memory:"

print(f"available backends: {known_backends()}")
brain = load_backend(os.environ["VEREL_MEMORY_BACKEND"])
print(f"selected: {os.environ['VEREL_MEMORY_BACKEND']} -> {type(brain).__name__}\n")


def fact(text: str) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FACT, subject="card", predicate="width", text=text,
                        scope="repo:demo")


# 1) write a belief, 2) re-assert it -> corroboration (one row, support grows, NOT a duplicate),
# 3) assert a NEW value for the same key -> supersession with a queryable correction chain.
r = brain.write(fact("use width:100%"))
print(f"wrote   id={r.id}  conf={r.epistemic_confidence}  support={r.support_count}")

again = brain.write(fact("use width:100%"))
print(f"re-assert -> support={again.support_count} (corroborated, still one row)")

superseded = brain.write(fact("use max-width:100%"))
got = brain.get(superseded.id)
print(f"supersede -> now={got.text!r}  was={got.detail.get('superseded')!r}")

hits = brain.recall("max-width card width", scope="repo:demo")
print(f"\nrecall -> {[h.text for h in hits]}")
print("same MemoryView contract holds for every backend — local, remote, or an external DB.")
