#!/usr/bin/env python3
"""Bi-temporal memory — "what did we believe at time T?"

Every value carries VALID-time (`valid_from`/`valid_to`: when it was true in the world) distinct from
TRANSACTION-time (`created_ts`: when it was written). When a fact changes, the old value's interval
closes and the new one opens; the correction chain preserves the history. `recall_as_of` then
reconstructs the value that was actually true at any past wall-clock time — not today's.

Runs offline, no API key:

    python examples/demo_bitemporal.py
"""
from __future__ import annotations

from verel.memory import LocalMemory, recall_as_of, value_as_of
from verel.memory.view import MemoryKind, MemoryRecord

JAN, JUN, TODAY = 1_700_000_000.0, 1_705_000_000.0, 1_710_000_000.0


def fact(text: str) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FACT, subject="server", predicate="region",
                        text=text, scope="repo:acme")


def main() -> None:
    mem = LocalMemory(":memory:")

    # In January we learn the server region is us-east.
    mem.write(fact("us-east"), ts=JAN)
    # In June it moves to us-west — a legitimate change, not a correction of a lie.
    mem.write(fact("us-west"), ts=JUN)

    rid = mem.all()[0].id
    current = mem.get(rid)
    print("current value:", current.text,
          f"(valid_from={current.valid_from:.0f}, valid_to={'open' if not current.valid_to else current.valid_to})")
    print("history in the correction chain:")
    for c in current.detail.get("corrections", []):
        print(f"  - {c['text']:<8} valid [{c['valid_from']:.0f} .. {c['valid_to']:.0f})")

    print("\nas-of queries — what did we believe about the region at each time?")
    for label, t in [("before Jan", JAN - 1e6), ("March", (JAN + JUN) / 2), ("today", TODAY)]:
        hits = recall_as_of(mem, "server region", as_of=t, scope="repo:acme")
        answer = hits[0].text if hits else "(nothing — the fact didn't exist yet)"
        print(f"  as_of {label:<10} -> {answer}")

    # value_as_of is the pure reconstruction primitive underneath recall_as_of.
    print("\nvalue_as_of(March):", value_as_of(current, (JAN + JUN) / 2).text)


if __name__ == "__main__":
    main()
