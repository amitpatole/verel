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

from verel.memory import (
    LocalMemory,
    members_as_of,
    parse_extracted_facts,
    recall_as_of,
    value_as_of,
)
from verel.memory.view import MemoryKind, MemoryRecord, make_id, make_key

JAN, JUN, TODAY = 1_700_000_000.0, 1_705_000_000.0, 1_710_000_000.0


def fact(text: str) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FACT, subject="server", predicate="region",
                        text=text, scope="repo:acme")


def role(subject: str, value: str) -> MemoryRecord:
    key = make_key(subject, "role", "repo:acme")
    return MemoryRecord(id=make_id(key), kind=MemoryKind.FACT, subject=subject, predicate="role",
                        text=value, scope="repo:acme", subj_pred_key=key)


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

    # --- valid-time CAPTURE + set-membership as-of ("who was admin THEN?") -----------
    print("\n--- roles over time (valid-time captured from content) ---")
    # Extraction reads the stated dates straight into valid_from/valid_to (fail-safe parsed):
    captured = parse_extracted_facts(
        '[{"subject":"alice","predicate":"role","object":"admin",'
        '"valid_from":"2024-01-03","valid_to":"2024-06-01"}]', scope="repo:acme")
    r = captured[0]
    print(f"  extracted: {r.subject} {r.predicate}={r.text}  "
          f"valid [{r.valid_from:.0f} .. {r.valid_to:.0f})  (not 'when we learned it')")

    # A role is a set-valued relation: alice was admin then demoted; bob is owner throughout.
    mem2 = LocalMemory(":memory:")
    mem2.write(role("alice", "admin"), ts=JAN)
    mem2.write(role("alice", "member"), ts=JUN)      # demoted in June
    mem2.write(role("bob", "owner"), ts=JAN)
    for label, t in [("March", (JAN + JUN) / 2), ("today", TODAY)]:
        admins = members_as_of(mem2, predicate="role", value="admin", as_of=t, scope="repo:acme")
        owners = members_as_of(mem2, predicate="role", value="owner", as_of=t, scope="repo:acme")
        print(f"  as_of {label:<6} -> admins={[a.subject for a in admins]}  "
              f"owners={[o.subject for o in owners]}")
    print("  → 'alice was an admin THEN' and 'bob is the current owner NOW' — history intact.")


if __name__ == "__main__":
    main()
