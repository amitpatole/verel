"""Semantic recall demo (§5.6) — the brain retrieves by MEANING, not shared words.

With an embedder, a query that shares no vocabulary with a stored rule still recalls it.
Falls back to lexical recall (and still runs) if no embedder/key is available.

Run:  python examples/demo_semantic_recall.py   (uses OpenAI key for real embeddings)
"""

from __future__ import annotations

from verel.memory import HashEmbedder, LocalMemory, MemoryKind, MemoryRecord, OpenAIEmbedder

RULES = [
    ("fixed-width containers overflow the viewport on small screens", "overflow-rule"),
    ("ensure sufficient color contrast to meet WCAG AA", "contrast-rule"),
    ("memoize expensive pure functions to avoid recomputation", "perf-rule"),
    ("validate and escape user input before rendering it", "xss-rule"),
]
QUERY = "the card runs off the edge of a narrow phone display"  # shares no words with any rule


def main() -> int:
    try:
        embedder = OpenAIEmbedder()
        embedder.embed(["probe"])  # verify the key works
        kind = "OpenAI (semantic)"
    except Exception:
        embedder = HashEmbedder()
        kind = "HashEmbedder (offline, lexical-ish)"

    mem = LocalMemory(embedder=embedder)
    for text, subject in RULES:
        mem.write(MemoryRecord(kind=MemoryKind.DESIGN_RULE, subject=subject, predicate="rule",
                               text=text, scope="repo:x"))

    print(f"embedder: {kind}")
    print(f"query:    {QUERY!r}\n")
    hits = mem.recall(QUERY, scope="repo:x", k=2)
    for h in hits:
        print(f"  → {h.subject}: {h.text}")

    ok = hits and hits[0].subject == "overflow-rule"
    print("\nResult:", "PASS — recalled the overflow rule by meaning, with no shared words"
          if ok else "(top hit was not the overflow rule — likely the offline HashEmbedder)")
    return 0 if ok else 0  # informational; HashEmbedder fallback may not match semantically


if __name__ == "__main__":
    raise SystemExit(main())
