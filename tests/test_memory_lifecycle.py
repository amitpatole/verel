"""Memory lifecycle additions (community-validated from the r/aiagents memory thread):
pinned · volatile-until-confirmed · hard TTL · context-triggered staleness · correction chains."""

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    correction_chain,
    is_pinned,
)

HOUR = 3600.0
DAY = 24 * HOUR


def _weak(text="ephemeral fact", subject="x", scope="repo:t", **detail):
    r = MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate="p", text=text, scope=scope,
                     retrieval_strength=0.1, epistemic_confidence=0.3, support_count=1)
    if detail:
        r.with_detail(**detail)
    return r


# ---- pinned: never decays / never pruned ----
def test_pinned_survives_prune_and_decay():
    m = LocalMemory()
    r = m.write(_weak(text="critical pinned rule"))
    m.pin(r.id)
    before = m.get(r.id).retrieval_strength
    pruned = m.decay(now=10 * 365 * DAY)  # a decade later
    assert pruned == 0
    got = m.get(r.id)
    assert got is not None and is_pinned(got)
    assert got.retrieval_strength == before  # pinned ignores decay entirely


def test_unpinned_weak_record_is_pruned():
    m = LocalMemory()
    r = m.write(_weak())
    assert m.decay(now=10 * 365 * DAY) == 1 and m.get(r.id) is None


# ---- hard TTL: ephemeral environment facts expire ----
def test_ttl_expires_ephemeral_fact():
    m = LocalMemory()
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="branch", predicate="is",
                             text="current branch is feature-x", scope="repo:t", created_ts=0.0))
    m.set_flags(r.id, ttl_s=HOUR)  # valid for one hour
    assert m.decay(now=30 * 60) == 0          # 30 min: still alive
    assert m.get(r.id) is not None
    assert m.decay(now=2 * HOUR) == 1          # 2 h: expired
    assert m.get(r.id) is None


# ---- volatile-until-confirmed ----
def test_volatile_expires_unless_confirmed():
    m = LocalMemory()
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="guess", predicate="p",
                             text="maybe true", scope="repo:t", created_ts=0.0).with_detail(volatile=True))
    # unconfirmed past the volatile window -> pruned
    assert m.decay(now=2 * DAY) == 1 and m.get(r.id) is None


def test_volatile_confirmed_by_corroboration_survives():
    m = LocalMemory()
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="guess2", predicate="p",
                             text="becomes true", scope="repo:t", created_ts=0.0,
                             epistemic_confidence=0.6).with_detail(volatile=True))
    m.corroborate(r.id)                         # confirmation clears volatile
    assert not m.get(r.id).detail.get("volatile")
    assert m.decay(now=2 * DAY) == 0 and m.get(r.id) is not None  # no longer volatile -> kept


# ---- context-triggered staleness ----
def test_idle_record_flagged_stale():
    m = LocalMemory()
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="rarely used",
                             scope="repo:t", created_ts=0.0, last_recall_ts=0.0,
                             epistemic_confidence=0.9, support_count=3))  # strong enough not to prune
    m.decay(now=60 * DAY, stale_after_s=30 * DAY)
    got = m.get(r.id)
    assert got is not None and got.detail.get("stale") is True


# ---- correction chains ----
def test_supersede_builds_correction_chain():
    m = LocalMemory()
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="port", predicate="is", text="8080",
                         scope="repo:t", created_ts=1.0))
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="port", predicate="is", text="9090",
                         scope="repo:t", created_ts=2.0))
    final = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="port", predicate="is", text="3000",
                                 scope="repo:t", created_ts=3.0))
    assert final.text == "3000"
    chain = correction_chain(m.get(final.id))
    assert [c["text"] for c in chain] == ["8080", "9090"]  # full history preserved, in order
