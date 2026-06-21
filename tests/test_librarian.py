"""The librarian (§5) — the gated maintenance cycle: consolidate, induce, graduate, prune. Offline."""

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    Trust,
    librarian_pass,
)
from verel.memory.view import make_key

RULE_STUB = '{"subject":"cards","condition":"fixed px","action":"use max-width","applies_to":"narrow"}'
SCHEMA_STUB = '{"subject":"layout","principle":"keep elements in-bounds"}'


def _both(messages):  # rule prompt vs schema prompt
    return SCHEMA_STUB if "principle" in messages[0]["content"].lower() else RULE_STUB


def _fail(text, kind, scope="repo:app"):
    return MemoryRecord(kind=MemoryKind.FAILURE, subject=text[:10], predicate="f", text=text,
                        scope=scope, subj_pred_key=make_key(text + scope, "f", scope)).with_detail(kind=kind)


def _rule(subj, text, scope, *, covers="layout"):
    return MemoryRecord(kind=MemoryKind.DESIGN_RULE, subject=subj, predicate="design_rule", text=text,
                        scope=scope, trust=Trust.VERIFIED, epistemic_confidence=0.8,
                        subj_pred_key=make_key(subj, "design_rule", scope)).with_detail(covers_kind=covers)


def _weak(subj, scope="repo:app"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="p", text="ephemeral",
                        scope=scope, trust=Trust.CANDIDATE, epistemic_confidence=0.3,
                        retrieval_strength=0.1, support_count=1, created_ts=0.0,
                        subj_pred_key=make_key(subj, "p", scope))


def test_consolidates_recurring_failures():
    mem = LocalMemory()
    mem.write(_fail("card overflows viewport", "overflow"))
    mem.write(_fail("panel overflow narrow", "overflow"))
    rep = librarian_pass(mem, scope="repo:app", chat=_both, induce=False, prune=False)
    assert rep.rules_induced == 1


def test_induces_schema_hierarchy_over_rules():
    mem = LocalMemory()
    mem.write(_rule("cards", "use max-width", "repo:app"))
    mem.write(_rule("grid", "avoid fixed px", "repo:app"))   # same family → one cluster → a schema
    rep = librarian_pass(mem, scope="repo:app", chat=_both, consolidate=False, prune=False, min_size=2)
    assert rep.schemas_induced >= 1


def test_prunes_decayed_records():
    mem = LocalMemory()
    mem.write(_weak("junk1"))
    mem.write(_weak("junk2"))
    rep = librarian_pass(mem, scope="repo:app", chat=_both, consolidate=False, induce=False,
                         half_life_s=1.0, now=10**9)        # age the weak records far out
    assert rep.pruned == 2 and not mem.all(scope="repo:app")


def test_graduates_cross_repo_beliefs_up_the_lattice():
    mem = LocalMemory()
    mem.write(_rule("logging", "use JSON logs", "repo:app"))
    mem.write(_rule("logging", "use JSON logs", "repo:billing"))
    rep = librarian_pass(mem, scope="team:web", children=["repo:app", "repo:billing"], chat=_both,
                         consolidate=False, induce=False, prune=False, graduate_min_scopes=2)
    assert rep.graduated == 1
    grad = next(r for r in mem.all(scope="team:web") if r.subject == "logging")
    assert grad.trust == Trust.CANDIDATE   # graduated knowledge re-earns trust at the top


def test_report_aggregates_and_toggles_skip_stages():
    mem = LocalMemory()
    mem.write(_weak("j"))
    rep = librarian_pass(mem, scope="repo:app", chat=_both, consolidate=False, induce=False,
                         half_life_s=1.0, now=10**9)
    assert rep.changed == rep.pruned == 1
    assert "pruned" in rep.summary()
    # everything off → a no-op pass
    noop = librarian_pass(mem, scope="repo:app", chat=_both, consolidate=False, induce=False, prune=False)
    assert noop.changed == 0


def test_librarian_maintains_a_shared_brain_over_http(tmp_path):
    from verel.memory import MemoryServer, RemoteMemory
    srv = MemoryServer(tmp_path / "brain.db").start()
    try:
        remote = RemoteMemory(srv.url)
        remote.write(_fail("card overflows", "overflow", scope="team:web"))
        remote.write(_fail("panel overflow", "overflow", scope="team:web"))
        rep = librarian_pass(remote, scope="team:web", chat=_both, induce=False, prune=False)
        assert rep.rules_induced == 1   # the librarian curates the SHARED store through RemoteMemory
    finally:
        srv.stop()
