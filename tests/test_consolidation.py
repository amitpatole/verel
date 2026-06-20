"""Deepened consolidation (§5.5) — adaptive decay, semantic clustering, structured + 2nd-order
induction. Offline: the LLM is a stub chat; clustering uses synthetic vectors."""

from verel.memory import (
    HashEmbedder,
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    Trust,
    cluster_records,
    consolidate_across_scopes,
    consolidate_failures,
    induce_hierarchy,
    induce_schemas,
)
from verel.memory.view import apply_decay, effective_half_life, make_key


def _fail(text, kind, scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FAILURE, subject=text[:12], predicate="f", text=text,
                        scope=scope, subj_pred_key=make_key(text[:12] + scope, "f", scope)).with_detail(kind=kind)


def _rule(subj, text, covers_kind, scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.DESIGN_RULE, subject=subj, predicate="design_rule",
                        text=text, scope=scope, trust=Trust.CANDIDATE,
                        subj_pred_key=make_key(subj, "design_rule", scope)).with_detail(
        covers_kind=covers_kind, grounding="inferred")


# ---- adaptive decay tuning ----
def test_effective_half_life_grows_with_support_and_confidence():
    weak = MemoryRecord(kind=MemoryKind.FACT, text="x", support_count=1, epistemic_confidence=0.5)
    strong = MemoryRecord(kind=MemoryKind.FACT, text="y", support_count=8, epistemic_confidence=0.9)
    assert effective_half_life(strong, 100.0) > effective_half_life(weak, 100.0) > 100.0


def test_effective_half_life_is_capped():
    huge = MemoryRecord(kind=MemoryKind.FACT, text="z", support_count=10_000, epistemic_confidence=1.0)
    assert effective_half_life(huge, 100.0) <= 100.0 * 6.0  # HL_MAX_FACTOR


def test_well_supported_memory_decays_slower():
    weak = MemoryRecord(kind=MemoryKind.FACT, text="x", support_count=1, epistemic_confidence=0.5,
                        retrieval_strength=1.0, created_ts=0.0)
    strong = MemoryRecord(kind=MemoryKind.FACT, text="y", support_count=8, epistemic_confidence=0.9,
                          retrieval_strength=1.0, created_ts=0.0)
    for r in (weak, strong):
        apply_decay(r, now=100.0, half_life_s=100.0, stale_after_s=1e9, volatile_ttl_s=1e9)
    assert strong.retrieval_strength > weak.retrieval_strength


# ---- clustering ----
def test_cluster_by_kind_never_merges_distinct_kinds():
    recs = [_fail("a", "overflow"), _fail("b", "overflow"), _fail("c", "contrast")]
    clusters = cluster_records(recs)  # no vectors -> bucket by kind
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 2]  # overflow{2}, contrast{1} — never a single merged cluster


def test_semantic_refine_splits_within_a_kind():
    recs = [MemoryRecord(kind=MemoryKind.FAILURE, text=f"r{i}").with_detail(kind="overflow")
            for i in range(4)]
    vecs = {id(recs[0]): [1, 0, 0], id(recs[1]): [0.99, 0.1, 0],
            id(recs[2]): [0, 1, 0], id(recs[3]): [0, 0.98, 0.1]}
    clusters = cluster_records(recs, vector_of=lambda r: vecs[id(r)], threshold=0.8)
    assert sorted(len(c) for c in clusters) == [2, 2]  # two sub-patterns inside one kind


# ---- structured rule induction ----
def _stub_rule(messages):
    if "contrast" in messages[-1]["content"]:
        return ('{"subject":"buttons","condition":"text contrast below WCAG",'
                '"action":"use a >=4.5:1 ratio","applies_to":"all text"}')
    return ('{"subject":"cards","condition":"fixed px width on a card",'
            '"action":"use max-width:100%","applies_to":"narrow viewports"}')


def test_consolidate_writes_structured_candidate_rules():
    mem = LocalMemory()
    for t, k in [("card overflows viewport", "overflow"), ("panel overflow narrow", "overflow"),
                 ("low contrast cta", "contrast"), ("button text contrast poor", "contrast")]:
        mem.write(_fail(t, k))
    rules = consolidate_failures(mem, scope="repo:x", min_cluster=2, chat=_stub_rule)
    assert {r.detail["covers_kind"] for r in rules} == {"overflow", "contrast"}
    for r in rules:
        assert r.trust == Trust.CANDIDATE and r.detail["grounding"] == "inferred"
        assert r.detail["condition"] and r.detail["action"] and r.detail["applies_to"]
        assert "→" in r.text  # condition → action
        assert len(r.provenance) == 2  # both clustered failures cited


def test_consolidate_accepts_legacy_flat_rule_format():
    mem = LocalMemory()
    mem.write(_fail("a", "overflow"))
    mem.write(_fail("b", "overflow"))
    flat = lambda _m: '{"subject":"cards","rule":"use max-width:100%"}'  # noqa: E731
    rules = consolidate_failures(mem, scope="repo:x", min_cluster=2, chat=flat)
    assert len(rules) == 1 and rules[0].detail["action"] == "use max-width:100%"


# ---- 2nd-order schema induction (rules cluster by their covered family) ----
def test_induce_schema_subsumes_rules_and_is_candidate():
    mem = LocalMemory()
    mem.write(_rule("cards", "use max-width", "layout"))      # same family -> one cluster
    mem.write(_rule("grid", "avoid fixed px", "layout"))
    schema_chat = lambda _m: '{"subject":"responsive layout","principle":"keep elements in-bounds"}'  # noqa: E731
    schemas = induce_schemas(mem, scope="repo:x", min_rules=2, chat=schema_chat)
    assert len(schemas) == 1
    s = schemas[0]
    assert s.kind == MemoryKind.SCHEMA and s.trust == Trust.CANDIDATE
    assert s.detail["grounding"] == "schema" and s.detail["order"] == 2
    assert len(s.detail["subsumes"]) == 2


def test_schema_induction_does_not_reconsolidate_schemas():
    mem = LocalMemory()
    mem.write(_rule("cards", "use max-width", "layout"))
    mem.write(_rule("grid", "avoid fixed px", "layout"))
    schema_chat = lambda _m: '{"subject":"layout","principle":"be responsive"}'  # noqa: E731
    induce_schemas(mem, scope="repo:x", min_rules=2, chat=schema_chat)
    # a second pass sees the SCHEMA but excludes it (only DESIGN_RULEs feed the first hop)
    again = induce_schemas(mem, scope="repo:x", min_rules=2, chat=schema_chat)
    assert len(again) == 1  # still only the 2 rules cluster; the schema itself is not re-fed


def test_semantic_consolidation_with_real_embedder_runs():
    # semantic=True exercises the vector path end-to-end (HashEmbedder is non-semantic, so we
    # only assert it produces candidate rules, not a specific clustering)
    mem = LocalMemory(embedder=HashEmbedder(dim=128))
    for t, k in [("card overflows viewport narrow", "overflow"),
                 ("panel overflow viewport mobile", "overflow")]:
        mem.write(_fail(t, k))
    rules = consolidate_failures(mem, scope="repo:x", min_cluster=2, chat=_stub_rule, semantic=True)
    assert all(r.trust == Trust.CANDIDATE for r in rules)


# ---- multi-hop schema hierarchy ----
def _counting_schema_chat():
    n = {"i": 0}

    def chat(_messages):
        n["i"] += 1
        return f'{{"subject":"principle{n["i"]}","principle":"general principle {n["i"]}"}}'
    return chat


def test_induce_hierarchy_builds_multiple_levels():
    mem = LocalMemory()
    for s, t, k in [("cards", "use max-width", "layout"), ("grid", "avoid fixed px", "layout"),
                    ("cta", "4.5:1 contrast", "color"), ("text", "darken on light", "color")]:
        mem.write(_rule(s, t, k))
    levels = induce_hierarchy(mem, scope="repo:x", min_size=2, max_order=4, chat=_counting_schema_chat())
    # two rule-families -> two order-2 schemas -> one order-3 meta-schema; then it stops
    assert {o: len(v) for o, v in levels.items()} == {2: 2, 3: 1}
    assert all(s.detail["order"] == 2 for s in levels[2])
    assert levels[3][0].detail["order"] == 3 and len(levels[3][0].detail["subsumes"]) == 2


def test_hierarchy_nodes_are_all_candidate():
    mem = LocalMemory()
    for s, t, k in [("a", "x", "layout"), ("b", "y", "layout"), ("c", "z", "color"), ("d", "w", "color")]:
        mem.write(_rule(s, t, k))
    levels = induce_hierarchy(mem, scope="repo:x", min_size=2, chat=_counting_schema_chat())
    assert all(s.trust == Trust.CANDIDATE for v in levels.values() for s in v)  # height ≠ trust


def test_hierarchy_stops_when_corpus_too_thin():
    mem = LocalMemory()
    mem.write(_rule("a", "x", "layout"))  # a single rule supports no schema at all
    assert induce_hierarchy(mem, scope="repo:x", min_size=2, chat=_counting_schema_chat()) == {}


# ---- cross-scope consolidation ----
def _rule_chat(_m):
    return ('{"subject":"layout","condition":"fixed width","action":"use max-width",'
            '"applies_to":"all repos"}')


def test_consolidate_across_scopes_generalizes_a_cross_repo_pattern():
    mem = LocalMemory()
    mem.write(_fail("card overflow", "overflow", "repo:A"))
    mem.write(_fail("panel overflow", "overflow", "repo:B"))  # same kind, different repo
    rules = consolidate_across_scopes(mem, ["repo:A", "repo:B"], target_scope="global",
                                      min_scopes=2, min_cluster=2, chat=_rule_chat)
    assert len(rules) == 1
    r = rules[0]
    assert r.scope == "global" and r.detail["cross_scope"] is True
    assert r.detail["spans"] == ["repo:A", "repo:B"]


def test_cross_scope_ignores_a_single_repo_quirk():
    mem = LocalMemory()
    mem.write(_fail("card overflow", "overflow", "repo:A"))
    mem.write(_fail("panel overflow", "overflow2", "repo:A"))  # both in ONE repo (and diff kinds)
    rules = consolidate_across_scopes(mem, ["repo:A", "repo:B"], min_scopes=2, min_cluster=2, chat=_rule_chat)
    assert rules == []  # spans only one scope -> not generalized
