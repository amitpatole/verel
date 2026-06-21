"""Scope lattice (§5) — resolve-down recall + graduate-up promotion. Offline, pure logic."""

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    ScopeLattice,
    Trust,
    graduate,
    lattice_recall,
)
from verel.memory.view import make_key


def _fact(subj, text, scope, *, trust=Trust.VERIFIED, ec=0.8):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="rule", text=text,
                        scope=scope, trust=trust, epistemic_confidence=ec,
                        subj_pred_key=make_key(subj, "rule", scope))


# ---- ScopeLattice ----
def test_ancestors_chain_and_default_is_flat():
    lat = ScopeLattice({"repo:app": "team:web", "team:web": "org:acme", "org:acme": "global"})
    assert lat.ancestors("repo:app") == ["repo:app", "team:web", "org:acme", "global"]
    assert ScopeLattice().ancestors("repo:x") == ["repo:x", "global"]  # default rolls up to global
    assert ScopeLattice().ancestors("global") == ["global"]


def test_ancestors_is_cycle_guarded():
    lat = ScopeLattice({"a": "b", "b": "a"})        # pathological cycle
    chain = lat.ancestors("a")
    assert chain[:2] == ["a", "b"] and chain[-1] == "global" and len(set(chain)) == len(chain)


def test_children_of():
    lat = ScopeLattice({"repo:app": "team:web", "repo:billing": "team:web", "team:web": "global"})
    assert set(lat.children("team:web", ["repo:app", "repo:billing", "team:web", "other"])) \
        == {"repo:app", "repo:billing"}


# ---- resolve down ----
def test_recall_resolves_across_ancestors():
    mem = LocalMemory()
    lat = ScopeLattice({"repo:app": "team:web", "team:web": "global"})
    mem.write(_fact("deploy", "deploy via the pipeline", "team:web"))
    mem.write(_fact("secrets", "secrets live in vault", "global"))
    hits = lattice_recall(mem, "how do we deploy secrets", scope="repo:app", lattice=lat, k=5)
    scopes = {r.scope for r in hits}
    assert scopes == {"team:web", "global"}   # sees the team rule AND the org-wide one


def test_specificity_breaks_ties_most_specific_wins():
    mem = LocalMemory()
    lat = ScopeLattice({"repo:app": "team:web", "team:web": "global"})
    for s in ("global", "team:web", "repo:app"):
        mem.write(_fact("deploy", "deploy via the pipeline", s))   # identical text → equal relevance
    order = [r.scope for r in lattice_recall(mem, "how do we deploy", scope="repo:app", lattice=lat, k=3)]
    assert order == ["repo:app", "team:web", "global"]   # closer scope ranks first


def test_stronger_relevance_in_a_broader_scope_still_wins():
    # the bonus only breaks ties; a much more relevant broader memory is NOT buried
    mem = LocalMemory()
    lat = ScopeLattice({"repo:app": "team:web", "team:web": "global"})
    mem.write(_fact("ci", "require 1 thing", "repo:app"))                 # weak match
    mem.write(_fact("ci", "require code review approvals on ci", "team:web"))  # strong match
    top = lattice_recall(mem, "code review approvals on ci", scope="repo:app", lattice=lat, k=1)
    assert top[0].scope == "team:web"


def test_recall_skips_rejected_and_irrelevant():
    mem = LocalMemory()
    mem.write(_fact("a", "totally unrelated content", "global"))
    mem.write(_fact("deploy", "deploy guide", "global", trust=Trust.REJECTED))
    assert lattice_recall(mem, "deploy", scope="repo:app", k=5) == []  # nothing relevant + not rejected


# ---- graduate up ----
def test_graduate_promotes_a_belief_verified_across_siblings():
    mem = LocalMemory()
    mem.write(_fact("logging", "use structured JSON logs", "repo:app"))
    mem.write(_fact("logging", "use structured JSON logs", "repo:billing"))
    grad = graduate(mem, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2)
    assert len(grad) == 1
    g = grad[0]
    assert g.scope == "team:web" and g.trust == Trust.CANDIDATE          # re-earns trust at the top
    assert g.detail["grounding"] == "graduated"
    assert g.detail["graduated_from"] == ["repo:app", "repo:billing"]


def test_single_scope_belief_does_not_graduate():
    mem = LocalMemory()
    mem.write(_fact("style", "tabs not spaces", "repo:app"))             # only one repo
    mem.write(_fact("logging", "use JSON logs", "repo:billing"))         # a different, also-single belief
    grad = graduate(mem, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2)
    assert grad == []


def test_unverified_belief_does_not_graduate():
    mem = LocalMemory()
    mem.write(_fact("x", "unproven idea", "repo:app", trust=Trust.CANDIDATE))
    mem.write(_fact("x", "unproven idea", "repo:billing", trust=Trust.CANDIDATE))
    assert graduate(mem, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2) == []


def test_regraduation_corroborates_the_team_belief():
    mem = LocalMemory()
    mem.write(_fact("logging", "use JSON logs", "repo:app"))
    mem.write(_fact("logging", "use JSON logs", "repo:billing"))
    g1 = graduate(mem, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2)[0]
    before = mem.get(g1.id).epistemic_confidence
    graduate(mem, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2)  # again
    assert mem.get(g1.id).epistemic_confidence >= before  # same claim re-asserted -> corroboration
