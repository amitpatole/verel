"""Cross-agent trust (§5) — import_belief (trust doesn't travel) + AuthorTrust. Offline."""

from verel.memory import (
    AuthorTrust,
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    Trust,
    author_of,
    import_belief,
)
from verel.memory.view import make_key


def _claim(subj, text, *, scope="team:web", author="", conf=0.99, trust=Trust.VERIFIED):
    r = MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="rule", text=text, scope=scope,
                     trust=trust, epistemic_confidence=conf, subj_pred_key=make_key(subj, "rule", scope))
    return r.with_detail(author=author) if author else r


# ---- import_belief: trust does not travel ----
def test_peer_claim_enters_as_candidate_regardless_of_its_asserted_trust():
    mem = LocalMemory()
    # the peer asserts VERIFIED with confidence 0.99 — none of that is honored
    res = import_belief(mem, _claim("x", "do the thing", trust=Trust.VERIFIED, conf=0.99),
                        verify=lambda r: False)
    assert res.installed and not res.reverified
    stored = next(r for r in mem.all(scope="team:web") if r.subject == "x")
    assert stored.trust == Trust.CANDIDATE and stored.epistemic_confidence < 0.99


def test_reverify_pass_promotes_to_verified_locally():
    mem = LocalMemory()
    res = import_belief(mem, _claim("y", "holds in my repo"), verify=lambda r: True)
    assert res.reverified
    assert next(r for r in mem.all(scope="team:web") if r.subject == "y").trust == Trust.VERIFIED


def test_imported_belief_records_author_and_provenance():
    mem = LocalMemory()
    import_belief(mem, _claim("z", "rule", author="agent-7"), verify=lambda r: True)
    rec = next(r for r in mem.all(scope="team:web") if r.subject == "z")
    assert author_of(rec) == "agent-7"
    assert any(p == "imported:agent-7" for p in rec.provenance)
    assert rec.detail["imported"] is True and rec.detail["grounding"] == "imported"


# ---- AuthorTrust ----
def test_author_prior_is_laplace_smoothed_and_neutral_when_unknown():
    mem = LocalMemory()
    at = AuthorTrust(mem)
    assert at.prior("nobody") == 0.5 and at.standing("nobody") == (0, 0)
    for _ in range(8):
        at.record("good", ok=True)
    for i in range(8):
        at.record("noisy", ok=(i % 4 == 0))   # 2/8
    assert at.prior("good") > 0.85 and at.standing("good") == (8, 8)
    assert at.prior("noisy") < 0.4 and at.standing("noisy") == (2, 8)


def test_author_prior_anchors_import_confidence_not_the_claim():
    mem = LocalMemory()
    at = AuthorTrust(mem)
    for _ in range(10):
        at.record("trusted", ok=True)
    for _ in range(10):
        at.record("flaky", ok=False)
    # identical self-asserted confidence; the importer anchors to AUTHOR reputation instead
    import_belief(mem, _claim("p", "x", author="trusted", conf=0.99), verify=lambda r: False, author_trust=at)
    import_belief(mem, _claim("q", "x", author="flaky", conf=0.99), verify=lambda r: False, author_trust=at)
    hi = next(r for r in mem.all(scope="team:web") if r.subject == "p").epistemic_confidence
    lo = next(r for r in mem.all(scope="team:web") if r.subject == "q").epistemic_confidence
    assert hi > lo


def test_import_updates_author_standing():
    mem = LocalMemory()
    at = AuthorTrust(mem)
    import_belief(mem, _claim("a", "1", author="w"), verify=lambda r: True, author_trust=at)
    import_belief(mem, _claim("b", "2", author="w"), verify=lambda r: False, author_trust=at)
    assert at.standing("w") == (1, 2)   # one re-verified, one didn't


def test_import_without_author_trust_uses_neutral_prior():
    mem = LocalMemory()
    res = import_belief(mem, _claim("n", "x"), verify=lambda r: False)
    assert res.prior == 0.5 and res.installed and not res.reverified
