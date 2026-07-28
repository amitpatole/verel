"""Self-assessment against the agent-memory-atlas rubric — this is BOTH the atlas-method dogfood
AND a regression guard: each dimension is a live behavioural probe, so if a memory capability
regresses (e.g. recall stops filtering scope, or the tombstone stops blocking), its mark flips and
this test fails. 7/7 is pinned.
"""

from verel.memory.rubric import assess


def test_self_assessment_is_seven_of_seven():
    a = assess()
    failed = [(r.title, r.proof) for r in a.results if not r.passed]
    assert a.score == 7, f"rubric regressed: {failed}"
    assert len(a.results) == 7


def test_every_dimension_has_evidence_and_proof():
    for r in assess().results:
        assert r.evidence and r.proof, f"{r.title} missing evidence/proof"
        assert r.criterion  # the atlas pass criterion is recorded verbatim


def test_probes_are_behavioural_not_hardcoded():
    """Sanity: the marks come from running behaviour, so a proof string reflects observed state
    (contains a concrete True/value), not a canned 'pass'."""
    a = assess()
    joined = " ".join(r.proof for r in a.results)
    assert "True" in joined  # probes report observed booleans
    # bi-temporal probe must show the reconstructed historical value, proving as-of actually ran
    bt = next(r for r in a.results if r.key == "bitemporal")
    assert "us-east" in bt.proof and "us-west" in bt.proof


def test_render_is_human_readable():
    out = assess().render()
    assert "7/7" in out and "NOT a maturity score" in out
    for title in ("Rejected-value Tombstone", "Bi-temporal Validity", "Human Review Surface"):
        assert title in out
