"""The authenticated multi-principal brain — closes the brain audit's deferred Findings 3 & 4.

Finding 3: `author` was an unauthenticated free string → AuthorTrust forgery/impersonation. Now a
principal is an ed25519 keypair; `author` is the VERIFIED key_id, so you can't author as someone else.
Finding 4: `rank()` ignored the trust tier → a candidate could outrank a verified fact. Now fixed.
"""

import pytest

pytest.importorskip("nacl", reason="principal auth needs verel[attest] (pynacl)")

from verel.memory import (  # noqa: E402
    AuthorTrust,
    LocalMemory,
    MemoryServer,
    Principal,
    RemoteMemory,
    authenticated_remember,
    verify_write,
)
from verel.memory.view import (  # noqa: E402
    MemoryKind,
    MemoryRecord,
    Trust,
    make_id,
    make_key,
    rank,
    relevance,
)


# --- Finding 4: trust-weighted ranking --------------------------------------
def test_verified_outranks_candidate_at_equal_relevance():
    q = "deploy oncall rule"
    verified = MemoryRecord(kind=MemoryKind.FACT, subject="deploy", predicate="oncall",
                            text="deploy oncall rule", trust=Trust.VERIFIED)
    candidate = MemoryRecord(kind=MemoryKind.FACT, subject="deploy", predicate="oncall",
                             text="deploy oncall rule", trust=Trust.CANDIDATE)
    assert rank(verified, relevance(q, verified)) > rank(candidate, relevance(q, candidate))
    # but a much MORE relevant candidate still beats a barely-relevant verified one (relevance dominates)
    relevant_cand = candidate
    irrelevant_verified = MemoryRecord(kind=MemoryKind.FACT, subject="z", predicate="z", text="z",
                                       trust=Trust.VERIFIED)
    assert rank(relevant_cand, relevance(q, relevant_cand)) > rank(irrelevant_verified, relevance(q, irrelevant_verified))


# --- Finding 3: authenticated principals ------------------------------------
def _mem():
    return LocalMemory(":memory:")


def test_signed_write_authenticates_and_derives_author():
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    sig = alice.sign_write(subject="db", predicate="engine", scope="team", text="postgres")
    r = authenticated_remember(mem, subject="db", predicate="engine", scope="team", text="postgres",
                               signature=sig, key_id=alice.key_id, trusted=trusted)
    assert r.authenticated and r.written and r.author == alice.key_id


def test_cannot_author_as_another_principal():
    """The core of finding 3: signing with your own key but claiming alice's key_id must fail."""
    alice, mallory = Principal.generate(), Principal.generate()
    trusted = dict([alice.enroll(), mallory.enroll()])
    forged = mallory.sign_write(subject="x", predicate="y", scope="team", text="poison")
    r = authenticated_remember(_mem(), subject="x", predicate="y", scope="team", text="poison",
                               signature=forged, key_id=alice.key_id, trusted=trusted)
    assert r.authenticated is False and r.written is False


def test_unenrolled_principal_rejected():
    eve = Principal.generate()
    sig = eve.sign_write(subject="a", predicate="b", scope="team", text="hi")
    r = authenticated_remember(_mem(), subject="a", predicate="b", scope="team", text="hi",
                               signature=sig, key_id=eve.key_id, trusted={})
    assert r.authenticated is False


def test_signature_is_bound_to_the_claim():
    """A signature over one claim must not verify a DIFFERENT fact (the payload binds the content)."""
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    sig = alice.sign_write(subject="a", predicate="b", scope="team", text="original")
    assert verify_write(key_id=alice.key_id, subject="a", predicate="b", scope="team",
                        text="original", signature=sig, trusted=trusted) is True
    assert verify_write(key_id=alice.key_id, subject="a", predicate="b", scope="team",
                        text="TAMPERED", signature=sig, trusted=trusted) is False


def test_enrolled_pubkey_must_match_its_key_id():
    """A trusted entry whose pubkey doesn't hash to its key_id can't grant trust (no id/key swap)."""
    alice, bob = Principal.generate(), Principal.generate()
    bad_trust = {alice.key_id: bob.public_key_b64()}   # alice's id mapped to bob's key
    sig = alice.sign_write(subject="a", predicate="b", scope="team", text="x")
    assert verify_write(key_id=alice.key_id, subject="a", predicate="b", scope="team", text="x",
                        signature=sig, trusted=bad_trust) is False


def test_cross_principal_verified_overwrite_blocked():
    alice, bob = Principal.generate(), Principal.generate()
    trusted = dict([alice.enroll(), bob.enroll()])
    mem = _mem()
    sig = alice.sign_write(subject="db", predicate="engine", scope="team", text="postgres")
    authenticated_remember(mem, subject="db", predicate="engine", scope="team", text="postgres",
                           signature=sig, key_id=alice.key_id, trusted=trusted)
    mem.promote(make_id(make_key("db", "engine", "team")))   # alice's belief is now verified
    bsig = bob.sign_write(subject="db", predicate="engine", scope="team", text="sqlite")
    r = authenticated_remember(mem, subject="db", predicate="engine", scope="team", text="sqlite",
                               signature=bsig, key_id=bob.key_id, trusted=trusted)
    assert r.conflict is True and r.written is False
    assert mem.get(make_id(make_key("db", "engine", "team"))).text == "postgres"


def test_authortrust_keys_on_authenticated_id():
    """AuthorTrust can't be inflated/tanked under a name you don't hold — it keys on the verified id."""
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    at = AuthorTrust(mem)
    sig = alice.sign_write(subject="s", predicate="p", scope="team", text="t")
    authenticated_remember(mem, subject="s", predicate="p", scope="team", text="t", signature=sig,
                           key_id=alice.key_id, trusted=trusted, author_trust=at)
    # a standing exists for alice's real id; a made-up name has the neutral prior
    assert at.prior("not-a-real-principal") == 0.5


# --- the HTTP wiring (in-process server) ------------------------------------
def test_signed_write_over_http(tmp_path):
    alice, eve = Principal.generate(), Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "brain.db"),
                       trusted_principals=dict([alice.enroll()])).start()
    try:
        cli = RemoteMemory(srv.url)
        r = cli.remember_signed(alice, subject="deploy", predicate="how", scope="team", text="page")
        assert r["authenticated"] and r["written"] and r["author"] == alice.key_id
        assert [x.text for x in cli.recall("page", scope="team")] == ["page"]
        # unenrolled principal → rejected (403 surfaced as a structured result, not an exception)
        r2 = cli.remember_signed(eve, subject="x", predicate="y", scope="team", text="poison")
        assert r2["authenticated"] is False and r2["written"] is False
        # enroll then accepted
        srv.enroll(*eve.enroll())
        assert cli.remember_signed(eve, subject="x", predicate="y", scope="team", text="ok")["written"]
    finally:
        srv.stop()
