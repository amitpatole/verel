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


def test_signed_mode_blocks_unauthenticated_write_and_promote(tmp_path):
    """Red-team round 1: the raw /write (forge author) and /promote (forge verified) endpoints must be
    refused in signed-writes mode — else a bearer holder bypasses the principal layer entirely."""
    import urllib.error

    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "b.db"),
                       trusted_principals=dict([alice.enroll()])).start()
    try:
        cli = RemoteMemory(srv.url)
        forged = MemoryRecord(kind=MemoryKind.FACT, subject="x", predicate="y", text="poison",
                              scope="team").with_detail(author=alice.key_id)
        with pytest.raises(urllib.error.HTTPError) as e1:
            cli.write(forged)
        assert e1.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as e2:
            cli.promote("anyid")
        assert e2.value.code == 403
        # signed write + reads still work
        assert cli.remember_signed(alice, subject="a", predicate="b", scope="team", text="ok")["written"]
        assert [r.text for r in cli.recall("ok", scope="team")] == ["ok"]
    finally:
        srv.stop()


def test_signed_mode_unscoped_all_requires_cluster_credential(tmp_path):
    """R-001: in signed-writes mode the UNSCOPED `/all` (a full-brain dump of every scope/principal)
    must require the CLUSTER credential — a mere bearer holder must not exfiltrate the whole brain. A
    SCOPED `/all` stays a normal bearer read (the scope-lattice recall and consolidation use it)."""
    import urllib.error

    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "b.db"),
                       trusted_principals=dict([alice.enroll()]),
                       cluster_token="cluster-secret").start()  # nosec B106 — test literal
    try:
        srv.store.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                     text="secret", scope="team"))
        bearer = RemoteMemory(srv.url)
        with pytest.raises(urllib.error.HTTPError) as ei:
            bearer.all()                                   # UNSCOPED dump → refused for a bearer client
        assert ei.value.code == 403
        assert {r.text for r in bearer.all(scope="team")} == {"secret"}   # SCOPED → allowed
        coord = RemoteMemory(srv.url, cluster_token="cluster-secret")
        assert {r.text for r in coord.all()} == {"secret"}  # cluster credential → unscoped dump allowed
    finally:
        srv.stop()


def test_enroll_after_open_start_auto_enables_signed_mode(tmp_path):
    import urllib.error

    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "c.db")).start()   # no principals → open mode
    try:
        cli = RemoteMemory(srv.url)
        cli.write(MemoryRecord(kind=MemoryKind.FACT, subject="a", predicate="b", text="ok",
                               scope="team"))   # open: raw write allowed
        srv.enroll(*alice.enroll())             # enrolling flips enforcement ON (read live)
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.write(MemoryRecord(kind=MemoryKind.FACT, subject="c", predicate="d", text="x",
                                   scope="team"))
        assert e.value.code == 403
    finally:
        srv.stop()


def test_apply_replica_forgery_blocked_in_signed_mode(tmp_path):
    """Red-team round 2 CRITICAL: /apply is a verbatim upsert — in signed mode it must require the
    CLUSTER credential, not a bearer token, else a bearer holder forges trust=verified + author."""
    import urllib.error

    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "b.db"),
                       trusted_principals=dict([alice.enroll()])).start()
    try:
        cli = RemoteMemory(srv.url)   # bearer only, no cluster token
        forged = MemoryRecord(kind=MemoryKind.FACT, subject="x", predicate="y", text="poison",
                              scope="team", trust=Trust.VERIFIED).with_detail(author=alice.key_id)
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.apply_replica(forged)
        assert e.value.code == 403
    finally:
        srv.stop()


def test_cluster_token_gates_replication(tmp_path):
    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "c.db"), trusted_principals=dict([alice.enroll()]),
                       cluster_token="CLUSTER-SECRET").start()
    try:
        good = RemoteMemory(srv.url, cluster_token="CLUSTER-SECRET")
        good.apply_replica(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                        text="replicated", scope="team"))
        assert [x.text for x in RemoteMemory(srv.url).recall("replicated", scope="team")] == ["replicated"]
        import urllib.error
        bad = RemoteMemory(srv.url, cluster_token="WRONG")
        with pytest.raises(urllib.error.HTTPError) as e:
            bad.apply_replica(MemoryRecord(kind=MemoryKind.FACT, subject="z", predicate="z",
                                           text="x", scope="team"))
        assert e.value.code == 403
    finally:
        srv.stop()


def test_cross_principal_cannot_reattribute_verified_via_case_variant():
    """Red-team round 2 LOW: a case/whitespace variant of another principal's verified belief must
    not corroborate-and-rewrite its author."""
    from verel.memory.share import author_of
    alice, bob = Principal.generate(), Principal.generate()
    trusted = dict([alice.enroll(), bob.enroll()])
    mem = _mem()
    authenticated_remember(mem, subject="db", predicate="eng", scope="s", text="Postgres",
                           signature=alice.sign_write(subject="db", predicate="eng", scope="s", text="Postgres"),
                           key_id=alice.key_id, trusted=trusted)
    mem.promote(make_id(make_key("db", "eng", "s")))
    r = authenticated_remember(mem, subject="db", predicate="eng", scope="s", text="POSTGRES",
                               signature=bob.sign_write(subject="db", predicate="eng", scope="s", text="POSTGRES"),
                               key_id=bob.key_id, trusted=trusted)
    assert r.conflict is True
    assert author_of(mem.get(make_id(make_key("db", "eng", "s")))) == alice.key_id


def test_signed_write_fields_are_bounded():
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    big = "x" * 20_001
    sig = alice.sign_write(subject="s", predicate="p", scope="team", text=big)
    r = authenticated_remember(_mem(), subject="s", predicate="p", scope="team", text=big,
                               signature=sig, key_id=alice.key_id, trusted=trusted)
    assert r.authenticated and r.written is False and "too long" in r.reason


def test_signed_write_cannot_tamper_reputation_ledger():
    """A signed client write into the reserved `meta:authors` scope must NOT clobber an author's
    standing — its (subject, predicate, scope) collides with the AuthorTrust ledger key, which would
    otherwise supersede it via the interference rule and reset the victim's reputation to neutral."""
    mem = _mem()
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    at = AuthorTrust(mem)
    victim = "VICTIM_KEYID"
    for _ in range(5):
        at.record(victim, ok=True)
    assert at.standing(victim) == (5, 5)

    # alice signs a write whose key collides with the victim's reputation record — try the exact
    # reserved scope AND case/whitespace variants that normalize to it (make_key strips+lowercases).
    for sc in ("meta:authors", " META:AUTHORS ", "Meta:Authors", "meta:authors "):
        sig = alice.sign_write(subject=victim, predicate="author_trust", scope=sc, text="poison")
        r = authenticated_remember(mem, subject=victim, predicate="author_trust", scope=sc,
                                   text="poison", signature=sig, key_id=alice.key_id,
                                   trusted=trusted, author_trust=at)
        assert r.authenticated and r.written is False and "reserved" in r.reason, sc
        assert at.standing(victim) == (5, 5), sc  # standing untouched

    # a normal write to a non-reserved scope still goes through.
    sig2 = alice.sign_write(subject="s", predicate="p", scope="repo:default", text="hi")
    ok = authenticated_remember(mem, subject="s", predicate="p", scope="repo:default", text="hi",
                                signature=sig2, key_id=alice.key_id, trusted=trusted)
    assert ok.authenticated and ok.written


def test_signed_writes_cannot_forge_control_records():
    """Red-team round 4: a signed write may only author a plain FACT with a non-reserved predicate/
    scope. Control-bearing kinds (FAILURE/DESIGN_RULE/SCHEMA/SKILL) and server-managed predicates
    ('fails', 'author_trust', 'design_rule', 'schema') are refused — else a principal could clobber
    the failure-regression ledger or inject forged rules into the consolidation→promotion pipeline."""
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()

    def signed(subject, predicate, scope, text, kind):
        sig = alice.sign_write(subject=subject, predicate=predicate, scope=scope, text=text)
        return authenticated_remember(mem, subject=subject, predicate=predicate, scope=scope,
                                      text=text, signature=sig, key_id=alice.key_id, trusted=trusted,
                                      kind=kind)

    # control-bearing KINDS refused
    for k in (MemoryKind.FAILURE, MemoryKind.DESIGN_RULE, MemoryKind.SCHEMA, MemoryKind.SKILL):
        r = signed("s", "p", "repo:x", "x", k)
        assert r.authenticated and r.written is False and "facts" in r.reason, k
    # reserved PREDICATES refused (even as a FACT, even in a normal scope, even case/space variants).
    # "tool" is the toolsmith's SKILL-registry predicate: a FACT colliding with it (make_id ignores
    # kind) would clobber the executable tool body in detail['tool'] — red-team round 5.
    for pred in ("fails", "author_trust", "design_rule", "schema", "tool",
                 " FAILS ", "Author_Trust", "TOOL"):
        r = signed("fp", pred, "repo:x", "override", MemoryKind.FACT)
        assert r.written is False and "reserved" in r.reason, pred
    # a normal FACT still authors fine
    assert signed("deploy", "how", "team", "page oncall", MemoryKind.FACT).written is True


def test_signed_write_cannot_clobber_skill_record():
    """Red-team round 5: a signed client FACT must not collide with a toolsmith SKILL record. The
    SKILL store keys on make_key(name, 'tool', scope) and make_id ignores `kind`, so without
    reserving the 'tool' predicate a FACT with the same (subject, scope) shares the SKILL's id and
    the interference rule would overwrite the executable tool body (detail['tool'])."""
    from verel.memory.view import make_id
    from verel.toolsmith.registry import ToolRecord, ToolRegistry

    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    reg = ToolRegistry(mem, scope="global")
    skill = reg.register(ToolRecord(name="slugify", capability="make url slug",
                                    doc="slug", code="def f(): pass", provenance=[]),
                         trust=Trust.CANDIDATE)
    assert "tool" in skill.detail  # the executable body is present

    sig = alice.sign_write(subject="slugify", predicate="tool", scope="global", text="POISON")
    r = authenticated_remember(mem, subject="slugify", predicate="tool", scope="global",
                               text="POISON", signature=sig, key_id=alice.key_id, trusted=trusted,
                               kind=MemoryKind.FACT)
    assert r.authenticated and r.written is False and "reserved" in r.reason
    after = mem.get(make_id(make_key("slugify", "tool", "global")))
    assert after.kind == MemoryKind.SKILL and reg.get("slugify") is not None  # intact


def test_structural_backstop_blocks_any_non_fact_collision():
    """Root-cause fix (round 5): make_id ignores `kind`, so a client FACT shares an id with a
    server-managed record at the same key. A client must never supersede a NON-FACT record — even
    under a predicate the reserved denylist doesn't know, so a future server-managed kind can't
    reopen the collision class the denylist chases one entry at a time."""
    from verel.memory.view import MemoryRecord
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    mem.write(MemoryRecord(kind=MemoryKind.SKILL, subject="x", predicate="futurepred", scope="g",
                           text="SERVER", subj_pred_key=make_key("x", "futurepred", "g")))
    sig = alice.sign_write(subject="x", predicate="futurepred", scope="g", text="POISON")
    r = authenticated_remember(mem, subject="x", predicate="futurepred", scope="g", text="POISON",
                               signature=sig, key_id=alice.key_id, trusted=trusted, kind=MemoryKind.FACT)
    assert r.written is False and "server-managed" in r.reason
    rec = mem.get(make_id(make_key("x", "futurepred", "g")))
    assert rec.text == "SERVER" and rec.kind == MemoryKind.SKILL


def test_graduate_does_not_inherit_a_preempted_author():
    """Red-team round 6: graduate() writes collective team-knowledge to a client-reachable key. If a
    principal pre-empts that key with a same-text FACT, the corroboration merge must NOT leave the
    attacker's author on the graduated record (which would forge authorship + credit their
    AuthorTrust). graduate stamps author='' so the merge overwrites it."""
    from verel.memory import graduate
    from verel.memory.share import author_of
    from verel.memory.view import MemoryRecord
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    for sc in ("repo:a", "repo:b"):
        mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="rule", predicate="x", text="retry 3x",
                               scope=sc, trust=Trust.VERIFIED, subj_pred_key=make_key("rule", "x", sc)))
    sig = alice.sign_write(subject="rule", predicate="x", scope="team", text="retry 3x")
    authenticated_remember(mem, subject="rule", predicate="x", scope="team", text="retry 3x",
                           signature=sig, key_id=alice.key_id, trusted=trusted)
    graduate(mem, parent="team", children=["repo:a", "repo:b"], min_scopes=2)
    grad = mem.get(make_id(make_key("rule", "x", "team")))
    assert author_of(grad) != alice.key_id and author_of(grad) == ""


def test_verify_write_fails_closed_without_pynacl(monkeypatch):
    """Coverage pin: with PyNaCl absent, verify_write must return False (never accept)."""
    from verel.verdict import keys
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    sig = alice.sign_write(subject="a", predicate="b", scope="team", text="x")
    assert verify_write(key_id=alice.key_id, subject="a", predicate="b", scope="team", text="x",
                        signature=sig, trusted=trusted) is True
    monkeypatch.setattr(keys, "_NACL", False)
    assert verify_write(key_id=alice.key_id, subject="a", predicate="b", scope="team", text="x",
                        signature=sig, trusted=trusted) is False


def test_cross_protocol_signature_rejected():
    """Coverage pin: a receipt signature (domain 'runreceipt'/'gatereceipt') must NOT verify as a
    memwrite — the domain tag separates the protocols (no cross-protocol replay)."""
    from verel.verdict import RunReceipt, attest_self
    from verel.verdict.keys import own_public_key_b64, self_runner_identity
    # the runner's own ed25519 key, enrolled as a principal, signing a RECEIPT (different domain)
    kid = self_runner_identity().split(":", 1)[1]
    trusted = {kid: own_public_key_b64()}
    rr = RunReceipt(suite_sha="a", inputs_digest="b", coverage_assertion="team",
                    runner_identity="", result_digest="x", signature="")
    attest_self(rr)   # an ed25519 receipt signature by the runner's key
    # present that receipt signature as a memwrite signature for the matching fields → must reject
    assert verify_write(key_id=kid, subject="a", predicate="b", scope="team", text="x",
                        signature=rr.signature, trusted=trusted) is False


# --- cross-principal `verified` tier via a fact-bound attestation -----------
def _attest(subject, predicate, text, verdict=None, attest="ed25519"):
    from verel.verdict import Verdict, attest_fact
    return attest_fact(verdict or Verdict.PASS, [], subject=subject, predicate=predicate, text=text,
                       attest=attest).model_dump()


def test_fact_attestation_roundtrip_and_binding():
    from verel.verdict import Verdict, fact_commitment, verify_fact_attestation
    att = _attest("retry", "rule", "retry 3x")
    assert verify_fact_attestation(att, "retry", "rule", "retry 3x", allowed_algs={"ed25519"})
    # bound to THIS exact claim — a different claim does not verify (no laundering)
    assert not verify_fact_attestation(att, "retry", "rule", "DIFFERENT", allowed_algs={"ed25519"})
    assert not verify_fact_attestation(att, "other", "rule", "retry 3x", allowed_algs={"ed25519"})
    # FAIL verdict is not a verification; hmac is not publicly verifiable
    assert not verify_fact_attestation(_attest("a", "b", "c", Verdict.FAIL), "a", "b", "c",
                                       allowed_algs={"ed25519"})
    assert not verify_fact_attestation(_attest("a", "b", "c", attest="hmac"), "a", "b", "c",
                                       allowed_algs={"ed25519"})
    # the commitment binds content, not scope
    assert fact_commitment("a", "b", "c") == fact_commitment("a", "b", "c")


def test_authenticated_remember_earns_verified_with_fact_attestation():
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    mem = _mem()
    S, P, X = "deploy", "how", "page oncall"
    sig = alice.sign_write(subject=S, predicate=P, scope="team", text=X)
    # no evidence → candidate
    r0 = authenticated_remember(mem, subject=S, predicate=P, scope="team", text=X, signature=sig,
                                key_id=alice.key_id, trusted=trusted)
    assert r0.reverified is False
    # a fact-bound attestation → verified (trust travels only via a trusted grader's signed PASS)
    r1 = authenticated_remember(mem, subject=S, predicate=P, scope="team", text=X, signature=sig,
                                key_id=alice.key_id, trusted=trusted, evidence=_attest(S, P, X))
    assert r1.reverified is True
    assert mem.get(make_id(make_key(S, P, "team"))).trust == Trust.VERIFIED


def test_unrelated_attestation_does_not_launder_trust():
    alice = Principal.generate()
    trusted = dict([alice.enroll()])
    sig = alice.sign_write(subject="x", predicate="y", scope="team", text="false claim")
    r = authenticated_remember(_mem(), subject="x", predicate="y", scope="team", text="false claim",
                               signature=sig, key_id=alice.key_id, trusted=trusted,
                               evidence=_attest("unrelated", "z", "something else"))
    assert r.reverified is False   # the receipt is valid but not bound to THIS claim → candidate


def test_fact_attestation_over_http(tmp_path):
    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "b.db"),
                       trusted_principals=dict([alice.enroll()])).start()
    try:
        cli = RemoteMemory(srv.url)
        S, P, X = "oncall", "rule", "use pagerduty"
        r = cli.remember_signed(alice, subject=S, predicate=P, scope="team", text=X,
                                evidence=_attest(S, P, X))
        assert r["reverified"] is True
        assert [x.trust.value for x in cli.recall(X, scope="team")] == ["verified"]
    finally:
        srv.stop()


def test_explicit_opt_out_keeps_raw_write_open(tmp_path):
    """An operator can explicitly run single-principal-style even with principals enrolled."""
    alice = Principal.generate()
    srv = MemoryServer(db_path=str(tmp_path / "d.db"), trusted_principals=dict([alice.enroll()]),
                       require_signed_writes=False).start()
    try:
        cli = RemoteMemory(srv.url)
        cli.write(MemoryRecord(kind=MemoryKind.FACT, subject="a", predicate="b", text="ok",
                               scope="team"))   # opt-out: raw write allowed
    finally:
        srv.stop()
