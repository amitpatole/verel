"""verel.auth + the generic chain log: roles, hashed tokens, OIDC attacks, audit tamper-evidence."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import time

import pytest

from verel._chainlog import ChainLog, ChainRecord, LogCorrupt
from verel.auth import (
    AuditLog,
    Authenticator,
    OIDCConfig,
    OIDCVerifier,
    Principal,
    Role,
    TokenStore,
    add_token,
    list_tokens,
    parse_role,
    revoke_token,
    valid_tenant,
)
from verel.auth.rbac import PERMISSIONS
from verel.auth.tokens import hash_token


# ------------------------------------------------------------------ rbac
def test_role_permissions_are_monotonic_and_fixed():
    v, o, a = (PERMISSIONS[r] for r in (Role.VIEWER, Role.OPERATOR, Role.ADMIN))
    assert v < o < a
    assert "pilot:promote" not in o and "pilot:record" not in v


@pytest.mark.parametrize("bad", ["", "Admin ", "root", None, 5])
def test_unknown_roles_raise(bad):
    if bad == "Admin ":
        assert parse_role(bad) is Role.ADMIN   # normalised, not a loophole
        return
    with pytest.raises(ValueError):
        parse_role(bad)


@pytest.mark.parametrize("bad", ["", "../x", "A", "a/b", "a b", "-a", "x" * 64, None, 3, "a\n"])
def test_tenant_validation(bad):
    with pytest.raises(ValueError):
        valid_tenant(bad)


# ------------------------------------------------------------------ tokens
def _store(tmp_path):
    p = tmp_path / "tokens.json"
    t_op = add_token(p, id="alice", role="operator", tenant="acme")
    t_ad = add_token(p, id="root", role="admin", tenant="acme")
    t_other = add_token(p, id="bob", role="viewer", tenant="globex")
    return p, t_op, t_ad, t_other


def test_token_roundtrip_and_storage_is_hash_only(tmp_path):
    p, t_op, _, _ = _store(tmp_path)
    assert t_op not in p.read_text()               # secret is never stored
    assert hash_token(t_op) in p.read_text()
    s = TokenStore(p)
    pr = s.authenticate(t_op)
    assert pr == Principal("alice", Role.OPERATOR, "acme", "token")
    assert (p.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("bad", ["", "vrl_", "vrl_" + "a" * 500, "nope", "Bearer x", None])
def test_bad_tokens_denied(tmp_path, bad):
    p, *_ = _store(tmp_path)
    assert TokenStore(p).authenticate(bad) is None


def test_expiry_and_revocation_hot_reload(tmp_path):
    p = tmp_path / "t.json"
    tok = add_token(p, id="u", role="viewer", tenant="acme", expires="2026-01-01")
    s = TokenStore(p)
    assert s.authenticate(tok, today=dt.date(2025, 12, 31)) is not None
    assert s.authenticate(tok, today=dt.date(2026, 1, 2)) is None
    tok2 = add_token(p, id="v", role="viewer", tenant="acme")
    assert s.authenticate(tok2) is not None
    assert revoke_token(p, "v") is True
    time.sleep(0.01)
    assert s.authenticate(tok2) is None            # takes effect on the very next request
    assert revoke_token(p, "v") is False


def test_corrupt_or_loose_token_file_denies_everyone(tmp_path):
    p, t_op, *_ = _store(tmp_path)
    s = TokenStore(p)
    assert s.authenticate(t_op) is not None
    p.write_text("{ not json")
    assert s.authenticate(t_op) is None            # fail closed, no stale grants
    p2 = tmp_path / "loose.json"
    p2.write_text(json.dumps({"version": 1, "tokens": []}))
    os.chmod(p2, 0o666)
    with pytest.raises(ValueError):
        TokenStore(p2)


@pytest.mark.parametrize("entry", [
    {"id": "a", "role": "god", "tenant": "t", "sha256": "0" * 64},
    {"id": "a", "role": "viewer", "tenant": "../t", "sha256": "0" * 64},
    {"id": "a", "role": "viewer", "tenant": "t", "sha256": "xyz"},
    {"id": "", "role": "viewer", "tenant": "t", "sha256": "0" * 64},
    {"id": "a", "role": "viewer", "tenant": "t", "sha256": "0" * 64, "expires": "soon"},
])
def test_bad_entries_rejected(tmp_path, entry):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"version": 1, "tokens": [entry]}))
    with pytest.raises(ValueError):
        TokenStore(p)


def test_duplicate_id_rejected(tmp_path):
    p = tmp_path / "t.json"
    add_token(p, id="a", role="viewer", tenant="t")
    with pytest.raises(ValueError):
        add_token(p, id="a", role="admin", tenant="t")
    assert len(list_tokens(p)) == 1 and "sha256" not in list_tokens(p)[0]


def test_authenticator_header_parsing(tmp_path):
    p, t_op, *_ = _store(tmp_path)
    a = Authenticator(TokenStore(p))
    assert a.authenticate(f"Bearer {t_op}").id == "alice"
    for h in (None, "", t_op, f"bearer {t_op}", f"Basic {t_op}", "Bearer "):
        assert a.authenticate(h) is None
    with pytest.raises(ValueError):
        Authenticator()


# ------------------------------------------------------------------ OIDC
@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm
    d = tmp_path_factory.mktemp("oidc")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    f = d / "jwks.json"
    f.write_text(json.dumps({"keys": [jwk]}))
    return priv, other, f


def _jwt(priv, **over):
    import jwt
    claims = {"iss": "https://idp.example", "aud": "verel", "sub": "u1", "exp": int(time.time()) + 300,
              "verel_role": "operator", "verel_tenant": "acme", **over.pop("claims", {})}
    for k in over.pop("drop", []):
        claims.pop(k, None)
    return jwt.encode(claims, priv, algorithm=over.pop("alg", "RS256"), headers={"kid": over.pop("kid", "k1")})


@pytest.fixture
def v(keys):
    return OIDCVerifier(OIDCConfig(issuer="https://idp.example", audience="verel", jwks_file=str(keys[2])))


def test_oidc_happy_path(v, keys):
    p = v.authenticate(_jwt(keys[0]))
    assert p == Principal("oidc:u1", Role.OPERATOR, "acme", "oidc")


def test_oidc_rejects(v, keys):
    priv, other, _ = keys
    bad = [
        _jwt(other),                                          # signed by an unknown key
        _jwt(priv, kid="nope"),                               # unknown kid, no fallback to "the only key"
        _jwt(priv, claims={"aud": "someone-else"}),
        _jwt(priv, claims={"iss": "https://evil.example"}),
        _jwt(priv, claims={"exp": int(time.time()) - 3600}),
        _jwt(priv, drop=["exp"]),
        _jwt(priv, drop=["sub"]),
        _jwt(priv, drop=["verel_role"]),
        _jwt(priv, claims={"verel_role": "superuser"}),       # unknown role denies, never defaults
        _jwt(priv, claims={"verel_tenant": "../etc"}),
        _jwt(priv, drop=["verel_tenant"]),
    ]
    for t in bad:
        assert v.authenticate(t) is None, t[:40]


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_oidc_alg_none_and_hs_confusion(v, keys):
    import hashlib
    import hmac
    priv, _, jwks = keys
    claims = {"iss": "https://idp.example", "aud": "verel", "sub": "u1", "exp": int(time.time()) + 300,
              "verel_role": "admin", "verel_tenant": "acme"}
    none_tok = _b64({"alg": "none", "kid": "k1", "typ": "JWT"}) + "." + _b64(claims) + "."
    assert v.authenticate(none_tok) is None
    # classic key confusion: HS256 signed with the PUBLIC key bytes as the HMAC secret
    pub = json.loads(jwks.read_text())["keys"][0]["n"].encode()
    head = _b64({"alg": "HS256", "kid": "k1", "typ": "JWT"}) + "." + _b64(claims)
    sig = base64.urlsafe_b64encode(hmac.new(pub, head.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert v.authenticate(head + "." + sig) is None


def test_oidc_garbage_and_oversize(v):
    for t in ("", "a.b", "a.b.c", "x" * 20000, None, 5, "....", "a.b.c.d"):
        assert v.authenticate(t) is None


def test_oidc_tampered_payload(v, keys):
    h, p, s = _jwt(keys[0]).split(".")
    forged = json.loads(base64.urlsafe_b64decode(p + "=="))
    forged["verel_role"] = "admin"
    assert v.authenticate(f"{h}.{_b64(forged)}.{s}") is None


@pytest.mark.parametrize("kw", [
    {"algorithms": ("HS256",)}, {"algorithms": ("none",)}, {"algorithms": ()},
    {"jwks_file": None, "jwks_url": None}, {"jwks_url": "http://idp/jwks"}, {"leeway_s": 9999},
])
def test_oidc_config_validation(keys, kw):
    base = {"issuer": "i", "audience": "a", "jwks_file": str(keys[2])}
    base.update(kw)
    with pytest.raises(ValueError):
        OIDCConfig(**base)


def test_authenticator_falls_back_to_oidc(tmp_path, v, keys):
    p, t_op, *_ = _store(tmp_path)
    a = Authenticator(TokenStore(p), v)
    assert a.authenticate(f"Bearer {t_op}").source == "token"
    assert a.authenticate(f"Bearer {_jwt(keys[0])}").source == "oidc"
    assert a.authenticate("Bearer vrl_" + "z" * 43) is None


# ------------------------------------------------------------------ chain log / audit
class Rec(ChainRecord):
    n: int


def _log(tmp_path, n=5):
    lg = ChainLog(tmp_path / "c.jsonl", Rec)
    for i in range(n):
        lg.append(Rec(n=i))
    return lg


def test_chainlog_basics(tmp_path):
    lg = _log(tmp_path)
    assert lg.verify() == 5 and lg.head() == lg.records()[-1].hash
    assert (tmp_path / "c.jsonl").stat().st_mode & 0o077 == 0


def test_chainlog_tamper(tmp_path):
    lg = _log(tmp_path)
    lines = lg.path.read_text().splitlines()
    lg.path.write_text("\n".join(lines).replace('"n":2', '"n":9') + "\n")
    with pytest.raises(LogCorrupt):
        lg.verify()
    lg.path.write_text("\n".join([lines[0], lines[2], lines[3], lines[4]]) + "\n")
    with pytest.raises(LogCorrupt):
        lg.verify()


def test_archive_keeps_live_chain_verifiable(tmp_path):
    lg = _log(tmp_path, 6)
    head_before = lg.head()
    moved = lg.archive_first(4, tmp_path / "seg1.archive")
    assert moved == 4 and lg.verify() == 2 and lg.head() == head_before and lg.archived_count() == 4
    lg.append(Rec(n=99))
    assert lg.verify() == 3
    seg = ChainLog(tmp_path / "seg1.archive", Rec)
    assert seg.verify(segment=True) == 4                               # the segment is itself a verifiable chain
    lg.archive_first(2, tmp_path / "seg2.archive")         # a second archive chains off the first anchor
    assert lg.archived_count() == 6 and ChainLog(tmp_path / "seg2.archive", Rec).verify(segment=True) == 2
    with pytest.raises(ValueError):
        lg.archive_first(1, tmp_path / "seg2.archive")     # never overwrites an existing segment
    # editing a live record after archiving is still detected
    txt = lg.path.read_text().replace('"n":99', '"n":98')
    lg.path.write_text(txt)
    with pytest.raises(LogCorrupt):
        lg.verify()


def test_archive_nothing_and_everything(tmp_path):
    lg = _log(tmp_path, 3)
    assert lg.archive_first(0, tmp_path / "a") == 0
    assert lg.archive_first(99, tmp_path / "all.archive") == 3
    assert lg.verify() == 0
    lg.append(Rec(n=1))
    assert lg.verify() == 1


def _proc(args):
    path, k = args
    lg = ChainLog(path, Rec)
    for j in range(20):
        lg.append(Rec(n=k * 100 + j))


def test_chainlog_concurrent_processes(tmp_path):
    import multiprocessing as mp
    path = str(tmp_path / "p.jsonl")
    with mp.get_context("fork").Pool(6) as pool:
        pool.map(_proc, [(path, k) for k in range(6)])
    assert ChainLog(path, Rec).verify() == 120


def test_audit_log_never_stores_secrets(tmp_path):
    a = AuditLog(tmp_path / "audit.jsonl")
    a.log(Principal("alice", Role.OPERATOR, "acme"), "POST /x", True, "ok")
    a.log(None, "POST /x", False, "unauthenticated")
    recs = a.records()
    assert [r.principal for r in recs] == ["alice", "anonymous"] and a.verify() == 2
    assert "Bearer" not in (tmp_path / "audit.jsonl").read_text()
