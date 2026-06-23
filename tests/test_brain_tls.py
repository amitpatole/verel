"""Roadmap item 3 — transport confidentiality (TLS) for routable brain binds. A non-loopback
MemoryServer must be BOTH authenticated AND encrypted (fail closed); the client refuses to put a token
on a cleartext hop to a routable host; loopback stays zero-config plain HTTP. See SUBSTRATE_DESIGN §15.4.
"""

import shutil
import subprocess

import pytest

from verel.memory import MemoryKind, MemoryRecord, RemoteMemory
from verel.memory.hosted import MemoryServer, ReplicaClient

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl to mint a cert")


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    """A throwaway self-signed cert/key with SAN IP:127.0.0.1 so a client can verify the loopback TLS
    roundtrip against it as a CA."""
    d = tmp_path_factory.mktemp("tls")
    crt, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(crt), "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    return str(crt), str(key)


# ---- server bind policy (fail closed on a routable host) ----

def test_routable_bind_without_auth_token_refuses(tmp_path):
    with pytest.raises(ValueError, match="auth_token"):
        MemoryServer(db_path=str(tmp_path / "b.db"), host="0.0.0.0")


def test_routable_bind_without_tls_refuses(tmp_path):
    """A token alone isn't enough on a routable host — without TLS it crosses the wire in cleartext."""
    with pytest.raises(ValueError, match="TLS"):
        MemoryServer(db_path=str(tmp_path / "b.db"), host="0.0.0.0", auth_token="t")


def test_routable_bind_with_tls_and_token_is_allowed(tmp_path, cert):
    crt, key = cert
    # Construction must not raise (policy satisfied). Don't actually serve on all interfaces.
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="0.0.0.0", auth_token="t",
                       certfile=crt, keyfile=key)
    assert srv.url.startswith("https://")


def test_loopback_stays_zero_config_plain_http(tmp_path):
    srv = MemoryServer(db_path=str(tmp_path / "b.db")).start()   # default host 127.0.0.1, no token/cert
    try:
        assert srv.url.startswith("http://")
        client = RemoteMemory(srv.url)
        rec = client.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                        text="loopback ok", scope="team"))
        assert rec.text == "loopback ok"
    finally:
        srv.stop()


# ---- TLS roundtrip (server encrypts, client verifies the CA) ----

def test_tls_roundtrip_write_and_read(tmp_path, cert):
    crt, key = cert
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=crt, keyfile=key).start()
    try:
        assert srv.url.startswith("https://")
        client = RemoteMemory(srv.url, cafile=crt)
        client.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                  text="over tls", scope="team"))
        hits = client.recall("over tls", scope="team")
        assert [h.text for h in hits] == ["over tls"]
    finally:
        srv.stop()


def test_tls_client_rejects_untrusted_cert(tmp_path, cert):
    """Without the CA, the self-signed cert must NOT verify — a MITM with a bogus cert is rejected."""
    import urllib.error

    crt, key = cert
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=crt, keyfile=key).start()
    try:
        client = RemoteMemory(srv.url)   # no cafile → system roots → self-signed cert is untrusted
        with pytest.raises(urllib.error.URLError):
            client.recall("x", scope="team")
    finally:
        srv.stop()


# ---- client cleartext-secret guard (never leak a token on a routable cleartext hop) ----

def test_client_refuses_token_on_cleartext_routable_url():
    with pytest.raises(ValueError, match="cleartext"):
        RemoteMemory("http://10.0.0.5:8000", auth_token="secret-token")


def test_client_refuses_cluster_token_on_cleartext_routable_url():
    with pytest.raises(ValueError, match="cleartext"):
        ReplicaClient("http://10.0.0.5:8000", cluster_token="cluster-secret")


def test_client_allows_token_on_loopback_http():
    rm = RemoteMemory("http://127.0.0.1:8000", auth_token="t")   # loopback never leaves the box
    assert rm.token == "t"


def test_client_allows_token_on_https_routable():
    rm = RemoteMemory("https://brain.internal:8443", auth_token="t")   # encrypted hop → fine
    assert rm.token == "t"


def test_client_insecure_optout_allows_cleartext_routable():
    rm = RemoteMemory("http://10.0.0.5:8000", auth_token="t", insecure=True)
    assert rm.token == "t"


def test_client_no_token_on_cleartext_routable_is_fine():
    """No secret to leak → a plain http routable URL is allowed (reads aren't confidential)."""
    rm = RemoteMemory("http://10.0.0.5:8000")
    assert rm.token is None


# ---- red-team round-1 regression: empty host is the WILDCARD bind, not loopback ----

def test_empty_host_is_not_loopback():
    """host='' binds 0.0.0.0 (all interfaces) — it must be treated as routable, not loopback, or an
    `MemoryServer(host='')` would be an anonymous cleartext service on every interface (red-team R1)."""
    from verel.transport import enforce_bind_policy, is_loopback

    assert is_loopback("") is False
    with pytest.raises(ValueError, match="auth_token"):
        enforce_bind_policy("", auth_token=None, tls=False, service="x")


def test_empty_host_server_refuses_anonymous_bind(tmp_path):
    with pytest.raises(ValueError, match="auth_token"):
        MemoryServer(db_path=str(tmp_path / "b.db"), host="")


# ---- red-team round-2 regression: a 3xx redirect must not ferry the token onto a cleartext/cross hop ----

def test_redirect_refuses_downgrade_to_cleartext_routable():
    """urllib re-sends Authorization across a 3xx by default — an https→http(routable) downgrade would
    leak the token past the init guard. The secure redirect handler must refuse it."""
    import urllib.request

    from verel.transport import _SecureRedirectHandler

    h = _SecureRedirectHandler()
    req = urllib.request.Request("https://brain.internal/x", headers={"Authorization": "Bearer s3cr3t"})
    with pytest.raises(ValueError, match="cleartext"):
        h.redirect_request(req, None, 302, "Found", {}, "http://10.0.0.5/sink")


def test_redirect_strips_secret_cross_origin():
    """Even an https→https redirect to a DIFFERENT origin must not carry the secret (it was minted for
    the original server only)."""
    import urllib.request

    from verel.transport import _SecureRedirectHandler

    h = _SecureRedirectHandler()
    req = urllib.request.Request("https://a.internal/x",
                                 headers={"Authorization": "Bearer s", "X-Cluster-Token": "c"})
    new = h.redirect_request(req, None, 302, "Found", {}, "https://b.internal/y")
    assert "Authorization" not in new.headers and "X-cluster-token" not in new.headers


def test_redirect_keeps_secret_same_origin():
    """A same-origin redirect (e.g. a path change) legitimately keeps the token."""
    import urllib.request

    from verel.transport import _SecureRedirectHandler

    h = _SecureRedirectHandler()
    req = urllib.request.Request("https://a.internal/x", headers={"Authorization": "Bearer s"})
    new = h.redirect_request(req, None, 302, "Found", {}, "https://a.internal/y")
    assert new.headers.get("Authorization") == "Bearer s"


def test_token_set_after_init_is_still_guarded_per_request():
    """The init-time guard can't see a token set later — `send()` must re-check on the live token so a
    post-construction `client.token = ...` can't ride a cleartext routable hop (red-team R2, finding 2)."""
    rm = RemoteMemory("http://10.0.0.5:8000")   # no token at construction → allowed
    rm.token = "sneaky"
    with pytest.raises(ValueError, match="cleartext"):
        rm.recall("x", scope="team")
