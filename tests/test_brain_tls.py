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


@pytest.fixture(scope="module")
def client_id(tmp_path_factory):
    """A client cert+key for mTLS — self-signed, used as both the presented client cert and (as its own
    CA) the server's `client_ca` trust anchor."""
    d = tmp_path_factory.mktemp("mtls")
    crt, key = d / "client.pem", d / "client.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(crt), "-subj", "/CN=verel-client"],
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


def test_redirect_keeps_secret_across_default_port_normalization():
    """https://h and https://h:443 are the SAME origin — a redirect that only adds/drops the default
    port must NOT strip the token (round-2 over-strip nit)."""
    import urllib.request

    from verel.transport import _SecureRedirectHandler

    h = _SecureRedirectHandler()
    req = urllib.request.Request("https://a.internal/x", headers={"Authorization": "Bearer s"})
    new = h.redirect_request(req, None, 302, "Found", {}, "https://a.internal:443/y")
    assert new.headers.get("Authorization") == "Bearer s"


# ---- red-team round-2 regression: TLS handshake must not starve the accept loop (unauth DoS) ----

def test_tls_handshake_does_not_starve_accept_loop(tmp_path, cert):
    """A raw TCP connection that never sends a ClientHello must not block the single-threaded accept
    loop — the handshake happens in the worker thread, so a concurrent legit request still completes
    (red-team R2b, HIGH). Pre-fix this hung until timeout."""
    import socket
    import time

    crt, key = cert
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=crt, keyfile=key).start()
    try:
        host, port = srv._httpd.server_address[:2]
        stalled = socket.create_connection((host, port))   # connects, sends nothing
        try:
            t0 = time.time()
            client = RemoteMemory(srv.url, cafile=crt, timeout=8)
            client.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                      text="alive", scope="team"))
            assert [h.text for h in client.recall("alive", scope="team")] == ["alive"]
            assert time.time() - t0 < 5   # not starved by the stalled handshake
        finally:
            stalled.close()
    finally:
        srv.stop()


def test_connection_cap_drops_over_cap_connections(tmp_path):
    """A flood of stalled connections must not park unbounded worker threads — over `max_connections`
    in-flight, the server drops (closes) the connection instead of spawning another thread (red-team
    R3a, MEDIUM)."""
    import socket
    import time

    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1", max_connections=3).start()
    try:
        host, port = srv._httpd.server_address[:2]
        stalled = [socket.create_connection((host, port)) for _ in range(3)]   # fill all slots
        try:
            time.sleep(0.3)
            assert srv._httpd._slots._value == 0            # cap reached, not negative
            over = socket.create_connection((host, port))   # over the cap → dropped
            over.settimeout(3)
            try:
                t0 = time.time()
                assert over.recv(16) == b""                 # server closed it
                assert time.time() - t0 < 2                 # promptly, not parked
            finally:
                over.close()
        finally:
            for s in stalled:
                s.close()
    finally:
        srv.stop()


def test_connection_slot_released_after_request(tmp_path):
    """Slots are released when a handler finishes, so a small cap doesn't permanently throttle — many
    sequential requests succeed through a cap of 2."""
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1", max_connections=2).start()
    try:
        client = RemoteMemory(srv.url)
        # 6 sequential round-trips through a cap of 2 only complete if each handler RELEASES its slot;
        # a leaked slot would exhaust the cap and hang by the 3rd request.
        ids = [client.write(MemoryRecord(kind=MemoryKind.FACT, subject=f"s{i}", predicate="p",
                                         text=f"rec{i}", scope="team")).id for i in range(6)]
        assert len(ids) == 6 and all(ids)
    finally:
        srv.stop()


def test_max_connections_must_be_positive(tmp_path):
    """A non-positive cap would silently drop every connection (a hang) — reject it with a clear error."""
    with pytest.raises(ValueError, match="max_connections"):
        MemoryServer(db_path=str(tmp_path / "b.db"), max_connections=0)


def test_verify_request_false_does_not_over_release_slots():
    """Slot release is paired in the worker thread, not shutdown_request — so the verify_request()==False
    path (shutdown_request without a prior acquire) can't over-release the BoundedSemaphore (red-team R4a,
    latent). Pins the accounting against a future verify_request override."""
    import socket
    import threading
    import time
    from http.server import BaseHTTPRequestHandler

    from verel.transport import TLSThreadingHTTPServer

    class RejectAll(TLSThreadingHTTPServer):
        def verify_request(self, request, client_address):
            return False   # socketserver calls shutdown_request WITHOUT process_request

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()

    srv = RejectAll(("127.0.0.1", 0), H, max_connections=4)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        host, port = srv.server_address[:2]
        for _ in range(6):
            try:
                s = socket.create_connection((host, port))
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                s.recv(16)
                s.close()
            except OSError:
                pass
        time.sleep(0.3)
        assert srv._slots._value == 4   # balanced — no over-release despite rejected requests
    finally:
        srv.shutdown()


def test_client_opener_ignores_ambient_proxy(tmp_path, monkeypatch):
    """The client must NOT honor HTTP_PROXY/ALL_PROXY — doing so would ship Authorization to the proxy
    in cleartext even for a loopback http target (red-team R2a, MEDIUM). A dead proxy in env must not
    break a direct loopback request."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    srv = MemoryServer(db_path=str(tmp_path / "b.db")).start()
    try:
        client = RemoteMemory(srv.url)   # loopback http, no token
        client.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                                  text="direct", scope="team"))
        assert [h.text for h in client.recall("direct", scope="team")] == ["direct"]
    finally:
        srv.stop()


# ---- mTLS: the server authenticates the client at the transport layer (item 3 residual) ----

def test_mtls_requires_a_client_cert(cert, client_id, tmp_path):
    """With client_ca set, a client must present a cert signed by it — a client without one is rejected
    (under TLS 1.3 the server enforces this just after the handshake, surfacing as an SSL error); the
    enrolled client gets through."""
    import ssl
    import urllib.error

    server_crt, server_key = cert
    client_crt, client_key = client_id
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=server_crt, keyfile=server_key, client_ca=client_crt).start()
    try:
        nocert = RemoteMemory(srv.url, cafile=server_crt)        # no client cert presented
        with pytest.raises((urllib.error.URLError, ssl.SSLError)):
            nocert.recall("x", scope="team")
        ok = RemoteMemory(srv.url, cafile=server_crt, client_cert=client_crt, client_key=client_key)
        ok.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="mtls",
                              scope="team"))
        assert [h.text for h in ok.recall("mtls", scope="team")] == ["mtls"]
    finally:
        srv.stop()


def test_mtls_client_ca_without_server_cert_refused(tmp_path, client_id):
    """mTLS is meaningless without the server also presenting a cert — fail closed at construction."""
    with pytest.raises(ValueError, match="mTLS"):
        MemoryServer(db_path=str(tmp_path / "b.db"), client_ca=client_id[0])


# ---- certificate pinning (item 3 residual: pinning now first-class) ----

def test_pinning_accepts_the_pinned_cert(cert, tmp_path):
    from verel.transport import cert_sha256

    server_crt, server_key = cert
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=server_crt, keyfile=server_key).start()
    try:
        c = RemoteMemory(srv.url, cafile=server_crt, pin_sha256=cert_sha256(server_crt))
        c.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="pinned",
                             scope="team"))
        assert [h.text for h in c.recall("pinned", scope="team")] == ["pinned"]
    finally:
        srv.stop()


def test_pinning_rejects_an_unpinned_cert(cert, tmp_path):
    """A cert outside the pinned set is rejected even though the CA (cafile) trusts it."""
    import urllib.error

    server_crt, server_key = cert
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       certfile=server_crt, keyfile=server_key).start()
    try:
        c = RemoteMemory(srv.url, cafile=server_crt, pin_sha256="00" * 32)   # bogus pin
        with pytest.raises(urllib.error.URLError):
            c.recall("x", scope="team")
    finally:
        srv.stop()


def test_cert_sha256_matches_openssl(cert):
    import subprocess

    from verel.transport import cert_sha256

    crt, _ = cert
    out = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True).stdout
    expected = out.split("=", 1)[1].strip().replace(":", "").lower()
    assert cert_sha256(crt) == expected


# ---- per-source-IP fairness (item 3 residual: one source can't monopolize the global cap) ----

def test_per_ip_cap_drops_over_one_sources_share(tmp_path):
    import socket
    import time

    srv = MemoryServer(db_path=str(tmp_path / "b.db"), host="127.0.0.1",
                       max_connections=10, max_per_ip=2).start()
    try:
        host, port = srv._httpd.server_address[:2]
        held = [socket.create_connection((host, port)) for _ in range(2)]   # fill 127.0.0.1's share
        try:
            time.sleep(0.3)
            over = socket.create_connection((host, port))   # same IP, over its per-IP share
            over.settimeout(3)
            try:
                assert over.recv(16) == b""        # dropped though the global cap (10) isn't full
            finally:
                over.close()
        finally:
            for s in held:
                s.close()
    finally:
        srv.stop()


def test_max_per_ip_must_be_positive(tmp_path):
    with pytest.raises(ValueError, match="max_per_ip"):
        MemoryServer(db_path=str(tmp_path / "b.db"), max_per_ip=0)
