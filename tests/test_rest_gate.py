"""R1 — REST gate server + GitHub webhook adapter. Pure helpers + a live loopback server."""

import hashlib
import hmac
import json
import urllib.error
import urllib.request

import pytest

from verel.integrations.rest import (
    GateServer,
    parse_pr_event,
    post_commit_status,
    verify_github_signature,
)


# ---- webhook signature (constant-time HMAC) ----
def _sign(secret, body):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_signature_valid():
    body = b'{"action":"opened"}'
    assert verify_github_signature("s3cret", body, _sign("s3cret", body))


def test_signature_rejects_wrong_secret_tamper_and_missing():
    body = b'{"action":"opened"}'
    assert not verify_github_signature("s3cret", body, _sign("WRONG", body))
    assert not verify_github_signature("s3cret", body + b"x", _sign("s3cret", body))  # tampered body
    assert not verify_github_signature("s3cret", body, None)                          # missing header
    assert not verify_github_signature("s3cret", body, "md5=deadbeef")                # wrong algo
    assert not verify_github_signature("", body, _sign("", body))                     # no secret → closed


# ---- payload parsing (no fetching) ----
def test_parse_pr_event():
    payload = {"action": "synchronize", "number": 7,
               "repository": {"full_name": "o/r"},
               "pull_request": {"head": {"sha": "abc1234"}}}  # ≥7 hex (GitHub abbrev minimum)
    ev = parse_pr_event(payload)
    assert ev == {"action": "synchronize", "repo": "o/r", "number": 7, "sha": "abc1234"}


def test_parse_non_pr_event_is_none():
    assert parse_pr_event({"action": "created", "issue": {}}) is None


def test_post_commit_status_rejects_bad_state():
    with pytest.raises(ValueError, match="invalid status state"):
        post_commit_status("o/r", "sha", state="merged", token="t")


# ---- live server ----
@pytest.fixture
def repo(tmp_path):
    (tmp_path / "m.py").write_text("def ok():\n    return 1\n")
    (tmp_path / "test_m.py").write_text("from m import ok\n\ndef test_ok():\n    assert ok() == 1\n")
    return tmp_path


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read())


def _post(url, body=b"", headers=None):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_health_and_gate_loopback_zeroconf(repo):
    srv = GateServer(str(repo), lint=False).start()
    try:
        assert _get(srv.url + "/health") == (200, {"status": "ok"})
        code, body = _post(srv.url + "/gate")
        assert code == 200 and body["verdict"] == "pass"
    finally:
        srv.stop()


def test_gate_requires_token_when_set(repo):
    srv = GateServer(str(repo), auth_token="t0ken", lint=False).start()
    try:
        assert _post(srv.url + "/gate")[0] == 401                                   # no auth
        assert _post(srv.url + "/gate")[0] == 401
        code, body = _post(srv.url + "/gate", headers={"Authorization": "Bearer t0ken"})
        assert code == 200 and body["verdict"] == "pass"
    finally:
        srv.stop()


def test_github_webhook_requires_valid_signature(repo):
    secret = "whsec"
    srv = GateServer(str(repo), webhook_secret=secret, lint=False).start()
    try:
        payload = json.dumps({"action": "opened", "number": 1,
                              "repository": {"full_name": "o/r"},
                              "pull_request": {"head": {"sha": "deadbeef"}}}).encode()
        # forged / missing signature → 401, no gate runs
        assert _post(srv.url + "/github", payload, {"X-Hub-Signature-256": "sha256=00"})[0] == 401
        assert _post(srv.url + "/github", payload)[0] == 401
        # valid signature → gate runs, verdict returned with the parsed event
        code, body = _post(srv.url + "/github", payload,
                           {"X-Hub-Signature-256": _sign(secret, payload)})
        assert code == 200 and body["gate"]["verdict"] == "pass" and body["event"]["sha"] == "deadbeef"
    finally:
        srv.stop()


def test_routable_bind_without_tls_and_token_fails_closed(repo):
    # A routable bind must refuse to start without BOTH auth and TLS (transport bind policy).
    with pytest.raises(Exception):  # noqa: B017 - enforce_bind_policy raises (ValueError/RuntimeError)
        GateServer(str(repo), host="0.0.0.0")


def test_empty_token_fails_closed_on_routable_bind(repo):
    # Regression: a blank VEREL_GATE_TOKEN must NOT bind a routable surface (empty secret = no auth).
    with pytest.raises(Exception):  # noqa: B017 - enforce_bind_policy raises
        GateServer(str(repo), host="0.0.0.0", auth_token="", certfile=None, keyfile=None)


def test_empty_token_does_not_authenticate_empty_bearer(repo):
    # Regression: an empty token must be treated as "no auth" (open loopback), NOT as a credential
    # that accepts `Authorization: Bearer ` — never a matchable empty secret.
    srv = GateServer(str(repo), auth_token="   ", lint=False).start()  # whitespace → None
    try:
        # token normalized to None → loopback is open, and an empty bearer is NOT a special match
        code, body = _post(srv.url + "/gate", headers={"Authorization": "Bearer "})
        assert code == 200  # open because token is None (not because "Bearer " matched a "" secret)
        assert _post(srv.url + "/gate")[0] == 200  # also open with no header
    finally:
        srv.stop()


def test_non_ascii_auth_header_denies_cleanly_not_500(repo):
    srv = GateServer(str(repo), auth_token="t0ken", lint=False).start()
    try:
        # a non-ASCII bearer must yield 401 (clean deny), not a 500 from compare_digest raising
        assert _post(srv.url + "/gate", headers={"Authorization": "Bearer ÿ"})[0] == 401
    finally:
        srv.stop()


def test_non_ascii_signature_header_is_false_not_raise():
    assert verify_github_signature("s", b"{}", "sha256=ÿ" * 8) is False  # no TypeError


def test_parse_non_object_payload_is_none():
    # A valid-JSON-but-not-object body must skip cleanly (no AttributeError → 500).
    assert parse_pr_event([]) is None and parse_pr_event("x") is None and parse_pr_event(5) is None


def test_parse_rejects_hostile_repo_and_sha():
    base = {"pull_request": {"head": {"sha": "deadbeef"}}, "repository": {"full_name": "o/r"}}
    assert parse_pr_event(base) is not None
    bad_repo = {**base, "repository": {"full_name": "o/r\r\nX-Injected: 1"}}
    bad_sha = {"pull_request": {"head": {"sha": "deadbeef\r\nFoo: bar"}}, "repository": {"full_name": "o/r"}}
    assert parse_pr_event(bad_repo) is None and parse_pr_event(bad_sha) is None


def test_post_commit_status_rejects_hostile_repo_sha():
    with pytest.raises(ValueError, match="invalid repo/sha"):
        post_commit_status("o/r\r\nx: 1", "deadbeef", state="success", token="t")


def _raw_request(srv, raw: bytes) -> str:
    import socket
    from urllib.parse import urlparse
    u = urlparse(srv.url)
    s = socket.create_connection((u.hostname, u.port), timeout=10)
    s.sendall(raw)
    out = s.recv(8192).decode(errors="replace")
    s.close()
    return out


def test_transfer_encoding_is_rejected_and_connection_closed(repo):
    srv = GateServer(str(repo), webhook_secret="x", lint=False).start()
    try:
        resp = _raw_request(srv, b"POST /github HTTP/1.1\r\nHost: x\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        assert "400" in resp.split("\r\n", 1)[0]
        assert "close" in resp.lower()  # connection torn down → no smuggling/desync
    finally:
        srv.stop()


def test_duplicate_content_length_is_rejected(repo):
    srv = GateServer(str(repo), webhook_secret="x", lint=False).start()
    try:
        resp = _raw_request(srv, b"POST /github HTTP/1.1\r\nHost: x\r\n"
                                 b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}")
        assert "400" in resp.split("\r\n", 1)[0]
    finally:
        srv.stop()


def test_error_response_closes_connection_no_pipelining(repo):
    # After a 400, the connection must be closed so a pipelined request isn't served on the same socket.
    import socket
    from urllib.parse import urlparse
    srv = GateServer(str(repo), lint=False).start()
    try:
        u = urlparse(srv.url)
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        # a 400 (Transfer-Encoding) immediately followed by a pipelined /gate on the SAME socket
        s.sendall(b"POST /gate HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                  b"POST /gate HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        data = s.recv(65536).decode(errors="replace")
        s.close()
        assert data.count("HTTP/1.1") == 1  # only the 400 answered; the smuggled request was not served
    finally:
        srv.stop()


def test_get_also_rejects_smuggled_framing(repo):
    # Regression (round 3): the framing check must apply to GET too — a smuggled body on GET /health
    # must not desync the connection and run a pipelined request.
    import socket
    from urllib.parse import urlparse
    srv = GateServer(str(repo), lint=False).start()
    try:
        u = urlparse(srv.url)
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\n"
                  b"POST /gate HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        data = s.recv(65536).decode(errors="replace")
        s.close()
        assert data.count("HTTP/1.1") == 1 and "400" in data.split("\r\n", 1)[0]  # no smuggled 2nd resp
    finally:
        srv.stop()


def test_get_with_single_content_length_body_is_rejected(repo):
    # Regression (round 4): a GET with ONE valid Content-Length body (the CL.0 desync class) must be
    # refused + the connection closed, so the body can't be re-parsed as a pipelined second request.
    import socket
    from urllib.parse import urlparse
    srv = GateServer(str(repo), lint=False).start()
    try:
        u = urlparse(srv.url)
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: 31\r\n\r\n"
                  b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        data = s.recv(65536).decode(errors="replace")
        s.close()
        assert data.count("HTTP/1.1") == 1 and "400" in data.split("\r\n", 1)[0]
        assert "close" in data.lower()
    finally:
        srv.stop()


def test_no_connection_reuse_kills_smuggling_structurally(repo):
    # The load-bearing guarantee: every response closes the connection, so NO pipelined second
    # request is ever served on the same socket — regardless of header-parser quirks. Covers the
    # round-5 whitespace-before-colon Transfer-Encoding truncation (which bypasses _check_framing).
    import socket
    from urllib.parse import urlparse
    srv = GateServer(str(repo), lint=False).start()
    try:
        u = urlparse(srv.url)
        # (a) round-5 variant: "Transfer-Encoding :" truncates headers → framing check can't see it,
        # but force-close discards the unconsumed body so the smuggled GET is never served.
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        s.sendall(b"POST /gate HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\nContent-Length: 35"
                  b"\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: x\r\n\r\n")
        out_a = s.recv(65536).decode(errors="replace")
        s.close()
        assert out_a.count("HTTP/1.1") == 1 and "SMUGGLED" not in out_a
        assert "close" in out_a.lower()
        # (b) a clean 200 followed by a pipelined request → still only one response (no reuse)
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        out_b = s.recv(65536).decode(errors="replace")
        s.close()
        assert out_b.count("HTTP/1.1") == 1  # the second pipelined request is not served
    finally:
        srv.stop()


def test_gate_concurrency_is_bounded(repo):
    # With max_concurrent_gates=1 and a slow gate, a second concurrent request must get 503, not pile up.
    import threading
    import time
    started = threading.Event()
    srv = GateServer(str(repo), lint=False, max_concurrent_gates=1)

    def slow():
        started.set()
        time.sleep(1.0)
        return {"verdict": "pass", "issues": []}
    srv._run_gate = slow  # replace the gate with a slow stub to hold the single slot
    srv.start()
    try:
        codes = {}
        def hit(i):
            codes[i] = _post(srv.url + "/gate")[0]
        t1 = threading.Thread(target=hit, args=(1,))
        t1.start()
        started.wait(2)
        time.sleep(0.1)
        hit(2)  # second request while the first holds the only slot → 503
        t1.join(5)
        assert codes[1] == 200 and codes[2] == 503
    finally:
        srv.stop()


def test_oversize_body_is_rejected(repo):
    # The cap is enforced on the Content-Length HEADER before any body is read (DoS guard), so a raw
    # request claiming a huge length is rejected 400 without the server allocating/reading it.
    import socket
    from urllib.parse import urlparse
    srv = GateServer(str(repo), webhook_secret="x", lint=False).start()
    try:
        u = urlparse(srv.url)
        s = socket.create_connection((u.hostname, u.port), timeout=10)
        s.sendall(b"POST /github HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n"
                  b"X-Hub-Signature-256: sha256=00\r\n\r\ntiny")
        resp = s.recv(4096).decode(errors="replace")
        s.close()
        assert "400" in resp.split("\r\n", 1)[0]  # rejected on the declared length, body never read
    finally:
        srv.stop()
