"""The shipped metrics dashboard (`verel.dashboard`) reuses the verel.transport hardening: loopback is
zero-config; a routable bind must be authenticated AND encrypted (fail closed); access is a
constant-time bearer/`?token=` check. Data collection is monkeypatched out (no network in tests).
"""

import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from verel import dashboard
from verel.dashboard import _make_handler, main
from verel.transport import TLSThreadingHTTPServer


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # never hit gh/pypi in tests; render trivially
    monkeypatch.setattr(dashboard, "cached", lambda: {"ok": True})
    monkeypatch.setattr(dashboard, "render", lambda d: "<html>ok</html>")


@contextmanager
def _serve(token):
    srv = TLSThreadingHTTPServer(("127.0.0.1", 0), _make_handler(token))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=5)


# ---- bind policy (reused from verel.transport) ----

def test_routable_bind_without_auth_and_tls_refuses(monkeypatch):
    monkeypatch.setenv("VEREL_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.delenv("VEREL_DASHBOARD_TOKEN", raising=False)
    assert main() == 2   # fail closed, never serves


def test_routable_bind_with_token_but_no_tls_refuses(monkeypatch):
    monkeypatch.setenv("VEREL_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("VEREL_DASHBOARD_TOKEN", "t")
    monkeypatch.delenv("VEREL_DASHBOARD_CERT", raising=False)
    assert main() == 2   # token alone isn't enough on a routable host — TLS required


# ---- auth on the handler ----

def test_loopback_no_token_is_open():
    with _serve(None) as base:
        assert _get(base + "/").status == 200
        assert _get(base + "/api/metrics").status == 200


def test_token_required_when_set():
    with _serve("s3cr3t") as base:
        # no credential → 401
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(base + "/")
        assert e.value.code == 401
        # wrong token → 401
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(base + "/?token=nope")
        assert e.value.code == 401
        # right token via query → 200
        assert _get(base + "/?token=s3cr3t").status == 200
        # right token via Authorization: Bearer → 200
        assert _get(base + "/", {"Authorization": "Bearer s3cr3t"}).status == 200
