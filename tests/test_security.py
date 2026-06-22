"""Security regression tests — lock the fixes from the attack-surface audit.

Each test pins a specific hardening so a future refactor can't silently reopen the hole.
"""

from __future__ import annotations

import hashlib
import hmac

from verel._secrets import load_secret
from verel.registry.store import PublicRegistry
from verel.toolsmith.seccomp import DENIED_SYSCALLS
from verel.verdict.gate import verify_signature
from verel.verdict.models import RunReceipt

_OLD_PUBLIC_DEFAULTS = (b"verel-dev-runner-secret", b"verel-dev-registry-secret", b"verel-dev-tool-secret")


def test_registry_get_rejects_path_traversal(tmp_path):
    """A content-hash lookup must reject anything that isn't a hex digest, so `../` can't
    escape the registry root and read arbitrary *.json files off the host (audit N5)."""
    reg = PublicRegistry(tmp_path)
    for evil in ("../../../etc/passwd", "..%2f..%2fsecret", "/etc/hosts", "a/../../b", "ABC..json"):
        assert reg.get(evil) is None
    # a well-formed (but absent) hash is also None — and crucially does not raise/traverse
    assert reg.get("0123456789abcdef") is None


def test_seccomp_denylist_blocks_process_spawn():
    """The default container profile must deny fork/clone/vfork so sandboxed tool code can't
    spawn subprocesses or fork-bomb (audit S3)."""
    for sc in ("fork", "vfork", "clone", "clone3", "unshare", "socket", "ptrace"):
        assert sc in DENIED_SYSCALLS


def test_no_public_default_signing_secret(monkeypatch, tmp_path):
    """An unset signing secret must resolve to a real per-installation random key — never a
    public, in-source constant anyone could read and forge with (audit C1/C2)."""
    monkeypatch.setenv("VEREL_X_KEY", "configured")
    assert load_secret("VEREL_X_KEY", "x") == b"configured"   # env override wins

    monkeypatch.delenv("VEREL_X_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    k1 = load_secret("VEREL_X_KEY", "x")
    assert k1 not in _OLD_PUBLIC_DEFAULTS and len(k1) == 32   # random, not a public default
    assert load_secret("VEREL_X_KEY", "x") == k1              # persisted: stable cross-process on one host


def test_servers_refuse_unauthenticated_non_loopback_bind(tmp_path):
    """A server must not bind a routable interface without an auth token — that would expose an
    unauthenticated service to the network (audit N3). Loopback stays zero-config."""
    import pytest

    from verel.fleet.control_plane import ControlPlaneServer
    from verel.memory.hosted import MemoryServer
    from verel.registry.hosted import RegistryServer

    with pytest.raises(ValueError, match="auth_token"):
        MemoryServer(":memory:", host="0.0.0.0")
    with pytest.raises(ValueError, match="auth_token"):
        ControlPlaneServer(str(tmp_path / "cp.db"), host="0.0.0.0")
    with pytest.raises(ValueError, match="auth_token"):
        RegistryServer(tmp_path / "reg", host="0.0.0.0")
    # loopback with no token is fine (the common local case); release the socket without the
    # serve_forever/shutdown dance (the server was never started).
    srv = MemoryServer(":memory:", host="127.0.0.1")
    srv._httpd.server_close()
    # a non-loopback bind WITH a token is allowed
    srv2 = MemoryServer(":memory:", host="0.0.0.0", auth_token="t")
    srv2._httpd.server_close()


def test_forged_receipt_with_old_default_secret_is_rejected():
    """A receipt signed with the retired public default secret must NOT verify — the whole point
    of removing the default (audit C1)."""
    rr = RunReceipt(suite_sha="s", inputs_digest="i", coverage_assertion="c",
                    runner_identity="r", signature="")
    rr.signature = hmac.new(b"verel-dev-runner-secret", rr.signing_payload().encode(),
                            hashlib.sha256).hexdigest()
    assert verify_signature(rr) is False
