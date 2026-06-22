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


def test_lease_terminal_write_is_owner_bound():
    """A fencing token is readable by any authenticated caller; terminal writes must ALSO require the
    owner, so a token-holder can't hijack another task's outcome (red-team C2)."""
    import pytest

    from verel.fleet import InMemoryLeaseStore
    from verel.fleet.lease import FencingError, Lease

    s = InMemoryLeaseStore()
    lease = s.acquire("task", "alice", now=0.0, ttl=10.0)
    with pytest.raises(FencingError):                       # right token, wrong owner
        s.complete(Lease("task", "mallory", lease.token, 0.0), "poisoned")
    assert s.outcome("task") is None
    s.complete(lease, "done")                               # the real owner succeeds
    assert s.outcome("task") == "done"


def test_result_digest_binds_confidence_and_errored():
    """The attestation digest must cover every field the gate trusts — flipping confidence
    HIGH→LOW (which clamps a CRITICAL to WARNING) or toggling `errored` must change the digest, or
    a valid receipt could be paired with a downgraded report (red-team H1)."""
    from verel.verdict.models import (
        Confidence,
        GraderKind,
        Issue,
        IssueKind,
        Report,
        Severity,
        Verdict,
        report_result_digest,
    )

    hi = Issue(kind=IssueKind.OVERFLOW, severity=Severity.CRITICAL, message="x",
               source=GraderKind.SECURITY, confidence=Confidence.HIGH)
    lo = hi.model_copy(update={"confidence": Confidence.LOW})
    base = Report(verdict=Verdict.FAIL, summary="", issues=[hi], grader=GraderKind.SECURITY)
    flipped = Report(verdict=Verdict.FAIL, summary="", issues=[lo], grader=GraderKind.SECURITY)
    errored = Report(verdict=Verdict.FAIL, summary="", issues=[hi], grader=GraderKind.SECURITY, errored=True)
    assert report_result_digest(base) != report_result_digest(flipped)   # confidence bound
    assert report_result_digest(base) != report_result_digest(errored)   # errored bound


def test_worktree_rejects_traversal_task_id(tmp_path):
    """task_id becomes a filesystem path + git ref — reject traversal/option-injection (red-team M1)."""
    import subprocess

    import pytest

    from verel.fleet.worktree import WorktreeError, WorktreeManager

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    mgr = WorktreeManager(str(tmp_path))
    for bad in ("../escape", "..", "a/b", "-rf", "/abs", ".", "x/../../y"):
        with pytest.raises(WorktreeError):
            mgr._wt_path(bad)
    assert mgr._wt_path("task-1").name == "task-1"           # a well-formed id is accepted


def test_eval_tool_cases_default_is_isolated_not_in_process():
    """Untrusted tool code must NOT run in the host process by default — only an explicit
    isolation='none' may. A tool that mutates host env proves out-of-process execution (round-3 C1)."""
    import os

    from verel.toolsmith.smith import ToolCase, eval_tool_cases

    os.environ.pop("VEREL_PWNED", None)
    code = "import os\ndef f(x):\n    os.environ['VEREL_PWNED'] = '1'\n    return x"
    eval_tool_cases(code, "f", [ToolCase(args=[1], expected=1)])   # ALL DEFAULTS
    assert os.environ.get("VEREL_PWNED") is None                   # host env untouched → ran isolated


def test_secret_rejects_insecure_planted_key(monkeypatch, tmp_path):
    """A pre-existing key file that is group/other-accessible (a planted key) must be refused so an
    attacker-known key can't be loaded to forge signatures — fall back to ephemeral (round-3 M)."""
    monkeypatch.delenv("VEREL_Y_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    keydir = tmp_path / "verel"
    keydir.mkdir()
    planted = keydir / "y.key"
    planted.write_bytes(b"attacker-known-key-value-0000001")
    planted.chmod(0o644)                                           # group/other-readable → insecure
    got = load_secret("VEREL_Y_KEY", "y")
    assert got != b"attacker-known-key-value-0000001"              # refused; used an ephemeral key


def test_negative_content_length_is_rejected():
    """A negative Content-Length must be rejected, not passed to read(-1) which reads to EOF and
    defeats the body-size cap (round-3 H)."""
    import socket

    from verel.memory.hosted import MemoryServer

    srv = MemoryServer(":memory:").start()
    try:
        host, port = srv._httpd.server_address[:2]
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b"POST /all HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n"
                  b"Connection: close\r\n\r\n" + b"A" * 4096)
        resp = s.recv(256)
        s.close()
        assert b"400" in resp                                      # rejected, not buffered to EOF
    finally:
        srv.stop()


def test_forged_receipt_with_old_default_secret_is_rejected():
    """A receipt signed with the retired public default secret must NOT verify — the whole point
    of removing the default (audit C1)."""
    rr = RunReceipt(suite_sha="s", inputs_digest="i", coverage_assertion="c",
                    runner_identity="r", signature="")
    rr.signature = hmac.new(b"verel-dev-runner-secret", rr.signing_payload().encode(),
                            hashlib.sha256).hexdigest()
    assert verify_signature(rr) is False
