"""Security regression tests — lock the fixes from the attack-surface audit.

Each test pins a specific hardening so a future refactor can't silently reopen the hole.
"""

from __future__ import annotations

from verel.registry.store import PublicRegistry
from verel.toolsmith.seccomp import DENIED_SYSCALLS


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
