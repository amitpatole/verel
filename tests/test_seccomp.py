"""seccomp-bpf layer on the §7.7 container runner.

Unit assertions run everywhere; the live containment checks skip cleanly where bwrap or the
libseccomp binding is absent (e.g. CI without bubblewrap/libseccomp installed)."""

import tempfile

import pytest

from verel.toolsmith import (
    ALLOWED_SYSCALLS,
    DENIED_SYSCALLS,
    PROFILE_ALLOWLIST,
    SideEffect,
    ToolRecord,
)
from verel.toolsmith.container import bwrap_available, run_container
from verel.toolsmith.seccomp import build_bpf, seccomp_available

requires_seccomp = pytest.mark.skipif(not seccomp_available(),
                                      reason="libseccomp python binding not installed")
requires_container = pytest.mark.skipif(not (bwrap_available() and seccomp_available()),
                                        reason="needs bwrap + libseccomp binding")


def _tool(code, name="f"):
    return ToolRecord(name=name, code=code, side_effect=SideEffect.READ_ONLY).sign()


def test_denylist_covers_the_dangerous_primitives():
    # the curated denylist must at least contain the headline escape primitives
    for syscall in ("ptrace", "mount", "socket", "unshare", "setns", "bpf", "init_module"):
        assert syscall in DENIED_SYSCALLS


def test_allowlist_is_default_deny_and_omits_the_escape_syscalls():
    # the strict jail must ALLOW pure-compute essentials and must NOT list network / spawn /
    # privileged syscalls (their omission under a default-EPERM filter is what denies them)
    for needed in ("read", "write", "mmap", "futex", "openat", "execve"):
        assert needed in ALLOWED_SYSCALLS
    for forbidden in ("socket", "connect", "clone", "fork", "ptrace", "mount", "bpf"):
        assert forbidden not in ALLOWED_SYSCALLS


@requires_seccomp
@pytest.mark.parametrize("profile", ["denylist", PROFILE_ALLOWLIST])
def test_build_bpf_emits_a_nonempty_program(profile):
    with tempfile.TemporaryFile() as f:
        installed = build_bpf(f, profile=profile)
        f.seek(0)
        program = f.read()
    assert installed > 0  # at least some rules resolved on this arch
    assert len(program) > 0  # a real compiled cBPF program was written


@requires_seccomp
def test_build_bpf_rejects_unknown_profile():
    with tempfile.TemporaryFile() as f, pytest.raises(ValueError):
        build_bpf(f, profile="nonsense")


@requires_container
def test_seccomp_denies_socket_creation():
    # socket() is NOT blocked by the network namespace alone — seccomp is what stops it.
    sock = _tool("def f():\n    import socket\n    socket.socket()\n    return 'made socket'\n")
    with pytest.raises(Exception) as ei:  # SandboxError wrapping the child's PermissionError
        run_container(sock)
    assert "perm" in str(ei.value).lower() or "not permitted" in str(ei.value).lower()


@requires_container
def test_seccomp_allows_a_normal_pure_tool():
    assert run_container(_tool("def f(a, b):\n    return a + b\n"), [2, 3]) == 5


@requires_container
def test_without_seccomp_socket_is_not_denied():
    # control: proves the deny in test_seccomp_denies_socket_creation comes from seccomp,
    # not from something else in the sandbox (netns blocks connect(), not socket()).
    sock = _tool("def f():\n    import socket\n    socket.socket()\n    return 'made socket'\n")
    assert run_container(sock, seccomp=False) == "made socket"


# ── strict allowlist jail (default-deny) ────────────────────────────────────────────────────
@requires_container
def test_allowlist_runs_a_pure_compute_tool():
    # a single-threaded pure-compute tool must survive the minimal allow-list jail
    t = _tool("def f(a, b):\n    import math, json\n"
              "    return int(math.hypot(a, b)) + len(json.dumps({'k': [1, 2, 3]}))\n")
    assert run_container(t, [3, 4], seccomp_profile=PROFILE_ALLOWLIST) == 5 + len('{"k": [1, 2, 3]}')


@requires_container
@pytest.mark.parametrize("code", [
    "def f():\n    import socket\n    socket.socket()\n    return 'net'\n",         # network
    "def f():\n    import subprocess\n    return subprocess.run(['true']).returncode\n",  # spawn
    "def f():\n    import os\n    return os.fork()\n",                               # fork/clone
])
def test_allowlist_refuses_network_and_process_spawn(code):
    with pytest.raises(Exception) as ei:
        run_container(_tool(code), seccomp_profile=PROFILE_ALLOWLIST)
    msg = str(ei.value).lower()
    assert "perm" in msg or "not permitted" in msg
