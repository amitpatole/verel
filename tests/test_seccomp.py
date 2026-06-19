"""seccomp-bpf layer on the §7.7 container runner.

Unit assertions run everywhere; the live containment checks skip cleanly where bwrap or the
libseccomp binding is absent (e.g. CI without bubblewrap/libseccomp installed)."""

import tempfile

import pytest

from verel.toolsmith import (
    ALLOWED_SYSCALLS,
    DENIED_SYSCALLS,
    PROFILE_ALLOWLIST,
    PROFILE_CAPABILITY,
    SideEffect,
    ToolCase,
    ToolRecord,
    capability_allow,
    learn_syscall_profile,
    strace_available,
)
from verel.toolsmith.container import bwrap_available, run_container
from verel.toolsmith.seccomp import SUPERVISOR_SYSCALLS, build_bpf, seccomp_available

requires_seccomp = pytest.mark.skipif(not seccomp_available(),
                                      reason="libseccomp python binding not installed")
requires_container = pytest.mark.skipif(not (bwrap_available() and seccomp_available()),
                                        reason="needs bwrap + libseccomp binding")
requires_learn = pytest.mark.skipif(not strace_available(),
                                    reason="strace not installed (needed to learn a policy)")


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


@requires_seccomp
def test_capability_profile_requires_an_allow_set():
    with tempfile.TemporaryFile() as f, pytest.raises(ValueError):
        build_bpf(f, profile=PROFILE_CAPABILITY, allow=None)


def test_capability_allow_floors_a_policy_without_granting_escapes():
    enforced = set(capability_allow(["clock_nanosleep"]))  # one learned syscall
    # the learned syscall + the runtime floor + bwrap supervisor are present...
    assert "clock_nanosleep" in enforced
    assert {"read", "write", "mmap", "execve"} <= enforced       # floor essentials
    assert set(SUPERVISOR_SYSCALLS) <= enforced                  # bwrap reaper
    # ...and no escape primitive is ever floored in
    assert enforced.isdisjoint({"socket", "connect", "clone", "fork", "ptrace", "mount", "bpf"})


def test_capability_is_strictly_tighter_than_the_allowlist():
    # a minimal policy must enforce a PROPER subset of the allow-list jail (it denies the
    # optional syscalls — pipe2/epoll/nanosleep/select — that a tool didn't exercise)
    enforced = set(capability_allow(["getpid"]))
    allowlist = set(ALLOWED_SYSCALLS) | set(SUPERVISOR_SYSCALLS)
    assert enforced < allowlist
    assert {"pipe2", "epoll_ctl", "nanosleep", "select"} & (allowlist - enforced)


@requires_learn
def test_learn_syscall_profile_captures_the_core():
    code = "def f(a, b):\n    import math\n    return int(math.hypot(a, b))\n"
    policy = learn_syscall_profile(code, "f", [ToolCase(args=[3, 4]), ToolCase(args=[5, 12])])
    assert policy  # strace produced something
    assert {"mmap", "read", "openat"} <= set(policy)  # interpreter essentials seen
    assert "socket" not in policy and "clone" not in policy  # a pure tool issues neither


@requires_container
def test_capability_jail_runs_the_verified_tool_and_blocks_new_syscalls():
    code = "def f(a, b):\n    import math\n    return int(math.hypot(a, b))\n"
    policy = list(capability_allow(["getpid"]))  # a tight, fixed policy (no pipe2/epoll/socket)
    t = ToolRecord(name="f", code=code, side_effect=SideEffect.READ_ONLY, syscall_policy=policy).sign()
    # the pure tool runs under the tight policy
    assert run_container(t, [3, 4], seccomp_profile=PROFILE_CAPABILITY) == 5
    # a pipe() — allowed by the allow-list jail — is refused under this policy (pipe2 not granted)
    pipe = ToolRecord(name="f", side_effect=SideEffect.READ_ONLY, syscall_policy=policy,
                      code="def f(a, b):\n    import os\n    r, w = os.pipe()\n    return a + b\n").sign()
    assert run_container(pipe, [2, 3], seccomp_profile=PROFILE_ALLOWLIST) == 5
    with pytest.raises(Exception):
        run_container(pipe, [2, 3], seccomp_profile=PROFILE_CAPABILITY)


@requires_learn
def test_toolsmith_learns_and_stores_a_capability_policy():
    from verel.memory import LocalMemory
    from verel.toolsmith import ToolCase, ToolRegistry, ToolSmith, ToolSpec

    smith = ToolSmith(ToolRegistry(LocalMemory()),
                      chat=lambda _m: "```python\ndef triple(n):\n    return n * 3\n```",
                      isolation="subprocess", learn_syscalls=True)
    res = smith.build(ToolSpec(name="triple", capability="multiply an int by three",
                               cases=[ToolCase(args=[2], expected=6), ToolCase(args=[10], expected=30)]))
    assert res.registered and res.tool.syscall_policy  # a policy was learned + stored
    assert any(p.startswith("syscall-policy:") for p in res.tool.provenance)


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
