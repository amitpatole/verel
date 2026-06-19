"""Container tool runner (§7.7 production) — OS-level isolation via bubblewrap + seccomp.

The strongest tier of tool execution: the tool runs inside a `bwrap` namespace sandbox with
**no network** (`--unshare-all`), a **read-only** view of only the system libraries it needs
(no `/home`, no project files), an **ephemeral tmpfs** for `/tmp`, a cleared environment, the
same in-process rlimits + wall-clock timeout, and — when a libseccomp binding is available — a
**seccomp-bpf syscall filter** that denies dangerous syscalls (ptrace, mount, raw `socket`,
namespace manipulation, module loading, bpf, kexec, …) at the kernel boundary. Verified live:
network is blocked, `/home` is unreadable, writes don't persist, and a denied syscall returns
EPERM inside the sandbox.

This is the real §7.7 "separate-trust-domain runner" for untrusted, agent-authored code. The
seccomp layer is optional defense-in-depth (see seccomp.py); without it the namespace isolation
still applies. Falls back to the rlimit-only subprocess sandbox where bwrap is unavailable
(`best_runner`).
"""

from __future__ import annotations

import shutil
import tempfile

from .registry import ToolRecord
from .sandbox import _CHILD, SandboxError, exec_child, run_sandboxed
from .seccomp import build_bpf, seccomp_available


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def _bwrap_cmd() -> list[str]:
    cmd = ["bwrap", "--unshare-all", "--die-with-parent",
           "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib"]
    # /lib64 and /etc exist on most distros but not all (e.g. pure-merged-usr); bind if present.
    import os

    for p in ("/lib64", "/etc"):
        if os.path.exists(p):
            cmd += ["--ro-bind", p, p]
    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--setenv", "PATH", "/usr/bin"]
    return cmd


def run_container(tool: ToolRecord, args=None, kwargs=None, *, timeout_s: float = 5.0,
                  cpu_s: int = 3, mem_bytes: int = 256 * 1024 * 1024, seccomp: bool = True):
    """Execute `tool` inside a bwrap namespace sandbox (no net, read-only fs, ephemeral tmp), and
    — when `seccomp` is requested and a libseccomp binding is present — under a deny-list
    seccomp-bpf filter applied to the sandboxed process."""
    if not bwrap_available():
        raise SandboxError("bwrap not available — use run_sandboxed or install bubblewrap")
    if not tool.verify():
        raise SandboxError(f"tool {tool.name!r} failed signature verification")

    child = _CHILD.format(cpu=cpu_s, mem=mem_bytes)
    cmd = _bwrap_cmd()

    sec_file = None
    pass_fds: tuple[int, ...] = ()
    if seccomp and seccomp_available():
        # bwrap reads the compiled cBPF program from an inheritable fd; libseccomp exports it.
        sec_file = tempfile.TemporaryFile()  # noqa: SIM115 — fd must outlive the subprocess; closed in finally
        build_bpf(sec_file)
        sec_file.flush()
        sec_file.seek(0)
        cmd += ["--seccomp", str(sec_file.fileno())]
        pass_fds = (sec_file.fileno(),)

    cmd += ["python3", "-I", "-S", "-c", child]
    try:
        # env={} clears the parent environment so no host secrets leak into the sandbox.
        return exec_child(cmd, tool, args, kwargs, timeout_s=timeout_s, env={}, pass_fds=pass_fds)
    finally:
        if sec_file is not None:
            sec_file.close()


def best_runner():
    """Return the strongest available tool runner: container (bwrap) else rlimit subprocess."""
    return run_container if bwrap_available() else run_sandboxed
