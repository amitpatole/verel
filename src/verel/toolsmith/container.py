"""Container tool runner (§7.7 production) — OS-level isolation via bubblewrap.

The strongest tier of tool execution: the tool runs inside a `bwrap` namespace sandbox with
**no network** (`--unshare-all`), a **read-only** view of only the system libraries it needs
(no `/home`, no project files), an **ephemeral tmpfs** for `/tmp`, a cleared environment, and
the same in-process rlimits + wall-clock timeout on top. Verified live: network is blocked,
`/home` is unreadable, writes don't persist.

This is the real §7.7 "separate-trust-domain runner" for untrusted, agent-authored code.
Falls back to the rlimit-only subprocess sandbox where bwrap is unavailable (`best_runner`).
"""

from __future__ import annotations

import shutil

from .registry import ToolRecord
from .sandbox import _CHILD, SandboxError, exec_child, run_sandboxed


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
                  cpu_s: int = 3, mem_bytes: int = 256 * 1024 * 1024):
    """Execute `tool` inside a bwrap namespace sandbox (no net, read-only fs, ephemeral tmp)."""
    if not bwrap_available():
        raise SandboxError("bwrap not available — use run_sandboxed or install bubblewrap")
    if not tool.verify():
        raise SandboxError(f"tool {tool.name!r} failed signature verification")

    child = _CHILD.format(cpu=cpu_s, mem=mem_bytes)
    cmd = [*_bwrap_cmd(), "python3", "-I", "-S", "-c", child]
    # env={} clears the parent environment so no host secrets leak into the sandbox.
    return exec_child(cmd, tool, args, kwargs, timeout_s=timeout_s, env={})


def best_runner():
    """Return the strongest available tool runner: container (bwrap) else rlimit subprocess."""
    return run_container if bwrap_available() else run_sandboxed
