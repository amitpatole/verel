"""Per-tool seccomp policy *learning* (§7.7) — freeze a tool's verified syscall footprint.

The capability profile (seccomp.py) enforces "this tool may use only the syscalls it actually
needed." This module derives that set the honest way: run the tool's function over its **held-out
eval cases** — the same cases that verified it — under `strace`, and union the syscalls observed.
The result is the tool's policy: a later run that tries a syscall the tool never exercised while
being verified (e.g. an input-triggered `socket()` or `execve` of a shell) is refused by the
kernel, even though the tool's code passed eval.

Honest scope: learning needs `strace` (a build/registration-time dependency, not a runtime one —
enforcement needs only libseccomp). It traces the interpreter directly (not under bwrap), so the
bwrap supervisor syscalls are added at enforce time by `capability_allow`, not here. A learned
policy is only as complete as its eval corpus: under-exercised tools get a tighter (safer) policy,
which is why `RUNTIME_FLOOR` guarantees the interpreter itself can always run. Strace summary
parsing is best-effort across strace versions; an empty/garbled summary returns an empty set,
which `capability_allow` still floors into a runnable policy.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys

from .sandbox import _CHILD, _payload_for
from .smith import ToolCase

# a strace `-c` summary data row ends with the syscall name; header/total rows are filtered out
_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")
_SKIP = {"total", "syscall", "calls", "errors", "seconds", "usecs", "call"}


def strace_available() -> bool:
    return shutil.which("strace") is not None


def _syscalls_for(payload: str, *, timeout_s: float) -> set[str]:
    """Run the child harness once under strace; return the set of syscall names it issued."""
    cmd = ["strace", "-f", "-qq", "-c", "-e", "trace=all",
           sys.executable, "-I", "-S", "-c", _CHILD.format(cpu=2, mem=256 * 1024 * 1024)]
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout_s)
    except (subprocess.TimeoutExpired, OSError):
        return set()
    found: set[str] = set()
    for line in proc.stderr.splitlines():
        tok = line.split()
        if tok and (name := tok[-1]) not in _SKIP and _NAME.match(name):
            found.add(name)
    return found


def learn_syscall_profile(code: str, name: str, cases: list[ToolCase], *,
                          timeout_s: float = 10.0) -> tuple[str, ...]:
    """Trace `code`'s `name` function over `cases` and return the sorted union of syscalls used.
    Returns () if strace is unavailable (callers should fall back to the allowlist profile)."""
    if not strace_available() or not cases:
        return ()
    used: set[str] = set()
    for c in cases:
        used |= _syscalls_for(_payload_for(code, name, c.args, c.kwargs), timeout_s=timeout_s)
    return tuple(sorted(used))
