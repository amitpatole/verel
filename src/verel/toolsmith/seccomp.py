"""seccomp-bpf syscall filters for the container tool runner (§7.7).

The bwrap container already removes the network (CLONE_NEWNET via `--unshare-all`), the host
filesystem (ro-bind of /usr,/bin,/lib only), and the host environment. seccomp adds the missing
layer: a *kernel* syscall filter, so even arbitrary native code in the sandbox cannot reach a
dangerous syscall — it's the difference between "we didn't give you a network device" and "the
kernel refuses the socket() syscall".

Two profiles, weakest-to-strongest:

* ``denylist`` (default) — default ALLOW, EPERM on a curated set of dangerous syscalls (ptrace,
  mount, raw socket, namespace manipulation, module loading, bpf, kexec, keyring, chroot,
  device-node creation, cross-process memory peek). Honest defense-in-depth around a full
  CPython payload that runs *arbitrary* tool code; it won't break an exotic-but-legitimate tool.

* ``allowlist`` — default **EPERM** (default-deny), ALLOW only the syscalls a pure-compute
  CPython payload actually needs (derived empirically by tracing the interpreter, plus a margin
  for stdlib/libc/version variation). This is the real minimal jail: a tool calling `socket()`,
  spawning a subprocess (no `clone`/`fork`), or touching any privileged syscall is refused
  because it simply isn't on the list. The trade-off is strictness — a tool that needs threads,
  multiprocessing, or an unusual syscall is refused, so it is opt-in for *untrusted* code.
  EPERM (not KILL) is the default action so a refusal surfaces as a Python ``PermissionError``
  rather than a SIGSYS crash, matching the Docker/podman default-profile convention.

Both are applied *on top of* the namespace isolation, not instead of it. Optional: needs the
libseccomp python binding (`seccomp` or `pyseccomp`). When unavailable the container runner still
runs (namespace isolation applies) but without this layer, and `seccomp_available()` reports
False so callers can decide whether that is acceptable.
"""

from __future__ import annotations

import errno
from typing import Any

PROFILE_DENYLIST = "denylist"
PROFILE_ALLOWLIST = "allowlist"

# ── denylist profile ──────────────────────────────────────────────────────────────────────
# Dangerous syscalls denied (EPERM) on top of the namespace sandbox. libseccomp resolves these
# names per-architecture; a name unknown on this arch/kernel is skipped (see build_filter), so
# the list is a superset and never errors out a whole filter over one missing entry.
DENIED_SYSCALLS: tuple[str, ...] = (
    "ptrace",                                   # debug / inject into other processes
    "process_vm_readv", "process_vm_writev",    # peek/poke another process's memory
    "mount", "umount", "umount2",               # filesystem topology
    "pivot_root", "chroot",                     # root-of-fs games
    "unshare", "setns", "clone3",               # create / enter namespaces
    "socket", "socketcall",                     # any socket (net is netns-blocked too; in depth)
    "bpf",                                      # load BPF programs / maps
    "kexec_load", "kexec_file_load",            # load a replacement kernel
    "init_module", "finit_module", "delete_module",  # kernel modules
    "add_key", "request_key", "keyctl",         # kernel keyring
    "swapon", "swapoff",
    "reboot",
    "mknod", "mknodat",                         # create device nodes
    "perf_event_open",
    "_sysctl",
)

# ── allowlist profile ─────────────────────────────────────────────────────────────────────
# The syscalls a single-threaded, pure-compute CPython payload needs. The core set was derived
# by tracing `python3 -I -S` running representative pure tools (math/json/re/hashlib/decimal/
# itertools/datetime); the rest is a deliberate margin for libc/stdlib/version variation. It
# excludes — by omission, which under a default-EPERM filter means "denied" — every network
# syscall, every process-spawn syscall (clone/fork/vfork — so no subprocess and no threads), and
# every privileged family in DENIED_SYSCALLS. `execve` is allowed because the bwrap→python launch
# is itself an execve under the filter; a re-exec stays inside the same filter + read-only fs +
# no-spawn jail, so it cannot escalate. File *writes* are contained by RLIMIT_FSIZE + the
# read-only fs, not by withholding `write` (stdout needs it).
ALLOWED_SYSCALLS: tuple[str, ...] = (
    # process lifecycle / threads-of-one
    "execve", "exit", "exit_group", "restart_syscall", "rseq",
    "set_tid_address", "set_robust_list", "arch_prctl", "prlimit64", "prctl",
    # bwrap's own pid-namespace init/monitor (pid 1) runs under this filter and must reap the
    # payload: it needs wait + its sync primitives. These let bwrap supervise, not the tool spawn
    # (clone/fork are still withheld, so the payload cannot create a child to wait on).
    "wait4", "waitid", "signalfd4", "eventfd2",
    # memory
    "brk", "mmap", "mremap", "munmap", "mprotect", "madvise",
    # io on already-open fds (no socket, no spawn)
    "read", "pread64", "write", "pwrite64", "lseek", "close", "dup", "dup2", "dup3",
    "fcntl", "ioctl", "pipe2", "poll", "ppoll", "select", "pselect6",
    "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    # filesystem metadata + module import (reads only; fs is ro-bound)
    "openat", "openat2", "access", "faccessat", "faccessat2",
    "stat", "lstat", "fstat", "newfstatat", "statx", "statfs", "fstatfs",
    "getdents", "getdents64", "readlink", "readlinkat", "getcwd",
    # identity / introspection (harmless reads)
    "getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid",
    "getgroups", "uname", "sysinfo", "sched_getaffinity", "sched_yield",
    # time
    "clock_gettime", "clock_getres", "clock_nanosleep", "gettimeofday",
    "time", "nanosleep",
    # signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait", "sigaltstack",
    # entropy (hash randomization, secrets)
    "getrandom",
    # futex + membarrier (allocator / GIL primitives, even single-threaded)
    "futex", "membarrier",
)


def _binding() -> Any | None:
    """Return the libseccomp python binding (`seccomp` or its `pyseccomp` drop-in), or None."""
    try:
        import seccomp  # the official libseccomp binding
        return seccomp
    except ImportError:
        try:
            import pyseccomp  # pure pip wrapper, identical API
            return pyseccomp
        except ImportError:
            return None


def seccomp_available() -> bool:
    """True iff a libseccomp python binding is importable, so a filter can be compiled."""
    return _binding() is not None


def _add_each(flt: Any, action: Any, names: tuple[str, ...]) -> int:
    """Add one rule per syscall name, skipping names unknown on this arch/kernel."""
    installed = 0
    for name in names:
        try:
            flt.add_rule(action, name)
            installed += 1
        except (ValueError, OSError, RuntimeError):
            continue  # not defined on this arch/kernel — the remaining rules still apply
    return installed


def build_filter(s: Any, *, profile: str = PROFILE_DENYLIST) -> tuple[Any, int]:
    """Build the SyscallFilter for `profile` using binding `s`; return (filter, rules_installed).

    `denylist`: default ALLOW, deny the dangerous set. `allowlist`: default EPERM, allow only the
    pure-compute set. Each rule is added independently so one syscall name unknown on this
    architecture is skipped rather than aborting the whole filter."""
    eperm = s.ERRNO(errno.EPERM)
    if profile == PROFILE_ALLOWLIST:
        flt = s.SyscallFilter(defaction=eperm)
        installed = _add_each(flt, s.ALLOW, ALLOWED_SYSCALLS)
    elif profile == PROFILE_DENYLIST:
        flt = s.SyscallFilter(defaction=s.ALLOW)
        installed = _add_each(flt, eperm, DENIED_SYSCALLS)
    else:
        raise ValueError(f"unknown seccomp profile {profile!r}")
    return flt, installed


def build_bpf(fileobj, *, profile: str = PROFILE_DENYLIST) -> int:
    """Compile the `profile` filter and write the cBPF program (libseccomp's bwrap-compatible
    export) to `fileobj`. Returns the number of syscall rules actually installed. Raises if no
    libseccomp binding is available."""
    s = _binding()
    if s is None:
        raise RuntimeError("libseccomp python binding not available (pip install pyseccomp)")
    flt, installed = build_filter(s, profile=profile)
    flt.export_bpf(fileobj)
    return installed
