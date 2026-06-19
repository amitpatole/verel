"""seccomp-bpf syscall filter for the container tool runner (§7.7).

The bwrap container already removes the network (CLONE_NEWNET via `--unshare-all`), the host
filesystem (ro-bind of /usr,/bin,/lib only), and the host environment. seccomp adds the missing
layer: a *kernel* syscall filter, so even arbitrary native code in the sandbox cannot reach a
dangerous syscall — it's the difference between "we didn't give you a network device" and "the
kernel refuses the socket() syscall".

This is a DENY-LIST filter (default ALLOW, EPERM on a curated set of dangerous syscalls), not a
minimal allow-list jail: the payload is a full CPython interpreter running arbitrary
agent-authored code, for which an exhaustive allow-list is impractical to keep correct across
Python/libc versions. As a denylist it is honest defense-in-depth — it blocks ptrace, mount,
raw socket creation, namespace manipulation (unshare/setns/clone3), module loading, bpf, kexec,
key management, chroot/pivot_root, device-node creation and cross-process memory peeking — *on
top of* the namespace isolation, not instead of it.

Optional: needs the libseccomp python binding (`seccomp` or `pyseccomp`). When it is unavailable
the container runner still runs (namespace isolation applies) but without this layer, and
`seccomp_available()` reports False so callers can decide whether that is acceptable.
"""

from __future__ import annotations

import errno
from typing import Any

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


def build_filter(s: Any) -> tuple[Any, int]:
    """Build the deny-list SyscallFilter using binding `s`; return (filter, rules_installed).

    Each rule is added independently so one syscall name that is unknown on this architecture
    is skipped rather than aborting the whole filter."""
    flt = s.SyscallFilter(defaction=s.ALLOW)
    installed = 0
    for name in DENIED_SYSCALLS:
        try:
            flt.add_rule(s.ERRNO(errno.EPERM), name)
            installed += 1
        except (ValueError, OSError, RuntimeError):
            continue  # not defined on this arch/kernel — the remaining rules still apply
    return flt, installed


def build_bpf(fileobj) -> int:
    """Compile the deny-list filter and write the cBPF program (libseccomp's bwrap-compatible
    export) to `fileobj`. Returns the number of syscall rules actually installed. Raises if no
    libseccomp binding is available."""
    s = _binding()
    if s is None:
        raise RuntimeError("libseccomp python binding not available (pip install pyseccomp)")
    flt, installed = build_filter(s)
    flt.export_bpf(fileobj)
    return installed
