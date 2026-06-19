"""Per-capability seccomp jail — a tool may use only the syscalls it earned while verified (§7.7).

The container runner's tightest profile. We learn a tool's syscall footprint from the SAME
held-out cases that verify it, freeze that as its policy, and enforce it: the verified tool runs,
but any syscall it never exercised — opening a socket, spawning a subprocess, even an unused
`pipe()` the broad allow-list jail would permit — is refused by the kernel.

Containment (no key, real bwrap + libseccomp):  python examples/demo_capability_jail.py
Needs: bubblewrap (`bwrap`), libseccomp binding (`pip install pyseccomp`), and `strace` to learn.
"""

from __future__ import annotations

from verel.toolsmith import (
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
from verel.toolsmith.seccomp import ALLOWED_SYSCALLS, SUPERVISOR_SYSCALLS, seccomp_available


def _tool(code: str, policy: list[str] | None = None) -> ToolRecord:
    return ToolRecord(name="f", capability="hypotenuse", code=code,
                      side_effect=SideEffect.READ_ONLY, syscall_policy=policy).sign()


def main() -> None:
    if not (bwrap_available() and seccomp_available() and strace_available()):
        print("needs bwrap + a libseccomp binding (pip install pyseccomp) + strace — skipping")
        return

    code = "def f(a, b):\n    import math\n    return int(math.hypot(a, b))\n"
    cases = [ToolCase(args=[3, 4], expected=5), ToolCase(args=[5, 12], expected=13)]

    # 1) LEARN the tool's footprint from its verification cases.
    policy = list(learn_syscall_profile(code, "f", cases))
    enforced = capability_allow(policy)
    allowlist = set(ALLOWED_SYSCALLS) | set(SUPERVISOR_SYSCALLS)
    print(f"learned {len(policy)} syscalls → enforced {len(enforced)} "
          f"(allow-list jail would permit {len(allowlist)})")
    print(f"  denied here but allowed by the allow-list jail: {sorted(allowlist - set(enforced))}\n")

    # 2) ENFORCE: the verified tool runs under its own policy.
    print("verified tool under its capability jail:",
          run_container(_tool(code, policy), [3, 4], seccomp_profile=PROFILE_CAPABILITY))

    # 3) Anything it never exercised is refused — even a benign pipe() the allow-list jail allows.
    pipe = "def f(a, b):\n    import os\n    r, w = os.pipe()\n    os.close(r)\n    return a + b\n"
    print("pipe() under the ALLOW-LIST jail:",
          run_container(_tool(pipe, policy), [2, 3], seccomp_profile=PROFILE_ALLOWLIST))
    try:
        run_container(_tool(pipe, policy), [2, 3], seccomp_profile=PROFILE_CAPABILITY)
        print("pipe() under the CAPABILITY jail: UNEXPECTEDLY ALLOWED")
    except Exception as e:  # noqa: BLE001
        print("pipe() under the CAPABILITY jail: REFUSED —", str(e).split(":")[-1].strip())

    for label, c in {
        "socket()": "def f(a, b):\n    import socket\n    socket.socket()\n    return a\n",
        "subprocess": "def f(a, b):\n    import subprocess\n    return subprocess.run(['true']).returncode\n",
    }.items():
        try:
            run_container(_tool(c, policy), [1, 1], seccomp_profile=PROFILE_CAPABILITY)
            print(f"{label} under the CAPABILITY jail: UNEXPECTEDLY ALLOWED")
        except Exception as e:  # noqa: BLE001
            print(f"{label} under the CAPABILITY jail: REFUSED —", str(e).split(":")[-1].strip())


if __name__ == "__main__":
    main()
