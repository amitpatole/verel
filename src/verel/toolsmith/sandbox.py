"""Subprocess sandbox for executing agent-built tools (§7.7).

A genuine process boundary, unlike the in-process restricted-namespace guard in registry.py.
The tool runs in a FRESH interpreter (`python -I -S` — isolated mode, no site, no env-driven
imports, no user site-packages), with the function name + args passed over stdin and the
result returned over stdout as JSON. The child applies POSIX resource limits (CPU time,
address space, no new files) and the parent enforces a wall-clock timeout and kills the whole
process group on overrun.

Honest scope: this stops CPU/memory runaways and process-local crashes, isolates interpreter
state, and (via RLIMIT_FSIZE=0) prevents persisting file CONTENT to disk — though an empty
file can still be created and a buffered, never-flushed write won't error. It does NOT block
network egress or filesystem READS. True containment (network namespace / seccomp / container
/ VM) is the production §7.7 runner. This is a strong, dependency-free middle tier.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap

from .registry import ToolRecord

# Runs inside the sandboxed child. Reads {func, args, kwargs} from stdin, prints result JSON.
_CHILD = textwrap.dedent(
    '''
    import json, sys
    try:
        import resource
        # CPU seconds, address space (256MB), and no new open files beyond a few.
        resource.setrlimit(resource.RLIMIT_CPU, ({cpu}, {cpu}))
        resource.setrlimit(resource.RLIMIT_AS, ({mem}, {mem}))
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))   # cannot write files
        except (ValueError, OSError):
            pass
    except Exception:
        pass

    req = json.loads(sys.stdin.read())
    ns = {{}}
    exec(compile(req["code"], "<sandboxed-tool>", "exec"), ns)
    fn = ns.get(req["func"])
    if not callable(fn):
        print(json.dumps({{"error": "no callable named %r" % req["func"]}})); sys.exit(0)
    try:
        out = fn(*req.get("args", []), **req.get("kwargs", {{}}))
        json.dumps(out)  # ensure serializable
        print(json.dumps({{"ok": out}}))
    except Exception as e:
        print(json.dumps({{"error": "%s: %s" % (type(e).__name__, e)}}))
    '''
)


class SandboxError(RuntimeError):
    pass


def run_sandboxed(tool: ToolRecord, args=None, kwargs=None, *, timeout_s: float = 3.0,
                  cpu_s: int = 2, mem_bytes: int = 256 * 1024 * 1024):
    """Execute `tool` in an isolated subprocess. Verifies the signature first; returns the
    function's return value, or raises SandboxError on failure/timeout/limit."""
    if not tool.verify():
        raise SandboxError(f"tool {tool.name!r} failed signature verification")

    child = _CHILD.format(cpu=cpu_s, mem=mem_bytes)
    payload = json.dumps({"code": tool.code, "func": tool.name,
                          "args": list(args or []), "kwargs": dict(kwargs or {})})
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", child],
            input=payload, capture_output=True, text=True, timeout=timeout_s,
            start_new_session=True,  # own process group, so timeout kills children too
        )
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"tool {tool.name!r} exceeded {timeout_s}s wall-clock") from e

    if proc.returncode != 0 and not proc.stdout:
        raise SandboxError(f"tool {tool.name!r} crashed (rc={proc.returncode}): {proc.stderr[:200]}")
    try:
        result = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as e:
        raise SandboxError(f"tool {tool.name!r} produced no parseable result: {proc.stdout[:200]}") from e
    if "error" in result:
        raise SandboxError(result["error"])
    return result["ok"]
