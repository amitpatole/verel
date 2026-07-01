"""Server-side git fencing sink (§6.3) — reject a PUSH that carries a stale fencing token.

The in-memory / sqlite fence (lease.py) stops a stale leader's write to the *task store*. But a
worker also pushes *code* to a shared remote, and that push must be fenced too — otherwise a
paused leader resumes and pushes stale work over its successor's. The durable enforcement point is
a **pre-receive hook** on the remote: the pusher sends its `(resource, token)` as git push options
(`git push -o verel-resource=R -o verel-token=N`), and the hook accepts the push only if the token
is current for that resource (checked against the same sqlite lease store).

`validate_push` is the pure decision; `render_pre_receive_hook` / `write_pre_receive_hook` install
it on a bare remote. Tested both as a pure function and end-to-end against a real bare repo.
"""

from __future__ import annotations

import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .lease import LeaseStore

RESOURCE_OPT = "verel-resource"
TOKEN_OPT = "verel-token"


@dataclass
class FenceDecision:
    allow: bool
    reason: str


def validate_push(store: LeaseStore, resource: str, token: int) -> FenceDecision:
    """Accept iff `token` IS the current (highest-issued) token for `resource`. A stale leader's
    token is below the current one (a successor took over and bumped it); an unknown resource has
    no issued token (current 0); a token above current was never issued — all rejected."""
    current = store.current_token(resource)
    if current > 0 and token == current:
        return FenceDecision(True, f"token {token} is current for {resource!r}")
    return FenceDecision(False, f"token {token} is not current ({current}) for {resource!r} — push rejected")


def push_options(resource: str, token: int) -> list[str]:
    """The `-o` args a fenced push must carry: `git push -o verel-resource=R -o verel-token=N`."""
    return ["-o", f"{RESOURCE_OPT}={resource}", "-o", f"{TOKEN_OPT}={token}"]


# A self-contained pre-receive hook: reads the push options, looks up the current token in the
# sqlite lease store, and rejects a stale push. __PY__/__DB__ are substituted at render time.
_HOOK = r'''#!__PY__
import os, sqlite3, sys

DB = r"__DB__"


def _opt(name):
    n = int(os.environ.get("GIT_PUSH_OPTION_COUNT", "0"))
    for i in range(n):
        v = os.environ.get("GIT_PUSH_OPTION_%d" % i, "")
        if v.startswith(name + "="):
            return v[len(name) + 1:]
    return None


resource, token = _opt("verel-resource"), _opt("verel-token")
if resource is None or token is None:
    sys.stderr.write("verel-fence: push must set -o verel-resource=.. -o verel-token=..\n")
    sys.exit(1)
try:
    token = int(token)
except ValueError:
    sys.stderr.write("verel-fence: token must be an integer\n")
    sys.exit(1)
con = sqlite3.connect(DB, timeout=30)
row = con.execute("SELECT max_token FROM leases WHERE key=?", (resource,)).fetchone()
current = row[0] if row else 0
if current > 0 and token == current:
    sys.exit(0)
sys.stderr.write("verel-fence: token %d is not current %d for %r — push rejected\n"
                 % (token, current, resource))
sys.exit(1)
'''


def render_pre_receive_hook(db_path: str | Path, *, python: str | None = None) -> str:
    """The pre-receive hook script that fences pushes against the sqlite lease store at `db_path`."""
    py = str(python or sys.executable).replace("\\", "/")
    return _HOOK.replace("__PY__", py).replace("__DB__", str(Path(db_path).resolve()))


def enable_push_options(repo_git_dir: str | Path) -> None:
    """A fenced push sends its token as a push option, which a remote only relays to the hook when
    `receive.advertisePushOptions` is on. Set it on the bare remote (idempotent)."""
    import subprocess
    subprocess.run(["git", "--git-dir", str(repo_git_dir), "config",
                    "receive.advertisePushOptions", "true"], check=True, capture_output=True)


def write_pre_receive_hook(repo_git_dir: str | Path, db_path: str | Path,
                           *, python: str | None = None) -> Path:
    """Install the hook into `<repo_git_dir>/hooks/pre-receive` (the bare-remote hooks dir), make
    it executable, and enable push options on the remote. Returns the hook path."""
    hooks = Path(repo_git_dir) / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-receive"
    hook.write_text(render_pre_receive_hook(db_path, python=python), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    enable_push_options(repo_git_dir)
    return hook
