"""Worker worktree isolation + advisory lease (§6.1, §6.3 — v1 cut).

Each worker gets an EXCLUSIVE local git worktree so parallel workers never stomp each other's
files — the multi-repo/parallel-edit isolation the design calls for. v1 uses a single-writer
scheduler, so the lease is a local ADVISORY lock (an exclusive lockfile), not a fencing token;
fencing tokens + the server-side git fencing sink are v3 (they only matter under concurrent
managers, which v1 doesn't have).

A worktree is created off a base ref, the worker mutates files inside it, and it is removed on
release (auto-cleaned). This is single-repo isolation; the cross-repo atomic saga is v3.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

# A task id becomes a filesystem path and a git ref — constrain it so it can't traverse out of the
# worktree root (`../`), be `.`/`..`, or start with `-` (git option injection).
_VALID_TASK_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*\Z")


def _check_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or not _VALID_TASK_ID.match(task_id):
        raise WorktreeError(f"invalid task_id {task_id!r}: must match [A-Za-z0-9_][A-Za-z0-9._-]*")
    return task_id


class WorktreeError(RuntimeError):
    pass


class LeaseHeld(WorktreeError):
    pass


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise WorktreeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


@dataclass
class Worktree:
    task_id: str
    path: Path
    branch: str
    _manager: WorktreeManager

    def write(self, rel: str, content: str) -> Path:
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def commit_all(self, message: str) -> str | None:
        _git(self.path, "add", "-A")
        # nothing staged -> no commit
        if not _git(self.path, "status", "--porcelain"):
            return None
        _git(self.path, "-c", "user.name=verel", "-c", "user.email=verel@local",
             "commit", "-q", "-m", message)
        return _git(self.path, "rev-parse", "HEAD")

    def release(self) -> None:
        self._manager.remove(self.task_id)


class WorktreeManager:
    """Creates/removes isolated worktrees of `repo_root` under `.verel/wt/<task-id>`."""

    def __init__(self, repo_root: str | Path, *, root: str | Path | None = None):
        self.repo = Path(repo_root).resolve()
        if not (self.repo / ".git").exists():
            raise WorktreeError(f"{self.repo} is not a git repository")
        self.root = Path(root) if root else self.repo / ".verel" / "wt"
        self.root.mkdir(parents=True, exist_ok=True)

    def _lock_path(self, task_id: str) -> Path:
        return self.root / f"{_check_task_id(task_id)}.lock"

    def _wt_path(self, task_id: str) -> Path:
        return self.root / _check_task_id(task_id)

    def acquire_lease(self, task_id: str) -> None:
        """Exclusive advisory lock. O_CREAT|O_EXCL is atomic on POSIX, so two workers cannot
        both hold the same task's lease (the single-writer split-brain guard)."""
        lock = self._lock_path(task_id)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as e:
            raise LeaseHeld(f"lease for {task_id!r} already held ({lock})") from e
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)

    def release_lease(self, task_id: str) -> None:
        self._lock_path(task_id).unlink(missing_ok=True)

    def create(self, task_id: str, *, base: str = "HEAD") -> Worktree:
        self.acquire_lease(task_id)
        path = self._wt_path(task_id)
        branch = f"verel/{task_id}"
        try:
            if path.exists():
                self._force_remove(task_id)
            # `--` ends option parsing so a `-`-leading base can't be read as a git flag.
            _git(self.repo, "worktree", "add", "-q", "-b", branch, "--", str(path), base)
        except WorktreeError:
            self.release_lease(task_id)
            raise
        return Worktree(task_id=task_id, path=path, branch=branch, _manager=self)

    def _force_remove(self, task_id: str) -> None:
        path = self._wt_path(task_id)
        subprocess.run(["git", "-C", str(self.repo), "worktree", "remove", "--force", str(path)],
                       capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.repo), "branch", "-D", f"verel/{task_id}"],
                       capture_output=True, text=True)

    def remove(self, task_id: str) -> None:
        self._force_remove(task_id)
        _git(self.repo, "worktree", "prune")
        self.release_lease(task_id)

    def list(self) -> list[str]:
        out = _git(self.repo, "worktree", "list", "--porcelain")
        return [line.split(" ", 1)[1] for line in out.splitlines() if line.startswith("worktree ")]
