"""Worker worktree isolation + advisory lease (§6.1, §6.3) — real git in a temp repo."""

import subprocess

import pytest

from verel.fleet import LeaseHeld, WorktreeError, WorktreeManager


def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    def g(*a):
        subprocess.run(["git", "-C", str(path), *a], check=True, capture_output=True)
    g("init", "-q")
    g("config", "user.name", "t")
    g("config", "user.email", "t@t")
    (path / "base.txt").write_text("base\n")
    g("add", "-A")
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")
    return path


@pytest.fixture
def repo(tmp_path):
    return _init_repo(tmp_path / "r")


def test_create_isolated_worktrees_do_not_interfere(repo):
    mgr = WorktreeManager(repo)
    wa = mgr.create("task-a")
    wb = mgr.create("task-b")
    try:
        wa.write("page.html", "AAA")
        wb.write("page.html", "BBB")  # same rel path, different worktrees
        assert (wa.path / "page.html").read_text() == "AAA"
        assert (wb.path / "page.html").read_text() == "BBB"
        assert wa.path != wb.path
    finally:
        wa.release()
        wb.release()


def test_lease_is_exclusive(repo):
    mgr = WorktreeManager(repo)
    w = mgr.create("solo")
    try:
        with pytest.raises(LeaseHeld):
            mgr.acquire_lease("solo")  # already held
    finally:
        w.release()
    # after release the lease can be re-acquired
    mgr.acquire_lease("solo")
    mgr.release_lease("solo")


def test_commit_in_worktree_is_isolated_to_its_branch(repo):
    mgr = WorktreeManager(repo)
    w = mgr.create("feat")
    try:
        w.write("page.html", "hello")
        sha = w.commit_all("add page")
        assert sha and (w.path / "page.html").exists()
        # the change lives on the worktree branch, not on the main repo working tree
        assert not (repo / "page.html").exists()
    finally:
        w.release()


def test_release_removes_worktree_and_lease(repo):
    mgr = WorktreeManager(repo)
    w = mgr.create("ephemeral")
    p = w.path
    assert p.exists()
    w.release()
    assert not p.exists()
    assert not mgr._lock_path("ephemeral").exists()


def test_non_git_dir_rejected(tmp_path):
    with pytest.raises(WorktreeError):
        WorktreeManager(tmp_path / "not-a-repo")
