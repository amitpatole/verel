"""The memory-backend registry (src/verel/memory/registry.py) + `_brain()` selection.

Pins: built-ins resolve, unknown names fail with a helpful list, `remote` fails closed without a
URL, entry-point plugins are discoverable (built-ins still win), and the `_brain()` back-compat —
VEREL_MEMORY_BACKEND unset behaves exactly as before (local, or remote when VEREL_BRAIN_URL is set).
"""

import pytest

from verel.memory import known_backends, load_backend
from verel.memory.local import LocalMemory
from verel.memory.registry import _BUILTINS


def test_load_local_builtin():
    assert isinstance(load_backend("local"), LocalMemory)


def test_known_backends_includes_builtins():
    known = known_backends()
    assert "local" in known and "remote" in known


def test_unknown_backend_lists_known(monkeypatch):
    with pytest.raises(ValueError, match="unknown memory backend 'nope'"):
        load_backend("nope")


def test_remote_fails_closed_without_url(monkeypatch):
    monkeypatch.delenv("VEREL_BRAIN_URL", raising=False)
    with pytest.raises(RuntimeError, match="requires VEREL_BRAIN_URL"):
        load_backend("remote")


def test_local_respects_memory_store_env(monkeypatch, tmp_path):
    db = tmp_path / "sub" / "brain.db"
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(db))
    m = load_backend("local")
    assert isinstance(m, LocalMemory) and m.path == str(db)
    assert db.exists()  # from_env created the parent dir + opened the file


# ---- `_brain()` back-compat (the operator-env selection path) --------------
def test_brain_defaults_to_local(monkeypatch, tmp_path):
    monkeypatch.delenv("VEREL_MEMORY_BACKEND", raising=False)
    monkeypatch.delenv("VEREL_BRAIN_URL", raising=False)
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "b.db"))
    from verel.mcp_server import _brain
    assert isinstance(_brain(), LocalMemory)


def test_brain_url_implies_remote(monkeypatch):
    monkeypatch.delenv("VEREL_MEMORY_BACKEND", raising=False)
    monkeypatch.setenv("VEREL_BRAIN_URL", "https://brain.internal:8443")
    from verel.mcp_server import _brain
    from verel.memory.hosted import RemoteMemory
    assert isinstance(_brain(), RemoteMemory)


def test_explicit_backend_overrides_brain_url(monkeypatch, tmp_path):
    # VEREL_MEMORY_BACKEND wins over the VEREL_BRAIN_URL back-compat shortcut.
    monkeypatch.setenv("VEREL_MEMORY_BACKEND", "local")
    monkeypatch.setenv("VEREL_BRAIN_URL", "https://brain.internal:8443")
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "b.db"))
    from verel.mcp_server import _brain
    assert isinstance(_brain(), LocalMemory)


# ---- entry-point plugins: discoverable, but built-ins win ------------------
class _DummyBackend:
    @classmethod
    def from_env(cls):
        return cls()


class _FakeEP:
    def __init__(self, name, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


def test_entrypoint_plugin_is_discoverable(monkeypatch):
    monkeypatch.setattr("verel.memory.registry._entry_points",
                        lambda group: [_FakeEP("dummy", _DummyBackend)])
    assert "dummy" in known_backends()
    assert isinstance(load_backend("dummy"), _DummyBackend)


def test_builtin_wins_over_plugin_of_same_name(monkeypatch):
    # A plugin must NOT be able to hijack a built-in name (security): `local` stays LocalMemory.
    assert "local" in _BUILTINS
    monkeypatch.setattr("verel.memory.registry._entry_points",
                        lambda group: [_FakeEP("local", _DummyBackend)])
    assert isinstance(load_backend("local"), LocalMemory)
