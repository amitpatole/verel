"""Backend registry — the one place that turns a backend NAME into a `MemoryView`.

`load_backend("postgres")` resolves a built-in (or a third-party plugin) and calls its
`from_env()` factory, which reads operator env and lazy-imports its heavy dependency. This is
the seam that makes external DB stores out-of-the-box: `pip install verel[postgres]`, set
`VEREL_MEMORY_BACKEND=postgres` + a connection URL, no code.

Resolution order — **built-ins first**, on purpose:
  1. `_BUILTINS` (a static name→"module:attr" map). Fast, deterministic, editable-install-safe,
     and a malicious installed package CANNOT shadow a built-in backend name.
  2. the `verel.memory_backends` entry-point group — consulted only for names not built in,
     so third parties can register their own backends without touching verel.

Every backend object exposes `from_env() -> MemoryView` (a classmethod on the backend class).
`load_backend` resolves the class, then calls `.from_env()`. Listing known names never imports
a plugin (we read `ep.name`, we don't `.load()`); only the selected backend is imported.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .view import MemoryView

_ENTRY_POINT_GROUP = "verel.memory_backends"

# name -> "module:attr" of the backend class (which must expose a from_env() classmethod).
# Built-ins are resolved WITHOUT importing the heavy dep until from_env() runs. The external-DB
# backends (lancedb, postgres, redis) are added to this map as each ships in its own release.
_BUILTINS: dict[str, str] = {
    "local": "verel.memory.local:LocalMemory",
    "remote": "verel.memory.hosted:RemoteMemory",
    "postgres": "verel.memory.pg_backend:PostgresMemory",
    "lancedb": "verel.memory.lance_backend:LanceMemory",
}


def _import_target(target: str):
    """Resolve a 'module:attr' string to the attribute, importing the module lazily."""
    module_name, _, attr = target.partition(":")
    if not attr:
        raise ValueError(f"backend target {target!r} must be 'module:attr'")
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def _entry_points(group: str):
    """Yield the entry points in `group`, papering over the 3.10/3.11/3.12 API drift.

    Python 3.12+: `entry_points(group=...)` returns a selectable list.
    Python 3.10/3.11: `entry_points()` returns a dict keyed by group.
    We read names without loading targets, so listing never imports a plugin.
    """
    from importlib.metadata import entry_points

    if sys.version_info >= (3, 12):
        return list(entry_points(group=group))
    eps = entry_points()
    # 3.10 returns a dict; 3.11 added select() but the dict form still works.
    if hasattr(eps, "select"):
        return list(eps.select(group=group))
    return list(eps.get(group, []))  # type: ignore[attr-defined]


def _entry_point_factory(name: str) -> Callable[[], MemoryView] | None:
    for ep in _entry_points(_ENTRY_POINT_GROUP):
        if ep.name == name:
            cls = ep.load()
            return cls.from_env
    return None


def known_backends() -> list[str]:
    """Every selectable backend name (built-ins + registered plugins), without importing any."""
    names = set(_BUILTINS)
    for ep in _entry_points(_ENTRY_POINT_GROUP):
        names.add(ep.name)
    return sorted(names)


def load_backend(name: str) -> MemoryView:
    """Resolve `name` to a `MemoryView` via its `from_env()` factory.

    Built-ins win over plugins of the same name (so a name can't be hijacked). Raises a clear
    error naming the known backends when `name` is unknown. The backend's own `from_env()` is
    responsible for the missing-extra hint (`pip install verel[<name>]`) when its dep is absent.
    """
    target = _BUILTINS.get(name)
    if target is not None:
        cls = _import_target(target)
        return cls.from_env()
    factory = _entry_point_factory(name)
    if factory is not None:
        return factory()
    raise ValueError(f"unknown memory backend {name!r}; known: {known_backends()}")
