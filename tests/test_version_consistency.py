"""Guard: code __version__ must match installed package metadata (prevents the pyproject-vs-__init__
drift). Skips if not installed as a distribution."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

import pytest

import verel


def test_version_matches_metadata():
    try:
        meta = version("verel")
    except PackageNotFoundError:
        pytest.skip("verel not installed as a distribution")
    assert verel.__version__ == meta
