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


def test_readme_test_badge_not_understated():
    """The README test-count badge must not fall behind the real suite (it silently drifted 1025→1236,
    eroding the 'verified claims' pitch on the front door). Floor-guard: badge >= actual test functions,
    so adding tests without bumping the badge fails CI — a lockstep guard like the version one above."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    m = re.search(r"badge/tests-(\d+)", readme)
    assert m, "README test badge not found"
    badge = int(m.group(1))
    actual = sum(len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
                 for p in (root / "tests").glob("test_*.py"))
    assert badge >= actual, (
        f"README badge says {badge} tests but the suite has >= {actual} test functions — bump the badge "
        "(docs-lockstep). See tests/test_version_consistency.py.")
