"""Drift-proof binding (§8.2): the 'reachable without a vision backend' set is imported
from agentvision source, never hand-transcribed. Skips cleanly if AgentVision isn't
installed (it's the optional `verel[sight]` extra)."""

import pytest

# The set the design pins as of writing — used only to detect SILENT upstream drift, so a
# human reviews the capability table when AgentVision changes its classic checks.
_DESIGN_PINNED = {"contrast", "overflow", "broken_image", "error_text", "typo", "blank", "other"}


def test_classic_capabilities_imported_from_source():
    sight = pytest.importorskip("verel.senses.sight")
    try:
        caps = sight.classic_capabilities()
    except ModuleNotFoundError:
        pytest.skip("agentvision not installed (verel[sight] extra)")
    assert isinstance(caps, set) and caps
    # NOT in the classic set — must require a vision backend (the silent-green guard).
    assert {"clipped", "overlap", "layout", "missing_element"}.isdisjoint(caps)


def test_pinned_set_matches_or_flags_drift():
    sight = pytest.importorskip("verel.senses.sight")
    try:
        caps = sight.classic_capabilities()
    except ModuleNotFoundError:
        pytest.skip("agentvision not installed (verel[sight] extra)")
    assert caps == _DESIGN_PINNED, (
        f"AgentVision CLASSIC_CAPABILITIES drifted from the design-pinned set: "
        f"added={caps - _DESIGN_PINNED}, removed={_DESIGN_PINNED - caps}. "
        f"Review verel.senses.sight + docs/VEREL_DESIGN.md §8.2 before updating the pin."
    )
