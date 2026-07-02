"""RF-math RAN rules — prach-root-nonoverlap + ssb-raster, and the exact 3GPP tables they encode.

Every table value is pinned here (a wrong constant makes the gate quietly incorrect); the values were
cross-verified by two independent research passes and the N_RB grid against the guard-band physics.
"""
from __future__ import annotations

import pytest

pytest.importorskip("yaml", reason="telecom grader tests need verel[telecom]")
pytest.importorskip("defusedxml", reason="telecom XML tests need verel[telecom]")

from verel.ci import telecom_rf as rf
from verel.ci.telecom_model import Cell, TelecomConfigModel
from verel.ci.telecom_nrm import normalize_nrm_xml
from verel.ci.telecom_ran import rule_prach_root_nonoverlap, rule_ssb_raster
from verel.verdict.models import Severity


def _errs(issues):
    return [i for i in issues if i.severity == Severity.ERROR]


def _tcm(*cells):
    return TelecomConfigModel(cells=list(cells))


# --------------------------------------------------------------------------- exact tables (pinned)
def test_ncs_tables_exact():
    assert rf._NCS_839_125 == [0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419]
    assert rf._NCS_839_5 == [0, 13, 26, 33, 38, 41, 49, 55, 64, 76, 93, 119, 139, 209, 279, 419]
    assert rf._NCS_139 == [0, 2, 4, 6, 8, 10, 12, 13, 15, 17, 19, 23, 27, 34, 46, 69]
    # the format-3 split: formats 0/1/2 vs 3 diverge (index 2: 15 vs 26)
    assert rf.ncs_of("0", 2) == 15 and rf.ncs_of("3", 2) == 26
    assert rf.l_ra_of("3") == 839 and rf.l_ra_of("A1") == 139 and rf.l_ra_of("Z9") is None


def test_roots_needed_edges():
    assert rf.roots_needed(839, 13) == 1      # 64 preambles/root
    assert rf.roots_needed(839, 59) == 5      # ceil(64/14)
    assert rf.roots_needed(839, 0) == 64      # N_CS=0 → 1/root → 64 roots
    assert rf.roots_needed(139, 2) == 1 and rf.roots_needed(139, 69) == 32


def test_root_overlap_wraparound():
    # ranges [837,838,0] (start 837, len 3) and [0,1] must overlap mod 838
    assert rf.root_ranges_overlap(837, 3, 0, 2, 838) is True
    assert rf.root_ranges_overlap(0, 2, 10, 2, 838) is False


def test_arfcn_to_khz_three_ranges():
    assert rf.arfcn_to_khz(0) == 0
    assert rf.arfcn_to_khz(620352) == 3305280           # 3305.28 MHz (n78)
    assert rf.arfcn_to_khz(2016667) == 24250080          # FR2 boundary
    assert rf.arfcn_to_khz(3279166) is None              # out of range


def test_gscn_membership_and_anchors():
    assert rf.gscn_of(3305280) == 7711                   # on raster
    assert rf.gscn_of(3305281) is None                   # off raster (not a multiple of 1440)
    # <3GHz M∈{1,3,5}: N=2144,M=3 → 2 572 950 kHz → GSCN 6432
    assert rf.gscn_of(2144 * 1200 + 3 * 50) == 6432


def test_per_band_gscn():
    assert rf.gscn_in_band("n78", 7711, 30) is True
    assert rf.gscn_in_band("n41", 6246, 15) is True      # on step-3 grid
    assert rf.gscn_in_band("n41", 6247, 15) is False     # off step-3 grid
    assert rf.gscn_in_band("n38", 6432, 15) is True      # in the discrete set
    assert rf.gscn_in_band("n38", 6433, 15) is False     # not in the discrete set
    assert rf.gscn_in_band("n79", 8480, 30) is True and rf.gscn_in_band("n79", 8481, 30) is False
    assert rf.gscn_in_band("n258", 22257, 120) is True   # FR2
    assert rf.gscn_in_band("nZZ", 1, 30) is None


def test_nrb_grid_anchors_and_guardband_selfconsistent():
    assert rf.nrb_max(20, 15) == 106 and rf.nrb_max(100, 30) == 273 and rf.nrb_max(100, 60) == 135
    assert rf.nrb_max(5, 60) is None                     # undefined combo
    for scs, row in {**rf._NRB_FR1, **rf._NRB_FR2}.items():
        for bw, nrb in row.items():
            used = nrb * 12 * scs
            guard = (bw * 1000 - used) / 2 - scs / 2
            assert used < bw * 1000 and guard > 0, (scs, bw, nrb)


# --------------------------------------------------------------------------- prach-root-nonoverlap
def _prach_cell(name, gnb, root, zcz, fmt="0", arfcn=632628, neighbors=()):
    return Cell(name=name, gnb=gnb, arfcn_dl=arfcn,
                prach={"root": root, "zero_corr_zone": zcz, "format": fmt},
                neighbors=[{"target": n} for n in neighbors], loc=name)


def test_prach_same_site_overlap_gates():
    # zcz 0 → N_CS 0 → 64 roots each; roots 0 and 5 overlap heavily → ERROR (same gnb)
    a = _prach_cell("A", "g1", 0, 0)
    b = _prach_cell("B", "g1", 5, 0)
    assert any("overlap" in e.message for e in _errs(rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error"})))


def test_prach_no_overlap_passes():
    # zcz 15 → N_CS 419 → 32 roots; roots 0 and 500 are far apart (mod 838) → no overlap
    a = _prach_cell("A", "g1", 0, 15)
    b = _prach_cell("B", "g1", 500, 15)
    assert _errs(rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error"})) == []


def test_prach_different_freq_layer_skipped():
    a = _prach_cell("A", "g1", 0, 0, arfcn=632628)
    b = _prach_cell("B", "g1", 5, 0, arfcn=620000)   # different arfcn → cannot alias
    assert _errs(rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error"})) == []


def test_prach_neighbor_overlap_is_warning_not_error():
    a = _prach_cell("A", "g1", 0, 0, neighbors=["B"])
    b = _prach_cell("B", "g2", 5, 0)   # different gnb, but declared neighbor
    issues = rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error", "neighbor_severity": "warning"})
    assert _errs(issues) == [] and any(i.severity == Severity.WARNING for i in issues)


def test_prach_malformed_and_restricted():
    bad = _prach_cell("A", "g1", 9999, 0)   # root out of range (mod 838)
    assert _errs(rule_prach_root_nonoverlap(_tcm(bad), {"_severity": "error"}))
    rs = Cell(name="R", prach={"root": 1, "zero_corr_zone": 1, "format": "0", "restricted_set": "typeA"}, loc="r")
    issues = rule_prach_root_nonoverlap(_tcm(rs), {"_severity": "error"})
    assert any("restricted set" in i.message for i in issues) and _errs(issues) == []


# --------------------------------------------------------------------------- red-team R1 regressions
def test_prach_scales_no_cubic():
    # R1 HIGH: was O(n³) via _is_neighbor inside the pair loop (26s at n=400). Must be fast now.
    import time
    cells = [Cell(name=f"c{i}", gnb=f"g{i}", arfcn_dl=632628,
                  prach={"root": i % 800, "zero_corr_zone": 0, "format": "0"},
                  neighbors=[{"target": "unresolvable"}], loc=f"c{i}") for i in range(600)]
    t0 = time.monotonic()
    rule_prach_root_nonoverlap(_tcm(*cells), {"_severity": "error"})
    assert time.monotonic() - t0 < 3.0


def test_prach_oversize_cosite_fails_closed():
    # R2 fail-open fix: an implausibly large co-siting group must FAIL CLOSED (gating ERROR), never a
    # non-gating WARNING that lets a padded artifact escape the gate.
    from verel.ci.telecom_ran import _MAX_COSITE
    cells = [Cell(name=f"c{i}", gnb="g", arfcn_dl=1,
                  prach={"root": i % 838, "zero_corr_zone": 15, "format": "0"},  # valid roots (mod 838)
                  loc=f"c{i}") for i in range(_MAX_COSITE + 5)]
    errs = _errs(rule_prach_root_nonoverlap(_tcm(*cells), {"_severity": "error"}))
    assert any(e.detail.get("check") == "too-many-cosited" for e in errs)


def test_prach_padding_cannot_hide_real_overlap():
    # the concrete R2 attack: genuine same-site overlap + pad the layer past the cap → must NOT PASS
    from verel.ci.telecom_ran import _MAX_COSITE
    real = [_prach_cell("A", "g1", 0, 0), _prach_cell("B", "g1", 5, 0)]  # genuine same-gnb overlap
    pad = [_prach_cell(f"p{i}", "g1", i % 838, 15) for i in range(_MAX_COSITE + 5)]
    assert _errs(rule_prach_root_nonoverlap(_tcm(*real, *pad), {"_severity": "error"}))  # fails closed


def test_prach_dup_dn_not_deduped():
    # R2 LOW: two distinct co-sited overlapping cells sharing a DN must not collapse to one (identity-keyed)
    a = _prach_cell("same", "g1", 0, 0)
    b = _prach_cell("same", "g1", 5, 0)
    assert _errs(rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error"}))


def test_prach_missing_layer_infos_not_silent():
    # R2 LOW: a co-sited overlap with no arfcn_dl → surfaced as INFO, never silently dropped
    a = _prach_cell("A", "g1", 0, 0, arfcn=None)
    b = _prach_cell("B", "g1", 5, 0, arfcn=None)
    issues = rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error"})
    assert any(i.detail.get("check") == "no-layer" for i in issues)


def test_resolver_index_mirrors_resolve():
    # R3/R4 MEDIUM: the O(1) index must resolve EXACTLY the cell the linear _resolve would — incl.
    # cellLocalId ≠ DN-tail (R3) AND a multi-RDN DN suffix after ANY separator (R4). Else a neighbor
    # overlap is misrouted/missed.
    from verel.ci.telecom_ran import _resolve, _resolve_idx, _resolver_index
    real = Cell(name="ManagedElement=1/GNBDUFunction=2/NRCellDU=7", pci=101,
                attrs={"cellLocalId": "50"}, loc="real")
    decoy = Cell(name="ManagedElement=1/GNBDUFunction=3/NRCellDU=88", pci=102,
                 attrs={"cellLocalId": "7"}, loc="decoy")
    cells = [real, decoy]
    ridx = _resolver_index(cells)
    for target in ("7", "88", "NRCellDU=7", "GNBDUFunction=2/NRCellDU=7", "50", "101",
                   "ManagedElement=1/GNBDUFunction=2/NRCellDU=7"):
        assert _resolve_idx(target, ridx) is _resolve(target, cells), target


def test_resolver_index_differential_fuzz():
    # R4: a separator-heavy differential fuzz — the index must agree with _resolve on every target.
    import random

    from verel.ci.telecom_ran import _resolve, _resolve_idx, _resolver_index
    rng = random.Random(20260702)
    alpha = "ab=/12"
    for _ in range(4000):
        cells = [Cell(name="".join(rng.choice(alpha) for _ in range(rng.randint(1, 6))),
                      pci=rng.choice([None, 1, 2]),
                      attrs={"cellLocalId": rng.choice(["1", "2", "a"])} if rng.random() < 0.5 else {},
                      loc="x") for _ in range(rng.randint(1, 4))]
        ridx = _resolver_index(cells)
        t = "".join(rng.choice(alpha) for _ in range(rng.randint(1, 4)))
        assert _resolve_idx(t, ridx) is _resolve(t, cells), (t, [c.name for c in cells])


def test_resolver_index_bounded_on_pathological_name():
    # R5 HIGH: a name with thousands of separators must NOT be O(len²) — bounded build, no hang/OOM
    import time

    from verel.ci.telecom_ran import _resolver_index
    cells = [Cell(name="=" * 200000, loc="x")]
    t0 = time.monotonic()
    _resolver_index(cells)
    assert time.monotonic() - t0 < 2.0  # trie build is O(len); was ~23s / 20GB when materializing suffixes


def test_resolver_deep_dn_now_resolves_fully_faithful():
    # Phase-5 residual fix: the reversed-suffix trie indexes EVERY separator boundary, so a target that
    # is a suffix after an arbitrarily-deep (>8) separator resolves exactly as the linear _resolve —
    # the old last-8 bound dropped these (accepted fail-safe), now closed.
    from verel.ci.telecom_ran import _resolve, _resolve_idx, _resolver_index
    deep = "A=1/B=2/C=3/D=4/E=5/F=6/G=7/H=8/I=9/J=10/NRCellDU=x"  # 10 RDN levels (> 8 separators)
    cell = Cell(name=deep, loc="deep")
    cells = [cell]
    ridx = _resolver_index(cells)
    target = "1/B=2/C=3/D=4/E=5/F=6/G=7/H=8/I=9/J=10/NRCellDU=x"  # suffix after the deepest separator
    assert _resolve(target, cells) is cell
    assert _resolve_idx(target, ridx) is cell  # trie resolves it (last-8 bound would have returned None)


def test_resolver_none_target_parity():
    # R5 LOW: target "None" must not spuriously match a cellLocalId-absent cell (parity with _resolve)
    from verel.ci.telecom_ran import _resolve, _resolve_idx, _resolver_index
    cells = [Cell(name="me/g/NRCellDU=1", loc="x")]  # no cellLocalId attr
    assert _resolve("None", cells) is None
    assert _resolve_idx("None", _resolver_index(cells)) is None


def test_ssb_bwp_checked_even_without_ssb_frequency():
    # R5 LOW: an oversize BWP is an invariant independent of the SSB raster — must FAIL even if ssb absent
    c = Cell(name="c", channel_bw_mhz=100,  # N_RB 273 @ 30 kHz
             attrs={"bwps": [{"start_rb": 0, "num_rbs": 300, "scs_khz": 30}]}, loc="c")  # no ssb_frequency
    assert any(e.detail.get("check") == "bwp-fit" for e in _errs(rule_ssb_raster(_tcm(c), {"_severity": "error"})))


def test_prach_multi_rdn_dn_neighbor_overlap_caught():
    # R4 fail-open PoC: a sibling referenced by a multi-RDN DN must still be resolved → overlap caught
    a = Cell(name="ManagedElement=1/GNBDUFunction=1/NRCellDU=1", gnb="g1", arfcn_dl=100,
             prach={"root": 0, "zero_corr_zone": 0, "format": "0"},
             neighbors=[{"target": "GNBDUFunction=2/NRCellDU=7"}], loc="a")
    b = Cell(name="ManagedElement=1/GNBDUFunction=2/NRCellDU=7", gnb="g2", arfcn_dl=100,
             prach={"root": 40, "zero_corr_zone": 0, "format": "0"}, loc="b")
    issues = rule_prach_root_nonoverlap(_tcm(a, b), {"_severity": "error", "neighbor_severity": "error"})
    assert any("overlap" in e.message for e in _errs(issues))


def test_prach_neighbor_overlap_gating_when_configured_error():
    # R3: the fail-open case — a genuine neighbor overlap resolved via the ambiguous DN-tail must be
    # caught (and gate when neighbor_severity=error)
    c = _prach_cell("me/g1/NRCellDU=1", "g1", 0, 0, arfcn=100, neighbors=["7"])
    real = Cell(name="me/g2/NRCellDU=7", gnb="g2", arfcn_dl=100,
                prach={"root": 0, "zero_corr_zone": 0, "format": "0"},
                attrs={"cellLocalId": "50"}, loc="real")
    decoy = Cell(name="me/g3/NRCellDU=88", gnb="g3", arfcn_dl=200,
                 prach={"root": 400, "zero_corr_zone": 0, "format": "0"},
                 attrs={"cellLocalId": "7"}, loc="decoy")
    issues = rule_prach_root_nonoverlap(_tcm(c, real, decoy),
                                        {"_severity": "error", "neighbor_severity": "error"})
    assert any("overlap" in e.message for e in _errs(issues))


def test_prach_blank_gnb_cosited_still_checked():
    # R1 LOW: two NRCellDU directly under a ManagedElement (blank gnb) share the ME → co-sited → overlap
    m = normalize_nrm_xml("""<data><ManagedElement><id>me1</id>
<NRCellDU><id>1</id><attributes><nRPCI>1</nRPCI><arfcnDL>632628</arfcnDL>
<prachRootSequenceIndex>0</prachRootSequenceIndex><zeroCorrelationZoneConfig>0</zeroCorrelationZoneConfig>
<preambleFormat>0</preambleFormat><cellLocalId>1</cellLocalId></attributes></NRCellDU>
<NRCellDU><id>2</id><attributes><nRPCI>2</nRPCI><arfcnDL>632628</arfcnDL>
<prachRootSequenceIndex>5</prachRootSequenceIndex><zeroCorrelationZoneConfig>0</zeroCorrelationZoneConfig>
<preambleFormat>0</preambleFormat><cellLocalId>2</cellLocalId></attributes></NRCellDU>
</ManagedElement></data>""")
    assert any("overlap" in e.message for e in _errs(rule_prach_root_nonoverlap(m, {"_severity": "error"})))


def test_bwp_crb_relative_start_does_not_false_fail():
    # R1 LOW: a CRB-relative startRB (≥ N_RB) must not false-FAIL; only num_rbs > N_RB is impossible
    crb = Cell(name="c", ssb_frequency=620352, channel_bw_mhz=20,
               attrs={"band": "n78", "ssb_scs_khz": 30,
                      "bwps": [{"start_rb": 300, "num_rbs": 40, "scs_khz": 30}]}, loc="c")  # 300 ≥ N_RB 51
    assert not any(e.detail.get("check") == "bwp-fit" for e in _errs(rule_ssb_raster(_tcm(crb), {"_severity": "error"})))
    huge = Cell(name="d", ssb_frequency=620352, channel_bw_mhz=20,
                attrs={"band": "n78", "ssb_scs_khz": 30,
                       "bwps": [{"start_rb": 0, "num_rbs": 300, "scs_khz": 30}]}, loc="d")  # numRBs alone > 51
    assert any(e.detail.get("check") == "bwp-fit" for e in _errs(rule_ssb_raster(_tcm(huge), {"_severity": "error"})))


# --------------------------------------------------------------------------- ssb-raster
def test_ssb_off_raster_gates():
    c = Cell(name="c", ssb_frequency=620353, loc="c")   # 3305295 kHz — not a GSCN point
    assert _errs(rule_ssb_raster(_tcm(c), {"_severity": "error"}))


def test_ssb_on_raster_and_band_ok():
    c = Cell(name="c", ssb_frequency=620352, attrs={"band": "n78", "ssb_scs_khz": 30}, loc="c")
    assert _errs(rule_ssb_raster(_tcm(c), {"_severity": "error"})) == []


def test_ssb_band_range_violation_gates():
    # GSCN 7711 is valid raster but band n1 (5279..5419) does not include it
    c = Cell(name="c", ssb_frequency=620352, attrs={"band": "n1", "ssb_scs_khz": 15}, loc="c")
    assert any("band" in e.message for e in _errs(rule_ssb_raster(_tcm(c), {"_severity": "error"})))


def test_ssb_in_carrier_off_by_default_on_when_asserted():
    # SSB deliberately outside a narrow carrier; default (centre not asserted) → no ERROR; asserted → ERROR
    c = Cell(name="c", ssb_frequency=620352, arfcn_dl=600000, channel_bw_mhz=5,
             attrs={"ssb_scs_khz": 30}, loc="c")
    assert not any(i.detail.get("check") == "in-carrier" and i.severity == Severity.ERROR
                   for i in rule_ssb_raster(_tcm(c), {"_severity": "error"}))
    on = rule_ssb_raster(_tcm(c), {"_severity": "error", "arfcn_is_centre": True})
    assert any(i.detail.get("check") == "in-carrier" and i.severity == Severity.ERROR for i in on)


def test_ssb_bwp_fit_and_undefined_combo():
    over = Cell(name="c", ssb_frequency=620352, channel_bw_mhz=20,
                attrs={"band": "n78", "ssb_scs_khz": 30, "bwps": [{"start_rb": 0, "num_rbs": 300, "scs_khz": 30}]},
                loc="c")   # 300 > N_RB 51 for 20MHz@30k
    assert any("BWP" in e.message for e in _errs(rule_ssb_raster(_tcm(over), {"_severity": "error"})))
    undef = Cell(name="d", ssb_frequency=620352, channel_bw_mhz=5,
                 attrs={"ssb_scs_khz": 30, "bwps": [{"start_rb": 0, "num_rbs": 1, "scs_khz": 60}]}, loc="d")
    assert any("not a defined combination" in e.message for e in _errs(rule_ssb_raster(_tcm(undef), {"_severity": "error"})))


# --------------------------------------------------------------------------- end-to-end via NRM
def test_ran_rules_registered():
    from verel.ci.telecom_cfg import BUILTIN_RULES
    assert {"prach-root-nonoverlap", "ssb-raster"} <= set(BUILTIN_RULES)


def test_ssb_raster_end_to_end_nrm():
    m = normalize_nrm_xml("""<data><ManagedElement><id>g</id><GNBDUFunction><id>1</id>
<NRCellDU><id>1</id><attributes><nRPCI>1</nRPCI><ssbFrequency>620353</ssbFrequency>
<cellLocalId>1</cellLocalId></attributes></NRCellDU></GNBDUFunction></ManagedElement></data>""")
    assert _errs(rule_ssb_raster(m, {"_severity": "error"}))   # 620353 is off-raster
