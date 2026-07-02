"""Exact 3GPP NR RF lookup tables + pure math for the RAN rules (prach-root-nonoverlap, ssb-raster).

Every constant here is transcribed from the primary spec and CROSS-VERIFIED by two independent passes
(a domain advisor + an adversarial web-research workflow, 3-0 agreement) — the N_RB grid additionally
validated against the guard-band physics + canonical anchors. A wrong value would make the gate quietly
incorrect, so each table is pinned by a unit test. Pure functions, no I/O; all frequency math is in
integer kHz (every quantity here is an exact integer number of kHz).

Standards baseline: TS 38.211 §6.3.3.1 (PRACH N_CS, Tables 6.3.3.1-5/-6/-7), TS 38.104 §5.4.2.1 (global
raster), §5.4.3.1 + Table 5.4.3.3-1/-2 (GSCN sync raster + per-band ranges), TS 38.101-1 Table 5.3.2-1
(FR1 N_RB). Rel-15/16 vocabulary.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- PRACH N_CS
# UNRESTRICTED set only (restricted sets A/B are a high-speed/Doppler decision not derivable offline).
# Indexed by zeroCorrelationZoneConfig 0..15.
_NCS_839_125 = [0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419]   # Table 6.3.3.1-5
_NCS_839_5 = [0, 13, 26, 33, 38, 41, 49, 55, 64, 76, 93, 119, 139, 209, 279, 419]    # Table 6.3.3.1-6 (fmt 3)
_NCS_139 = [0, 2, 4, 6, 8, 10, 12, 13, 15, 17, 19, 23, 27, 34, 46, 69]               # Table 6.3.3.1-7

_LONG_FORMATS = {"0", "1", "2", "3"}   # L_RA = 839
_SHORT_FORMATS = {"A1", "A2", "A3", "B1", "B2", "B3", "B4", "C0", "C2",
                  "A1/B1", "A2/B2", "A3/B3"}  # L_RA = 139


def l_ra_of(fmt: str | None) -> int | None:
    """839 (long) / 139 (short) from the preamble format; None if unknown."""
    if fmt is None:
        return None
    f = str(fmt).strip().upper()
    if f in _LONG_FORMATS:
        return 839
    if f in _SHORT_FORMATS:
        return 139
    return None


def ncs_of(fmt: str | None, zcz: int) -> int | None:
    """N_CS (unrestricted) for a preamble format + zeroCorrelationZoneConfig. Format 3 uses the ΔfRA=5
    kHz table (6.3.3.1-6), NOT the 1.25 kHz one — indexing it into 6.3.3.1-5 gives wrong root counts."""
    if fmt is None or not (0 <= zcz <= 15):
        return None
    f = str(fmt).strip().upper()
    if f == "3":
        return _NCS_839_5[zcz]
    if f in {"0", "1", "2"}:
        return _NCS_839_125[zcz]
    if f in _SHORT_FORMATS:
        return _NCS_139[zcz]
    return None


def roots_needed(l_ra: int, ncs: int) -> int:
    """Consecutive logical root sequences needed to enumerate all 64 preambles (TS 38.211 §6.3.3.1).
    N_CS=0 → no cyclic shift → 1 preamble/root → 64 roots."""
    per_root = (l_ra // ncs) if ncs > 0 else 1
    if per_root < 1:  # unreachable given the tables (max N_CS < L_RA), but stay defensive
        per_root = 1
    return -(-64 // per_root)  # ceil(64 / per_root)


def root_modulus(l_ra: int) -> int:
    """The logical-root wrap modulus: 838 physical ZC roots for L_RA=839, 138 for L_RA=139."""
    return 838 if l_ra == 839 else 138


def root_ranges_overlap(a: int, na: int, b: int, nb: int, mod: int) -> bool:
    """Wrap-aware overlap of two consecutive logical-root intervals [a, a+na) and [b, b+nb) mod `mod`.
    Exact for na, nb ≤ mod (guaranteed: roots_needed ≤ 64 < 138 ≤ mod)."""
    return ((b - a) % mod) < na or ((a - b) % mod) < nb


# --------------------------------------------------------------------------- NR-ARFCN → kHz
# (F_REF-Offs kHz, ΔF_Global kHz, N_REF-Offs, N_REF_min, N_REF_max) per TS 38.104 Table 5.4.2.1-1.
_ARFCN_RANGES = [
    (0, 5, 0, 0, 599999),
    (3_000_000, 15, 600000, 600000, 2016666),
    (24_250_080, 60, 2016667, 2016667, 3279165),
]


def arfcn_to_khz(n_ref: int | None) -> int | None:
    """NR-ARFCN → frequency in integer kHz; None if the ARFCN is outside 0..3279165 (malformed)."""
    if n_ref is None:
        return None
    for f_offs, dglobal, n_offs, lo, hi in _ARFCN_RANGES:
        if lo <= n_ref <= hi:
            return f_offs + dglobal * (n_ref - n_offs)
    return None


# --------------------------------------------------------------------------- GSCN sync raster
def gscn_of(khz: int | None) -> int | None:
    """The GSCN of a candidate SSB frequency (integer kHz) IFF it lands exactly on the synchronization
    raster (TS 38.104 §5.4.3.1); None otherwise. <3 GHz allows M∈{1,3,5}."""
    if khz is None:
        return None
    if khz < 3_000_000:
        for m in (1, 3, 5):
            base = khz - 50 * m
            if base >= 1200 and base % 1200 == 0:
                n = base // 1200
                if 1 <= n <= 2499:
                    return 3 * n + (m - 3) // 2
        return None
    if khz < 24_250_080:
        base = khz - 3_000_000
        if base % 1440 == 0 and 0 <= base // 1440 <= 14756:
            return 7499 + base // 1440
        return None
    base = khz - 24_250_080
    if base % 17280 == 0 and 0 <= base // 17280 <= 4383:
        return 22256 + base // 17280
    return None


# Per-band GSCN applicability (TS 38.104 Table 5.4.3.3-1/-2). "range": (first, last, step); "set": an
# explicit discrete list (n38@15kHz). Keyed by band then SSB SCS (kHz).
_BAND_GSCN: dict[str, dict[int, dict]] = {
    "n1": {15: {"range": (5279, 5419, 1)}},
    "n3": {15: {"range": (4517, 4693, 1)}},
    "n7": {15: {"range": (6554, 6718, 1)}},
    "n28": {15: {"range": (1901, 2002, 1)}},
    "n38": {15: {"set": [6432, 6443, 6457, 6468, 6479, 6493, 6507, 6518, 6532, 6543]},
            30: {"range": (6437, 6538, 1)}},
    "n41": {15: {"range": (6246, 6717, 3)}, 30: {"range": (6252, 6714, 3)}},
    "n77": {30: {"range": (7711, 8329, 1)}},
    "n78": {30: {"range": (7711, 8051, 1)}},
    "n79": {30: {"range": (8480, 8880, 16)}},
    "n257": {120: {"range": (22388, 22558, 1)}, 240: {"range": (22390, 22556, 2)}},
    "n258": {120: {"range": (22257, 22443, 1)}, 240: {"range": (22258, 22442, 2)}},
    "n260": {120: {"range": (22995, 23166, 1)}, 240: {"range": (22996, 23164, 2)}},
    "n261": {120: {"range": (22446, 22492, 1)}, 240: {"range": (22446, 22490, 2)}},
}


def band_known(band: str | None) -> bool:
    return bool(band) and str(band).strip().lower() in _BAND_GSCN


def gscn_in_band(band: str, gscn: int, ssb_scs: int | None) -> bool | None:
    """True/False if the GSCN is on `band`'s sync raster; None if the band/SCS row can't be resolved."""
    rows = _BAND_GSCN.get(str(band).strip().lower())
    if not rows:
        return None
    candidates = [rows[ssb_scs]] if (ssb_scs in rows) else list(rows.values())
    if not candidates:
        return None
    for spec in candidates:
        if "set" in spec:
            if gscn in spec["set"]:
                return True
        else:
            first, last, step = spec["range"]
            if first <= gscn <= last and (gscn - first) % step == 0:
                return True
    return False


# --------------------------------------------------------------------------- N_RB (FR1)
# TS 38.101-1 Table 5.3.2-1: max N_RB per (SCS kHz → {channel BW MHz: N_RB}). Undefined combos absent.
_NRB_FR1: dict[int, dict[int, int]] = {
    15: {5: 25, 10: 52, 15: 79, 20: 106, 25: 133, 30: 160, 40: 216, 50: 270},
    30: {5: 11, 10: 24, 15: 38, 20: 51, 25: 65, 30: 78, 40: 106, 50: 133, 60: 162, 80: 217, 90: 245,
         100: 273},
    60: {10: 11, 15: 18, 20: 24, 25: 31, 30: 38, 40: 51, 50: 65, 60: 79, 80: 107, 90: 121, 100: 135},
}
# TS 38.101-2 Table 5.3.2-1 (FR2).
_NRB_FR2: dict[int, dict[int, int]] = {
    60: {50: 66, 100: 132, 200: 264},
    120: {50: 32, 100: 66, 200: 132, 400: 264},
}


def nrb_max(channel_bw_mhz: int | None, scs_khz: int | None) -> int | None:
    """Max resource blocks for (channel BW, SCS); None if the combination is not defined in 38.101."""
    if channel_bw_mhz is None or scs_khz is None:
        return None
    return _NRB_FR1.get(scs_khz, {}).get(channel_bw_mhz) or _NRB_FR2.get(scs_khz, {}).get(channel_bw_mhz)
