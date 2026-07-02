"""RAN invariants (Phase 3) + the flagship RAN↔Core cross-check — pure functions over the canonical
`TelecomConfigModel` populated identically by the Helm and NETCONF-NRM adapters (one machinery).

Rules: `tac-plmn-consistency` (cross-domain), `pci-collision-confusion`, `neighbor-symmetry`, `eirp-cap`,
and the RF-math pair `prach-root-nonoverlap` + `ssb-raster` (exact 3GPP tables in `telecom_rf`,
cross-verified by two independent research passes).

Honesty (same discipline as the Core rules): checks DECLARED config only — declared neighbor relations,
declared TAIs, declared power — not RF planning or the running network. Missing fields → non-gating INFO.
"""

from __future__ import annotations

from collections import defaultdict

from ..verdict.models import IssueKind, Severity
from .telecom_issues import _SEV, _info, _mk
from .telecom_model import Cell, TelecomConfigModel, _as_int
from .telecom_rf import (
    arfcn_to_khz,
    band_known,
    gscn_in_band,
    gscn_of,
    l_ra_of,
    ncs_of,
    nrb_max,
    root_modulus,
    root_ranges_overlap,
    roots_needed,
)

RID_TACPLMN = "tac-plmn-consistency"
RID_PCI = "pci-collision-confusion"
RID_NBR = "neighbor-symmetry"
RID_EIRP = "eirp-cap"
RID_PRACH = "prach-root-nonoverlap"
RID_SSB = "ssb-raster"


# ---------------------------------------------------------------- flagship cross-domain rule
def rule_tac_plmn_consistency(tcm: TelecomConfigModel, params: dict) -> list:
    """Every (PLMN, TAC) a gNB broadcasts must be in some AMF's served-TAI list — else UEs get
    Registration Reject 'tracking area not allowed' (5GMM cause #12). Reads ONLY cells{plmns,tac} and
    NF(AMF).attrs[served_tais]; both adapters fill those, so it fires identically on Helm and NRM."""
    sev = _SEV[params["_severity"]]
    broadcast = [(p, c.tac, c) for c in tcm.cells for p in c.plmns if c.tac is not None]
    if not broadcast:
        return []  # no RAN in the artifact → rule inert
    served: set[tuple[str, int]] = set()
    amfs = tcm.of_kind("AMF")
    for amf in amfs:
        for tai in amf.attrs.get("served_tais", []) or []:
            served.add((tai["plmn"], tai["tac"]))
    out: list = []
    if not served:
        w = sev if params.get("require_amf_tai") else Severity.WARNING
        out.append(_mk(RID_TACPLMN, "no-amf-tai", w, IssueKind.CROSS_NF_MISMATCH,
                       f"{RID_TACPLMN}: gNB broadcasts TAIs but no AMF served-TAI list is declared — "
                       "cannot verify registration reachability (TS 38.413 §8.7)", broadcast[0][2].loc))
        return out
    seen: set[tuple[str, int]] = set()
    for plmn, tac, cell in broadcast:
        if (plmn, tac) in served or (plmn, tac) in seen:
            continue
        seen.add((plmn, tac))
        out.append(_mk(RID_TACPLMN, "tai-not-served", sev, IssueKind.CROSS_NF_MISMATCH,
                       f"{RID_TACPLMN}: cell {cell.name} broadcasts TAI ({plmn}, TAC {tac}) not served by "
                       "any AMF — UEs here get Registration Reject 'tracking area not allowed' (5GMM "
                       "cause #12) (TS 23.501 §5.3, TS 24.501 §5.5.1.2.5)", cell.loc, plmn=plmn, tac=tac))
    return out


# ---------------------------------------------------------------- PCI collision / confusion
def _resolve(target: object, cells: list[Cell]) -> Cell | None:
    ts = str(target).strip()
    for c in cells:
        cl = c.attrs.get("cellLocalId")
        if c.name == ts or (cl is not None and str(cl) == ts) \
                or c.name.endswith("=" + ts) or c.name.endswith("/" + ts):
            return c
    ti = _as_int(ts)  # a bare pci/id target → match by pci
    if ti is not None:
        for c in cells:
            if c.pci == ti:
                return c
    return None


_MAX_DN_SUFFIXES = 8  # index only the last N RDN-suffixes of a name (a real DN has ≤ ~5 separators)


def _resolver_index(cells: list[Cell]) -> dict:
    """O(1) neighbor-resolution index that FAITHFULLY mirrors `_resolve` — avoids its O(n²) per-neighbor
    scan (red-team R2) without the criterion-priority divergence that missed overlaps (red-team R3). Each
    key stores the (list_index, cell) of the FIRST cell to claim it; lookup returns the earliest cell
    across all criteria, exactly as `_resolve`'s first-cell-wins linear scan would."""
    idx: dict = {}
    for i, c in enumerate(cells):
        idx.setdefault(("n", c.name), (i, c))
        cl = c.attrs.get("cellLocalId")
        if cl is not None:
            idx.setdefault(("cl", str(cl)), (i, c))
        # `_resolve` matches ts via name.endswith("=" + ts) / ("/" + ts) — ts is the suffix after any
        # separator. Index the last _MAX_DN_SUFFIXES boundaries (covers multi-RDN DN references, red-team
        # R4) but NOT every boundary — materializing all suffixes is O(len²) and a name with thousands of
        # separators is a DoS (red-team R5). Bounded to O(len·k); an exotic >8-deep DN target at most
        # misses a neighbor WARNING (co-sited ERRORs use the group path, not the resolver — fail-safe).
        seps = [k for k, ch in enumerate(c.name) if ch in ("=", "/")]
        for k in seps[-_MAX_DN_SUFFIXES:]:
            idx.setdefault(("tok", c.name[k + 1:]), (i, c))
        if c.pci is not None:
            idx.setdefault(("pci", c.pci), (i, c))
    return idx


def _resolve_idx(target: object, idx: dict) -> Cell | None:
    ts = str(target).strip()
    cands = [idx[k] for k in (("n", ts), ("cl", ts), ("tok", ts)) if k in idx]
    if cands:
        return min(cands, key=lambda t: t[0])[1]  # earliest cell across criteria (mirrors _resolve)
    ti = _as_int(ts)
    entry = idx.get(("pci", ti)) if ti is not None else None
    return entry[1] if entry else None


def rule_pci_collision_confusion(tcm: TelecomConfigModel, params: dict) -> list:
    sev = _SEV[params["_severity"]]
    cells = tcm.cells
    out: list = []
    unresolved = 0
    for c in cells:
        if c.pci is not None and not (0 <= c.pci <= 1007):
            out.append(_mk(RID_PCI, "pci-range", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_PCI}: cell {c.name} PCI {c.pci} out of range 0..1007 (TS 38.211 §7.4.2.1)",
                           f"{c.loc}/nRPCI"))
        elif c.attrs.get("pci_invalid") is not None:  # declared but not an integer → don't skip silently
            out.append(_mk(RID_PCI, "pci-invalid", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_PCI}: cell {c.name} PCI {c.attrs['pci_invalid']!r} is not an integer "
                           "(TS 38.211 §7.4.2.1)", f"{c.loc}/nRPCI"))
    seen_pairs: set[tuple[str, str]] = set()
    for c in cells:
        confusion: dict[int, str] = {}
        for nb in c.neighbors:
            t = _resolve(nb["target"], cells)
            if t is None:
                unresolved += 1
                continue
            if c.pci is not None and t.pci == c.pci:  # collision: a cell and a declared neighbor share PCI
                key = tuple(sorted((c.name, t.name)))
                if key not in seen_pairs:
                    seen_pairs.add(key)  # type: ignore[arg-type]
                    out.append(_mk(RID_PCI, "collision", sev, IssueKind.INVARIANT_VIOLATION,
                                   f"{RID_PCI}: cells {c.name} and {t.name} are declared neighbors and "
                                   f"share PCI {c.pci} (collision) (TS 28.541 NRCellRelation)", c.loc))
            if t.pci is not None:  # confusion: two distinct neighbors of c share a PCI
                if t.pci in confusion and confusion[t.pci] != t.name:
                    out.append(_mk(RID_PCI, "confusion", sev, IssueKind.INVARIANT_VIOLATION,
                                   f"{RID_PCI}: cell {c.name} has two neighbors ({confusion[t.pci]}, "
                                   f"{t.name}) with the same PCI {t.pci} (confusion — ambiguous HO target)",
                                   c.loc))
                confusion[t.pci] = t.name
    if unresolved:
        out.append(_info(RID_PCI, "external-neighbors",
                         f"{unresolved} neighbor relation(s) reference cells not in this artifact"))
    return out


# ---------------------------------------------------------------- neighbor symmetry
def rule_neighbor_symmetry(tcm: TelecomConfigModel, params: dict) -> list:
    sev = _SEV[params["_severity"]]  # default warning
    cells = tcm.cells
    out: list = []
    # index declared directed relations by (source cell, resolved target cell)
    edges: set[tuple[str, str]] = set()
    for c in cells:
        for nb in c.neighbors:
            t = _resolve(nb["target"], cells)
            if t is not None:
                edges.add((c.name, t.name))
    for c in cells:
        seen_targets: dict[str, object] = {}
        for nb in c.neighbors:
            t = _resolve(nb["target"], cells)
            if t is None:
                continue
            if (t.name, c.name) not in edges:  # asymmetry: A→B declared but no B→A
                out.append(_mk(RID_NBR, "asymmetry", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_NBR}: {c.name} → {t.name} is declared but the reverse relation is "
                               "not (asymmetric Xn neighbor) (TS 28.541 / ANR TS 32.511)",
                               nb.get("loc", c.loc)))
            # contradiction: the same neighbor declared twice with conflicting ho_allowed
            if t.name in seen_targets and seen_targets[t.name] != nb.get("ho_allowed"):
                out.append(_mk(RID_NBR, "contradiction", Severity.ERROR, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_NBR}: {c.name} → {t.name} declared twice with conflicting "
                               "isHOAllowed", nb.get("loc", c.loc)))
            seen_targets[t.name] = nb.get("ho_allowed")
    return out


# ---------------------------------------------------------------- EIRP cap
def rule_eirp_cap(tcm: TelecomConfigModel, params: dict) -> list:
    sev = _SEV[params["_severity"]]
    licenses = params.get("licenses") or []
    if not licenses:
        return [_info(RID_EIRP, "no-license",
                      "no licensed EIRP declared (params.licenses) — cannot check a legal limit")]
    import fnmatch
    out: list = []
    for c in tcm.cells:
        for lic in licenses:
            if not isinstance(lic, dict):
                continue
            cap = lic.get("max_eirp_dbm")
            if cap is None:
                continue
            glob = lic.get("cell_glob")
            band = lic.get("band")
            if glob and not fnmatch.fnmatch(c.name, str(glob)):
                continue
            if band:
                cell_band = str(c.attrs.get("band", ""))
                if not cell_band:  # band not derivable from the artifact → don't silently skip the gate
                    out.append(_info(RID_EIRP, "band", f"license scoped to band {band} but {c.name} "
                                     "declares no band — cannot apply", c.loc))
                    continue
                if cell_band != str(band):
                    continue
            configured = c.attrs.get("configured_max_eirp_dbm")
            if configured is not None:
                eirp = float(configured)
            elif c.max_tx_power_dbm is not None:
                gain = float(lic.get("antenna_gain_dbi", 0))
                loss = float(lic.get("feeder_loss_db", 0))
                eirp = c.max_tx_power_dbm + gain - loss
            else:
                out.append(_info(RID_EIRP, "no-power", f"no TX power for {c.name}", c.loc))
                continue
            if eirp > float(cap):
                out.append(_mk(RID_EIRP, "eirp", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_EIRP}: cell {c.name} EIRP {eirp:g} dBm > licensed {cap} dBm "
                               "(TS 38.104 §6.2; operator-declared limit)", c.loc))
    return out


# ---------------------------------------------------------------- PRACH root non-overlap
_UNRESTRICTED = {"", "unrestricted", "unrestrictedset", "typeunrestricted"}


def rule_prach_root_nonoverlap(tcm: TelecomConfigModel, params: dict) -> list:
    """Two co-sited / neighbor cells on the same frequency layer must not use overlapping PRACH logical
    root-sequence ranges (they'd share preambles → false detections). Root count comes from N_CS (TS
    38.211 §6.3.3.1); the format-3 ΔfRA=5 kHz table is distinct from formats 0/1/2. Checks DECLARED root/
    zcz only — not msg1 frequency/time separation, not restricted sets, not zcz-vs-cell-radius suitability.
    Because msg1 FDM/time offsets are unmodeled, neighbor-only overlaps default to WARNING (a same-site
    overlap is the hard error)."""
    sev = _SEV[params["_severity"]]
    nbr_sev = _SEV.get(str(params.get("neighbor_severity", "warning")), Severity.WARNING)
    cells = tcm.cells
    out: list = []
    occ: list[tuple] = []  # index-keyed (NOT by name — two NRCellDU can share a DN); (cell,l_ra,root,n,mod)
    underivable = 0
    for c in cells:
        p = c.prach or {}
        root, zcz, fmt = p.get("root"), p.get("zero_corr_zone"), p.get("format")
        if root is None or zcz is None:
            continue  # not a PRACH-configured cell in this artifact
        if str(p.get("restricted_set", "")).strip().lower() not in _UNRESTRICTED:
            out.append(_info(RID_PRACH, "restricted-set",
                             f"{c.name}: restricted set configured — root-overlap check skipped", c.loc))
            continue
        l_ra = l_ra_of(fmt)
        ncs = ncs_of(fmt, zcz) if l_ra is not None else None
        if l_ra is None or ncs is None:
            underivable += 1
            continue
        mod = root_modulus(l_ra)
        if not (0 <= root < mod) or not (0 <= zcz <= 15):
            out.append(_mk(RID_PRACH, "prach-domain", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_PRACH}: {c.name} PRACH root {root}/zcz {zcz} out of range "
                           f"(root 0..{mod - 1}, zcz 0..15) (TS 38.211 §6.3.3.1)", c.loc))
            continue
        occ.append((c, l_ra, root, roots_needed(l_ra, ncs), mod))
    if underivable:
        out.append(_info(RID_PRACH, "format",
                         f"{underivable} cell(s) declare PRACH root/zcz but no derivable preamble format"))
    # Candidate pairs come ONLY from co-siting groups + the neighbor adjacency (sparse) — a full same-layer
    # sweep was O(m²) with a non-gating over-cap escape (red-team R2 fail-open). A cell with no arfcn_dl
    # can't establish a frequency layer → non-gating INFO (never silently dropped). A single co-siting
    # group larger than _MAX_COSITE (a gNB with hundreds of cells on ONE layer) is implausible/malicious →
    # fail CLOSED at the gating severity, so padding can't buy a PASS.
    idx_of = {id(t[0]): i for i, t in enumerate(occ)}
    pairs: set[tuple[int, int]] = set()
    groups: dict[tuple, list[int]] = defaultdict(list)
    no_layer = 0
    for i, (c, la, _ra, _na, _ma) in enumerate(occ):
        if c.arfcn_dl is None:
            no_layer += 1
            continue
        groups[(_cosite(c), la, c.arfcn_dl)].append(i)
    if no_layer:
        out.append(_info(RID_PRACH, "no-layer",
                         f"{no_layer} PRACH cell(s) have no arfcn_dl (frequency layer) — not checked"))
    for gkey, idxs in groups.items():
        if len(idxs) > _MAX_COSITE:
            out.append(_mk(RID_PRACH, "too-many-cosited", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_PRACH}: {len(idxs)} co-sited cells on one layer (> {_MAX_COSITE}) at "
                           f"{gkey[0]} — implausible; cannot verify PRACH roots (failing closed)"))
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                pairs.add((idxs[a], idxs[b]))
    ridx = _resolver_index(cells)  # O(1) neighbor lookup — not O(n) per neighbor (R2 DoS)
    for i, (c, _la, _ra, _na, _ma) in enumerate(occ):
        for nb in c.neighbors:
            t = _resolve_idx(nb["target"], ridx)
            j = idx_of.get(id(t)) if t is not None else None
            if j is not None and j != i:
                pairs.add((min(i, j), max(i, j)))
    for i, j in pairs:
        ca, la, ra, na, ma = occ[i]
        cb, lb, rb, nb, _mb = occ[j]
        if la != lb or ca.arfcn_dl is None or ca.arfcn_dl != cb.arfcn_dl:
            continue  # different preamble length or frequency layer → cannot alias
        same_gnb = _cosite(ca) != "" and _cosite(ca) == _cosite(cb)
        if root_ranges_overlap(ra, na, rb, nb, ma):
            out.append(_mk(RID_PRACH, "root-overlap", sev if same_gnb else nbr_sev,
                           IssueKind.CROSS_NF_MISMATCH,
                           f"{RID_PRACH}: {ca.name} (root {ra}, +{na}) and {cb.name} (root {rb}, "
                           f"+{nb}) have overlapping PRACH root ranges (TS 38.211 §6.3.3.1)",
                           ca.loc, other=cb.loc))
    return out


# A gNB with more than this many cells on ONE frequency layer is implausible (sectors are few) → a group
# this large is treated as malformed/adversarial and fails closed rather than being swept O(m²).
_MAX_COSITE = 256


def _cosite(c: Cell) -> str:
    """The co-siting key: the gNB. Falls back to the gNBId attr or the ManagedElement prefix of the name
    so two NRCellDU placed directly under a ManagedElement (blank `gnb`) still count as co-sited."""
    return c.gnb or str(c.attrs.get("gnb_id", "")) or c.name.rsplit("/NRCellDU=", 1)[0]


# ---------------------------------------------------------------- SSB raster
def rule_ssb_raster(tcm: TelecomConfigModel, params: dict) -> list:
    """The SSB must sit on the NR synchronization raster (a valid GSCN), within the band's GSCN range,
    and its BWPs must fit the carrier's N_RB (TS 38.104 §5.4.3.1 / TS 38.101-1 Table 5.3.2-1). The
    SSB-in-carrier sub-check needs `arfcn_dl` to be the carrier CENTRE (not Point A) — off by default;
    set params.arfcn_is_centre=true to enable, else it is skipped (a Point-A value would false-FAIL).
    Not checked: kSSB / offsetToPointA / CORESET#0 alignment (needs MIB fields not in the model)."""
    sev = _SEV[params["_severity"]]
    out: list = []
    for c in tcm.cells:
        _ssb_bwp_check(c, sev, out)  # BWP-fit is independent of the SSB raster — run it even if ssb absent
        if c.ssb_frequency is None:
            continue
        khz = arfcn_to_khz(c.ssb_frequency)
        if khz is None:
            out.append(_mk(RID_SSB, "arfcn", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SSB}: {c.name} ssbFrequency {c.ssb_frequency} is not a valid NR-ARFCN "
                           "(0..3279165) (TS 38.104 §5.4.2.1)", c.loc))
            continue
        gscn = gscn_of(khz)
        if gscn is None:
            out.append(_mk(RID_SSB, "sync-raster", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SSB}: {c.name} SSB ({khz / 1000:g} MHz) is not on the synchronization "
                           "raster (no valid GSCN) (TS 38.104 §5.4.3.1)", f"{c.loc}/ssbFrequency"))
            continue  # GSCN undefined → band/carrier sub-checks can't run meaningfully
        scs = c.attrs.get("ssb_scs_khz")
        _ssb_band_check(c, gscn, scs, sev, out)
        _ssb_in_carrier_check(c, khz, scs, sev, params, out)
    return out


def _ssb_band_check(c: Cell, gscn: int, scs, sev: Severity, out: list) -> None:
    band = c.attrs.get("band")
    if not band_known(band):
        out.append(_info(RID_SSB, "band",
                         f"{c.name}: band not declared/known — GSCN range not checked", c.loc))
        return
    ok = gscn_in_band(str(band), gscn, scs if isinstance(scs, int) else None)
    if ok is None:
        out.append(_info(RID_SSB, "band-scs", f"{c.name}: band {band} SSB-SCS row not resolvable", c.loc))
    elif not ok:
        out.append(_mk(RID_SSB, "band-range", sev, IssueKind.INVARIANT_VIOLATION,
                       f"{RID_SSB}: {c.name} GSCN {gscn} is not on band {band}'s sync raster "
                       "(TS 38.104 Table 5.4.3.3-1)", f"{c.loc}/ssbFrequency"))


def _ssb_in_carrier_check(c: Cell, khz: int, scs, sev: Severity, params: dict, out: list) -> None:
    if not params.get("arfcn_is_centre"):
        return  # off by default: arfcn_dl may be Point A, not centre — would false-FAIL
    if c.arfcn_dl is None or c.channel_bw_mhz is None or not isinstance(scs, int):
        out.append(_info(RID_SSB, "in-carrier", f"{c.name}: arfcn_dl/channel_bw/ssb_scs missing", c.loc))
        return
    centre = arfcn_to_khz(c.arfcn_dl)
    if centre is None:
        return
    ssb_low, ssb_high = khz - 120 * scs, khz + 120 * scs  # 20-RB SSB block, ±half-SC conservative
    car_low, car_high = centre - c.channel_bw_mhz * 500, centre + c.channel_bw_mhz * 500
    if ssb_low < car_low or ssb_high > car_high:
        out.append(_mk(RID_SSB, "in-carrier", sev, IssueKind.INVARIANT_VIOLATION,
                       f"{RID_SSB}: {c.name} SSB block [{ssb_low}..{ssb_high}] kHz falls outside the "
                       f"carrier [{car_low}..{car_high}] kHz (TS 38.104 §5.4.3.1)", c.loc))


def _ssb_bwp_check(c: Cell, sev: Severity, out: list) -> None:
    for bwp in (c.attrs.get("bwps") or []):
        if not isinstance(bwp, dict):
            continue  # both adapters emit dicts; stay total for hand-built models
        scs, start, nrb = bwp.get("scs_khz"), bwp.get("start_rb"), bwp.get("num_rbs")
        if c.channel_bw_mhz is None or scs is None:
            continue
        cap = nrb_max(c.channel_bw_mhz, scs)
        if cap is None:
            out.append(_mk(RID_SSB, "bwp-scs", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SSB}: {c.name} BWP SCS {scs} kHz / BW {c.channel_bw_mhz} MHz is not a "
                           "defined combination (TS 38.101-1 Table 5.3.2-1)",
                           f"{c.loc}/{bwp.get('loc', '')}"))
        elif nrb is not None and nrb > cap:  # num_rbs alone > N_RB is impossible under ANY offset semantics
            out.append(_mk(RID_SSB, "bwp-fit", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SSB}: {c.name} BWP numRBs {nrb} exceeds N_RB {cap} for "
                           f"{c.channel_bw_mhz} MHz @ {scs} kHz (TS 38.101-1 Table 5.3.2-1)",
                           f"{c.loc}/{bwp.get('loc', '')}"))
        elif start is not None and nrb is not None and 0 <= start < cap and start + nrb > cap:
            # carrier-relative startRB (0..N_RB) overflows; a startRB ≥ N_RB is likely CRB-relative
            # (a common-resource-grid offset) → don't false-FAIL on it (red-team R1 LOW).
            out.append(_mk(RID_SSB, "bwp-fit", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SSB}: {c.name} BWP startRB+numRBs ({start}+{nrb}) exceeds N_RB {cap} for "
                           f"{c.channel_bw_mhz} MHz @ {scs} kHz (TS 38.101-1 Table 5.3.2-1)",
                           f"{c.loc}/{bwp.get('loc', '')}"))


# id → (fn, default_severity, clause, default_params); telecom_cfg wraps these into RuleDef entries.
RAN_RULES: dict[str, tuple] = {
    RID_TACPLMN: (rule_tac_plmn_consistency, "error", "TS 23.501 §5.3 / TS 24.501 §5.5.1.2.5",
                  {"require_amf_tai": False}),
    RID_PCI: (rule_pci_collision_confusion, "error", "TS 38.211 §7.4.2.1", {}),
    RID_NBR: (rule_neighbor_symmetry, "warning", "TS 28.541 / TS 32.511", {}),
    RID_EIRP: (rule_eirp_cap, "error", "TS 38.104 §6.2", {"licenses": []}),
    RID_PRACH: (rule_prach_root_nonoverlap, "error", "TS 38.211 §6.3.3.1", {"neighbor_severity": "warning"}),
    RID_SSB: (rule_ssb_raster, "error", "TS 38.104 §5.4.3.1", {"arfcn_is_centre": False}),
}
