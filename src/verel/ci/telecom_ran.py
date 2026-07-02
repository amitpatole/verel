"""RAN invariants (Phase 3) + the flagship RAN↔Core cross-check — pure functions over the canonical
`TelecomConfigModel` populated identically by the Helm and NETCONF-NRM adapters (one machinery).

Ships the tractable, high-value rules: `tac-plmn-consistency` (cross-domain), `pci-collision-confusion`,
`neighbor-symmetry`, `eirp-cap`. The deep-RF-math rules (`prach-root-nonoverlap`, `ssb-raster`) are a
documented follow-up — offline they need N_CS / GSCN table arithmetic that is error-prone without the
full RRC/38.104 context, and a half-right gate is worse than none.

Honesty (same discipline as the Core rules): checks DECLARED config only — declared neighbor relations,
declared TAIs, declared power — not RF planning or the running network. Missing fields → non-gating INFO.
"""

from __future__ import annotations

from ..verdict.models import IssueKind, Severity
from .telecom_issues import _SEV, _info, _mk
from .telecom_model import Cell, TelecomConfigModel, _as_int

RID_TACPLMN = "tac-plmn-consistency"
RID_PCI = "pci-collision-confusion"
RID_NBR = "neighbor-symmetry"
RID_EIRP = "eirp-cap"


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
        if c.name == ts or str(c.attrs.get("cellLocalId")) == ts \
                or c.name.endswith("=" + ts) or c.name.endswith("/" + ts):
            return c
    ti = _as_int(ts)  # a bare pci/id target → match by pci
    if ti is not None:
        for c in cells:
            if c.pci == ti:
                return c
    return None


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


# id → (fn, default_severity, clause, default_params); telecom_cfg wraps these into RuleDef entries.
RAN_RULES: dict[str, tuple] = {
    RID_TACPLMN: (rule_tac_plmn_consistency, "error", "TS 23.501 §5.3 / TS 24.501 §5.5.1.2.5",
                  {"require_amf_tai": False}),
    RID_PCI: (rule_pci_collision_confusion, "error", "TS 38.211 §7.4.2.1", {}),
    RID_NBR: (rule_neighbor_symmetry, "warning", "TS 28.541 / TS 32.511", {}),
    RID_EIRP: (rule_eirp_cap, "error", "TS 38.104 §6.2", {"licenses": []}),
}
