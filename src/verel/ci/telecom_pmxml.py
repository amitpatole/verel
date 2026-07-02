"""PM-XML adapter (3GPP TS 32.435 measCollecFile) → MetricFrame + a KPI-derivation pass.

The classic/appliance KPI path: EMS exports (ENM, NetAct in 32.435 mode) emit 15-minute ROP files of
RAW cumulative PM counters. This adapter parses them XXE-safely into `MetricSample`s keyed by canonical
counter id, and `derive_kpis()` computes the Phase-1 ratio KPI ids (`RRC.ConnEstabSuccRate`, …) so the
SAME `verel_kpi.yaml` thresholds work on Prometheus scrapes and PM-XML alike (one machinery).

Honest scope: PM-XML carries raw counters, never ratios — a zero denominator yields a sample with
`samples=0` (the insufficiency clamp makes it a non-gating WARNING, never a division error or a fake
100%). Vendor dialects (Ericsson MOM names, Huawei numeric ids) need a supplied mapping; unmapped
counters are kept verbatim as KPI ids (thresholds can still target them), never silently dropped.
"""

from __future__ import annotations

import re

from .telecom_model import MetricFrame, MetricSample, local_name, xml_root

_DUR = re.compile(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$")


def _duration_seconds(iso: str) -> int | None:
    m = _DUR.match((iso or "").strip())
    if not m or not any(m.groups()):
        return None
    h, mi, s = (int(x) if x else 0 for x in m.groups())
    return h * 3600 + mi * 60 + s


def _ldn_dims(ldn: str) -> dict[str, str]:
    """An RDN chain like 'ManagedElement=1,GNBDUFunction=1,NRCellDU=3' → dims."""
    dims: dict[str, str] = {"ldn": ldn[:512]}
    parts = dict(p.split("=", 1) for p in ldn.split(",") if "=" in p)
    for cls in ("NRCellDU", "NRCellCU", "EUtranCellFDD", "EUtranCellTDD"):
        if cls in parts:
            dims["cell"] = parts[cls]
    for cls in ("AMFFunction", "SMFFunction", "UPFFunction"):
        if cls in parts:
            dims["nf"] = parts[cls]
    return dims


def _num(v: str) -> float | None:
    v = (v or "").strip()
    if not v or v.upper() == "NIL":
        return None
    try:
        f = float(v)
    except ValueError:
        return None
    import math
    return f if math.isfinite(f) else None


def frame_from_pmxml(raw: str, mapping: dict[str, str] | None = None) -> MetricFrame:
    """Parse a TS 32.435 measCollecFile into raw-counter MetricSamples. Supports Form A (positional
    measTypes/measResults) and Form B (measType@p / r@p); a Form-A token-count mismatch fails closed."""
    root = xml_root(raw)
    m = mapping or {}
    samples: list[MetricSample] = []
    for md in _iter(root, "measData"):
        for mi in _children(md, "measInfo"):
            names = _meas_types(mi)  # {p_index: name}
            gp = _child(mi, "granPeriod")
            window = ""
            if gp is not None:
                window = f"{gp.attrib.get('endTime', '')}/{gp.attrib.get('duration', '')}"
            for mv in _children(mi, "measValue"):
                ldn = mv.attrib.get("measObjLdn", "")
                dims = _ldn_dims(ldn)
                suspect = (_text(mv, "suspect") or "").lower() == "true"
                for p_idx, val in _meas_results(mv, len(names)):
                    name = names.get(p_idx)
                    if name is None:
                        continue
                    fv = _num(val)
                    if fv is None:
                        continue
                    canon = m.get(name, name)  # identity for 28.552 names; unmapped kept verbatim
                    prov = f"measInfo[{mi.attrib.get('measInfoId', '')}] {ldn}"
                    samples.append(MetricSample(
                        kpi=canon, value=fv, dims=dims, window=window,
                        samples=0,  # raw counters carry no denominator; derive_kpis sets it on ratios
                        provenance=prov + (" [suspect]" if suspect else "")))
    return MetricFrame(samples=samples, source_sha=MetricFrame.digest(raw))


def _meas_types(mi: object) -> dict[int, str]:
    # Form B: <measType p="1">Name</measType> (repeatable). Form A: <measTypes>n1 n2 …</measTypes>.
    out: dict[int, str] = {}
    mts = _children(mi, "measType")
    if mts:
        for i, mt in enumerate(mts, 1):
            p = int(mt.attrib.get("p", i))
            out[p] = (mt.text or "").strip()
        return out
    block = _child(mi, "measTypes")
    if block is not None and block.text:
        for i, name in enumerate(block.text.split(), 1):
            out[i] = name
    return out


def _meas_results(mv: object, n_types: int) -> list[tuple[int, str]]:
    rs = _children(mv, "r")
    if rs:  # Form B
        return [(int(r.attrib.get("p", i)), (r.text or "")) for i, r in enumerate(rs, 1)]
    block = _child(mv, "measResults")
    if block is not None and block.text is not None:
        toks = block.text.split()
        if n_types and len(toks) != n_types:  # fail closed — never zip-truncate a positional mismatch
            raise ValueError(f"PM-XML measResults/measTypes length mismatch ({len(toks)} vs {n_types})")
        return [(i, tok) for i, tok in enumerate(toks, 1)]
    return []


# --- tiny local-name ElementTree helpers ---
def _children(el: object, name: str) -> list:
    return [c for c in el if local_name(c.tag) == name]  # type: ignore[attr-defined]


def _child(el: object, name: str):
    for c in el:  # type: ignore[attr-defined]
        if local_name(c.tag) == name:
            return c
    return None


def _text(el: object, name: str) -> str | None:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else None


def _iter(root: object, name: str) -> list:
    return [e for e in root.iter() if local_name(e.tag) == name]  # type: ignore[attr-defined]


# --- KPI derivation: raw counters → Phase-1 ratio KPI ids, per (dims, window) group ---
# ratio_kpi -> (numerator-counter-prefixes, denominator-counter-prefixes). Counters are summed over
# cause/5QI/S-NSSAI subcounter suffixes (a name equals the prefix or starts with prefix+".").
_RATIOS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "RRC.ConnEstabSuccRate": (("RRC.ConnEstabSucc",), ("RRC.ConnEstabAtt",)),
    "UECNTX.EstabSuccRate": (("UECNTX.ConnEstabSucc",), ("UECNTX.ConnEstabAtt",)),
    "MM.HoExeSuccRate": (("MM.HoExeInterSucc", "MM.HoExeIntraSucc"),
                         ("MM.HoExeInterReq", "MM.HoExeIntraReq")),
    "RM.RegInitSuccRate": (("RM.RegInitSucc",), ("RM.RegInitReq",)),
    "SM.PduSessionCreationSuccRate": (("SM.PduSessionCreationSucc",), ("SM.PduSessionCreationReq",)),
}


def _matches(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def derive_kpis(frame: MetricFrame) -> MetricFrame:
    """Return a NEW frame with the raw counters PLUS derived ratio KPIs (%). Each ratio is computed per
    (dims-key, window) group; `samples` = the integer denominator (feeds the min_samples clamp). A zero
    denominator → the ratio sample is emitted with samples=0 (insufficient), not 100%, not a crash."""
    groups: dict[tuple, list[MetricSample]] = {}
    for s in frame.samples:
        key = (tuple(sorted((k, v) for k, v in s.dims.items() if k != "ldn")), s.window)
        groups.setdefault(key, []).append(s)
    derived: list[MetricSample] = []
    for (dimkey, window), samps in groups.items():
        dims = dict(dimkey)
        # a suspect-flagged contributor makes the whole group unreliable → derived ratios get samples=0,
        # so a breach clamps to a non-gating WARNING WHEN the threshold sets min_samples>0 (with no
        # min_samples the operator has opted out of insufficiency handling and suspect data still gates).
        suspect = any(s.provenance.endswith("[suspect]") for s in samps)
        for kpi, (num_p, den_p) in _RATIOS.items():
            contributors = [s for s in samps if _matches(s.kpi, num_p) or _matches(s.kpi, den_p)]
            if not any(_matches(s.kpi, den_p) for s in samps):
                continue  # denominator counter absent → don't invent the KPI
            if any(s.value < 0 for s in contributors):
                continue  # a negative RAW counter is impossible → corrupt; check per-CONTRIBUTOR so a
                # negative sub-counter can't be laundered by a larger positive one (red-team R3)
            num = sum(s.value for s in samps if _matches(s.kpi, num_p))
            den = sum(s.value for s in samps if _matches(s.kpi, den_p))
            if num > den * (1.0 + 1e-9):
                continue  # impossible ratio (>100%) = corrupt counters → drop → KPI reads
                # "unmeasurable" (a non-gating WARNING via the absent-counter path), never a spurious PASS
            value = (num / den * 100.0) if den > 0 else 0.0
            derived.append(MetricSample(kpi=kpi, value=value, dims=dims, window=window,
                                        samples=0 if suspect else int(den),
                                        provenance=f"derived from {'+'.join(den_p)}"
                                                   + (" [suspect]" if suspect else "")))
    return MetricFrame(samples=frame.samples + derived, source_sha=frame.source_sha)
