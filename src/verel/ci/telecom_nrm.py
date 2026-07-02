"""NETCONF / 3GPP TS 28.541 NRM adapter (Phase 3, classic/appliance path) → TelecomConfigModel.

Projects a NETCONF `<get-config>` reply / NRM XML export into the SAME canonical model the Open5GS Helm
adapter fills (`telecom_cfg.normalize_helm_values`) — cells + NFs + AMF served-TAIs — so the identical
rule bodies (S-NSSAI consistency, tac-plmn-consistency, the RAN rules) grade both worlds. That shared
model is the "one machinery" proof.

Parsing is XXE-safe via `telecom_model.xml_root` (DTD/entities/external all forbidden, bounded). Element
matching is by LOCAL name — vendor MOMs rename the `urn:3gpp:sa5:*` namespaces but keep the 28.541 tree.

Honest scope: several fields are vendor extensions to the standard NRM (PRACH config lives in RRC, and
an AMF served-TAI list is authoritatively runtime NG-Setup content, not a standard AMFFunction attribute)
— where absent, the rules emit non-gating INFO, never a false FAIL.
"""

from __future__ import annotations

from typing import Any

from .telecom_model import (
    NF,
    Cell,
    Endpoint,
    MetricFrame,
    TelecomConfigModel,
    _as_int,
    canonical_snssai,
    local_name,
    xml_root,
)

_MO_CONTAINERS = {"rpc-reply", "data", "config", "SubNetwork", "ManagedElement",
                  "GNBDUFunction", "GNBCUCPFunction", "GNBCUUPFunction"}


def _mo_id(el: Any) -> str:
    # NRM id is either an <id> child or an `id` XML attribute
    for c in el:
        if local_name(c.tag) == "id" and (c.text or "").strip():
            return c.text.strip()
    return str(el.attrib.get("id", "")).strip()


def _attrs_el(mo: Any) -> Any:
    for c in mo:
        if local_name(c.tag) == "attributes":
            return c
    return mo  # some exports inline attributes directly under the MO


def _find(el: Any, name: str) -> list[Any]:
    return [c for c in el if local_name(c.tag) == name]


def _text(el: Any, name: str) -> str | None:
    for c in el:
        if local_name(c.tag) == name:
            return (c.text or "").strip() or None
    return None


def _plmn_of(el: Any) -> str:
    mcc = _text(el, "mcc")
    mnc = _text(el, "mnc")
    return f"{mcc}-{mnc}" if mcc and mnc else ""  # digits verbatim (MNC "01" ≠ "1", TS 23.003)


def _extend(path: str, name: str, mo_id: str) -> str:
    seg = f"{name}={mo_id}" if mo_id else name
    return f"{path}/{seg}" if path else seg


def normalize_nrm_xml(raw: str) -> TelecomConfigModel:
    """Parse an NRM XML artifact into the canonical model. XXE-safe; tolerant of an rpc-reply/data
    wrapper and vendor namespaces (matched by local name)."""
    root = xml_root(raw)
    cells: list[Cell] = []
    nfs: list[NF] = []
    relations: list[dict] = []  # NRCellRelation entries, joined into cells afterward by cellLocalId
    _walk(root, "", {"me": "", "gnb": ""}, cells, nfs, relations)
    _attach_relations(cells, relations)
    return TelecomConfigModel(nfs=nfs, cells=cells, source_sha=MetricFrame.digest(raw))


def _walk(el: Any, path: str, ctx: dict, cells: list[Cell], nfs: list[NF], relations: list[dict]) -> None:
    for child in el:
        ln = local_name(child.tag)
        mid = _mo_id(child)
        p = _extend(path, ln, mid)
        if ln == "ManagedElement":
            _walk(child, p, {**ctx, "me": mid}, cells, nfs, relations)
        elif ln == "GNBDUFunction":
            gid = _text(_attrs_el(child), "gNBId") or mid  # gNBId is the CU↔DU shared identity
            _walk(child, p, {**ctx, "gnb": mid or ctx.get("me", ""), "gnb_id": gid},
                  cells, nfs, relations)
        elif ln == "GNBCUCPFunction":
            gid = _text(_attrs_el(child), "gNBId") or mid
            _walk(child, p, {**ctx, "gnb_id": gid}, cells, nfs, relations)
        elif ln == "NRCellDU":
            cell = _cell(child, p, ctx)
            cells.append(cell)
            # attach DU-nested relations DIRECTLY to this cell — no id matching, so an RDN id that
            # differs from cellLocalId (legal per TS 28.541) can't drop/misroute them (red-team R4).
            _walk(child, p, {**ctx, "du_cell": cell, "cu_local": None}, cells, nfs, relations)
        elif ln == "NRCellCU":
            # CU mirrors a DU cell by cellLocalId; its nested relations post-join to that DU cell.
            cu_local = _text(_attrs_el(child), "cellLocalId") or mid
            _walk(child, p, {**ctx, "cu_local": cu_local, "du_cell": None}, cells, nfs, relations)
        elif ln == "NRCellRelation":
            rel = _relation(child, p)
            du = ctx.get("du_cell")
            if du is not None:  # DU-nested → attach directly
                du.neighbors.append({"target": rel["target"], "ho_allowed": rel["ho_allowed"],
                                     "loc": rel["loc"]})
            else:  # CU-nested (or loose) → defer, join by (gNBId, cellLocalId) — cellLocalId is only
                relations.append({**rel, "cu_local": ctx.get("cu_local") or "",  # gNB-unique (TS 28.541)
                                  "gnb_id": ctx.get("gnb_id", "")})
            _walk(child, p, ctx, cells, nfs, relations)
        elif ln == "AMFFunction":
            nfs.append(_amf(child, p))
        elif ln == "SMFFunction":
            nfs.append(_core_nf(child, "SMF", p))
        elif ln == "UPFFunction":
            nfs.append(_upf(child, p))
        elif ln in _MO_CONTAINERS:
            _walk(child, p, ctx, cells, nfs, relations)
        else:
            _walk(child, p, ctx, cells, nfs, relations)


def _plmn_infos(attrs: Any) -> tuple[list[str], list[str]]:
    plmns, snssais = [], []
    for pil in _find(attrs, "pLMNInfoList"):
        for pinfo in _find(pil, "pLMNInfo") or [pil]:
            p = _plmn_of(_find(pinfo, "plmnId")[0] if _find(pinfo, "plmnId") else pinfo)
            if p:
                plmns.append(p)
            for sn in _find(pinfo, "sNssai") + _find(pinfo, "snssai"):
                s = canonical_snssai(_text(sn, "sst"), _text(sn, "sd"))
                if s:
                    snssais.append(s)
    return plmns, snssais


def _cell(mo: Any, path: str, ctx: dict) -> Cell:
    a = _attrs_el(mo)
    plmns, snssais = _plmn_infos(a)
    pci_raw = _text(a, "nRPCI")
    pci = _as_int(pci_raw)
    attrs: dict[str, Any] = {"cellLocalId": _text(a, "cellLocalId") or _mo_id(mo),
                             "gnb_id": ctx.get("gnb_id", "")}
    if pci is None and pci_raw is not None:  # declared but not an integer → flagged, not silently dropped
        attrs["pci_invalid"] = pci_raw
    return Cell(
        name=f"{ctx.get('me', '')}/{ctx.get('gnb', '')}/NRCellDU={_mo_id(mo)}".strip("/"),
        gnb=ctx.get("gnb", ""),
        pci=pci,
        tac=_as_int(_text(a, "nRTAC")),
        plmns=sorted(set(plmns)), snssais=sorted(set(snssais)),
        arfcn_dl=_as_int(_text(a, "arfcnDL")),
        ssb_frequency=_as_int(_text(a, "ssbFrequency")),
        channel_bw_mhz=_as_int(_text(a, "bSChannelBwDL")),
        max_tx_power_dbm=_num(_text(a, "configuredMaxTxPower")),
        prach=_prach(a),
        loc=f"{path}/attributes",
        attrs=attrs)


def _prach(a: Any) -> dict:
    prach: dict[str, Any] = {}
    for src, dst in (("rachRootSequence", "root"), ("prachRootSequenceIndex", "root"),
                     ("zeroCorrelationZoneConfig", "zero_corr_zone")):
        v = _as_int(_text(a, src))
        if v is not None:
            prach.setdefault(dst, v)
    return prach


def _relation(mo: Any, path: str) -> dict:
    a = _attrs_el(mo)
    ho = _text(a, "isHOAllowed")
    return {"target": _text(a, "adjacentNRCellRef") or _text(a, "adjacentCellRef") or "",
            "ho_allowed": (ho.lower() == "true") if ho is not None else None,
            "loc": f"{path}/attributes"}


def _attach_relations(cells: list[Cell], relations: list[dict]) -> None:
    # Only CU-nested/loose relations reach here (DU-nested ones attach directly during the walk). Join
    # by (gNBId, cellLocalId): cellLocalId is only gNB-unique (TS 28.541), so a global cellLocalId dict
    # would misroute a relation to the wrong gNB's cell when two gNBs reuse a cellLocalId (red-team R5).
    by_key = {(str(c.attrs.get("gnb_id")), str(c.attrs.get("cellLocalId"))): c for c in cells}
    for rel in relations:
        cell = by_key.get((str(rel.get("gnb_id", "")), str(rel.get("cu_local", ""))))
        if cell is not None and rel.get("target"):
            cell.neighbors.append(
                {"target": rel["target"], "ho_allowed": rel["ho_allowed"], "loc": rel["loc"]})


def _amf(mo: Any, path: str) -> NF:
    a = _attrs_el(mo)
    plmns, snssais = _plmn_infos(a)
    served = []
    for tl in _find(a, "taiList") + _find(a, "supportedTaiList") + _find(a, "servedTaiList"):
        for tai in _find(tl, "tai") or [tl]:
            plmn = _plmn_of(_find(tai, "plmnId")[0] if _find(tai, "plmnId") else tai)
            tac = _as_int(_text(tai, "tac"))
            if plmn and tac is not None:
                served.append({"plmn": plmn, "tac": tac, "loc": f"{path}/attributes/taiList"})
    # AMFFunction may also carry plmn via pLMNId (single)
    for pid in _find(a, "pLMNId"):
        p = _plmn_of(pid)
        if p:
            plmns.append(p)
    return NF(kind="AMF", name=_mo_id(mo) or "amf", plmns=sorted(set(plmns)), snssais=sorted(set(snssais)),
              endpoints=_endpoints(mo), loc=f"{path}/attributes", attrs={"served_tais": served})


def _core_nf(mo: Any, kind: str, path: str) -> NF:
    a = _attrs_el(mo)
    plmns, snssais = _plmn_infos(a)
    for pid in _find(a, "pLMNId"):
        p = _plmn_of(pid)
        if p:
            plmns.append(p)
    return NF(kind=kind, name=_mo_id(mo) or kind.lower(), plmns=sorted(set(plmns)),
              snssais=sorted(set(snssais)), endpoints=_endpoints(mo), loc=f"{path}/attributes")


def _upf(mo: Any, path: str) -> NF:
    return NF(kind="UPF", name=_mo_id(mo) or "upf", endpoints=_endpoints(mo), loc=f"{path}/attributes")


_EP_IFACE = {"EP_N2": "N2", "EP_N3": "N3", "EP_N4": "N4", "EP_N6": "N6", "EP_NgC": "N2", "EP_NgU": "N3"}


def _endpoints(mo: Any) -> list[Endpoint]:
    eps = []
    for child in mo:
        iface = _EP_IFACE.get(local_name(child.tag))
        if iface:
            a = _attrs_el(child)
            la = _find(a, "localAddress")
            addr = _text(la[0], "ipAddress") if la else _text(a, "ipAddress")
            eps.append(Endpoint(iface, str(addr or ""), f"{local_name(child.tag)}={_mo_id(child)}"))
    return eps


def _num(v: object) -> float | None:
    if v is None:
        return None
    try:
        return float(str(v).strip())
    except ValueError:
        return None
