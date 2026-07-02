"""Declared config-invariant grader (Phase 2) — deterministic 5G Core invariants over a config artifact.

Clones the `iac.py` pattern: normalize a raw artifact (an Open5GS-shaped Helm-values document) into the
canonical `TelecomConfigModel`, then run PURE rule functions (TCM → Issues). NO LLM, no network — a
telecom gate that can hallucinate is worse than useless. Every Issue is grounded with a `locator` into
the source values path and carries `detail_json["rule_id"]` (the `iam_risk_issues` convention).

Honest scope (docs/use-cases-telecom.md): this grades DECLARED config, not the running network. It does
not observe live state, and several rules depend on chart-specific paths — where a field isn't derivable
it emits a non-gating INFO ("insufficient evidence"), never a false FAIL or a silent PASS.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .graders import GraderSpec, _receipt
from .telecom_model import (
    NF,
    Endpoint,
    MetricFrame,
    TelecomConfigModel,
    _as_float,
    _as_int,
    _yaml_load,
    canonical_snssai,
)

Rule = Callable[[TelecomConfigModel, dict], "list[Issue]"]


# ============================================================================ adapter
def _dig(obj: object, *keys: object) -> object:
    """Walk nested dict/list by keys (str for dict, int for list); None on any miss."""
    cur = obj
    for k in keys:
        if isinstance(k, int) and isinstance(cur, list):
            if not 0 <= k < len(cur):
                return None
            cur = cur[k]
        elif isinstance(k, str) and isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


def _as_list(v: object) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _plmn(obj: object) -> str:
    mcc, mnc = _dig(obj, "mcc"), _dig(obj, "mnc")
    return f"{mcc}-{mnc}" if mcc is not None and mnc is not None else ""


def _snssai(obj: object) -> str:
    if not isinstance(obj, dict):
        return ""
    return canonical_snssai(obj.get("sst"), obj.get("sd"))


def _cm(values: dict, nf: str) -> dict | None:
    """The embedded Open5GS NF config: values[nf].configmap.<nf> (the umbrella-chart layout)."""
    cm = _dig(values, nf, "configmap", nf)
    return cm if isinstance(cm, dict) else None


def _replicas(values: dict, nf: str) -> int | None:
    for key in ("replicaCount", "replicas"):
        v = _dig(values, nf, key)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def _sbi_client_uris(cm: dict, base: str) -> tuple[list[dict], str]:
    """Return ([{uri, loc}], scheme) — client NRF/SCP/NSI URIs, plus derived server scheme."""
    uris: list[dict] = []
    for group in ("nrf", "scp", "nsi"):
        for i, e in enumerate(_as_list(_dig(cm, "sbi", "client", group))):
            uri = _dig(e, "uri")
            if isinstance(uri, str):
                uris.append({"uri": uri, "loc": f"{base}.sbi.client.{group}[{i}].uri"})
    # server scheme: TLS material present ⇒ https; else unknown (Open5GS would serve http, but we do
    # not synthesize a default — "unknown" surfaces as INFO, never a pass-as-https).
    tls = _dig(cm, "default", "tls", "server")
    scheme = "https" if isinstance(tls, dict) and (tls.get("cert") or tls.get("key")) else "unknown"
    return uris, scheme


def normalize_helm_values(raw: str) -> TelecomConfigModel:
    """Project an Open5GS-shaped Helm-values document into the canonical model (profile:
    `open5gs-configmap`). Tolerant: an absent section simply yields no NF/attr (rules then emit INFO,
    not FAIL). A present-but-wrong-typed values root raises ValueError (fail closed)."""
    data = _yaml_load(raw)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("telecom config artifact must be a YAML/JSON mapping (Helm values)")
    nfs: list[NF] = []

    # AMF
    cm = _cm(data, "amf")
    if cm is not None:
        plmns, plmn_slices = [], {}
        for ps in _as_list(_dig(cm, "plmn_support")):
            p = _plmn(_dig(ps, "plmn_id"))
            if p:
                plmns.append(p)
                plmn_slices[p] = [s for s in (_snssai(x) for x in _as_list(_dig(ps, "s_nssai"))) if s]
        sec = _dig(cm, "security") or {}
        eps = [Endpoint("N2", str(a), "amf.configmap.amf.ngap.server")
               for a in _addr_list(_dig(cm, "ngap", "server"))]
        uris, scheme = _sbi_client_uris(cm, "amf.configmap.amf")
        nf = NF(kind="AMF", name="amf", plmns=sorted(set(plmns)), endpoints=eps,
                replicas=_replicas(data, "amf"), loc="amf.configmap.amf",
                attrs={"plmn_slices": plmn_slices,
                       "integrity_order": _upper(_dig(sec, "integrity_order")),
                       "ciphering_order": _upper(_dig(sec, "ciphering_order")),
                       "sbi_client_uris": uris, "sbi_scheme": scheme})
        nfs.append(nf)

    # SMF
    cm = _cm(data, "smf")
    if cm is not None:
        slice_dnns: dict[str, list[str]] = {}
        for info in _as_list(_dig(cm, "info")):
            for sn in _as_list(_dig(info, "s_nssai")):
                s = _snssai(sn)
                if s:
                    slice_dnns.setdefault(s, [])
                    for d in _as_list(_dig(sn, "dnn")):
                        if d not in slice_dnns[s]:
                            slice_dnns[s].append(str(d))
        upf_pool = []
        for i, u in enumerate(_as_list(_dig(cm, "pfcp", "client", "upf"))):
            upf_pool.append({"name": str(_dig(u, "address") or ""),
                             "dnns": [str(x) for x in _as_list(_dig(u, "dnn"))],
                             "loc": f"smf.configmap.smf.pfcp.client.upf[{i}]"})
        sessions = _sessions(cm, "smf.configmap.smf.session")
        uris, scheme = _sbi_client_uris(cm, "smf.configmap.smf")
        eps = [Endpoint("N4", str(a), "smf.configmap.smf.pfcp.server")
               for a in _addr_list(_dig(cm, "pfcp", "server"))]
        nfs.append(NF(kind="SMF", name="smf", snssais=sorted(slice_dnns), endpoints=eps,
                      replicas=_replicas(data, "smf"), loc="smf.configmap.smf",
                      attrs={"slice_dnns": slice_dnns, "upf_pool": upf_pool, "sessions": sessions,
                             "mtu": _dig(cm, "mtu"), "sbi_client_uris": uris, "sbi_scheme": scheme}))

    # UPF
    cm = _cm(data, "upf")
    if cm is not None:
        eps = [Endpoint("N3", str(a), "upf.configmap.upf.gtpu.server")
               for a in _addr_list(_dig(cm, "gtpu", "server"))]
        eps += [Endpoint("N4", str(a), "upf.configmap.upf.pfcp.server")
                for a in _addr_list(_dig(cm, "pfcp", "server"))]
        sessions = _sessions(cm, "upf.configmap.upf.session")
        eps += [Endpoint("N6", str(s["subnet"]), s["loc"]) for s in sessions if s.get("subnet")]
        nfs.append(NF(kind="UPF", name="upf", endpoints=eps, replicas=_replicas(data, "upf"),
                      loc="upf.configmap.upf", attrs={"sessions": sessions}))

    # NSSF
    cm = _cm(data, "nssf")
    if cm is not None:
        snssais, uris = [], []
        nsi = _dig(cm, "sbi", "client", "nsi")
        if nsi is None:
            nsi = _dig(cm, "nsi")  # legacy ≤2.5 layout
        for i, e in enumerate(_as_list(nsi)):
            s = _snssai(_dig(e, "s_nssai"))
            if s:
                snssais.append(s)
            uri = _dig(e, "uri")
            if isinstance(uri, str):
                uris.append({"uri": uri, "loc": f"nssf.configmap.nssf.sbi.client.nsi[{i}].uri"})
        nfs.append(NF(kind="NSSF", name="nssf", snssais=sorted(set(snssais)),
                      replicas=_replicas(data, "nssf"), loc="nssf.configmap.nssf",
                      attrs={"nsi_snssais": snssais, "sbi_client_uris": uris}))

    # UDM (SUCI home-network keys)
    cm = _cm(data, "udm")
    if cm is not None:
        hnet = []
        for i, h in enumerate(_as_list(_dig(cm, "hnet"))):
            hnet.append({"id": _dig(h, "id"), "scheme": _dig(h, "scheme"),
                         "key_present": bool(_dig(h, "key")),
                         "loc": f"udm.configmap.udm.hnet[{i}]"})
        nfs.append(NF(kind="UDM", name="udm", replicas=_replicas(data, "udm"),
                      loc="udm.configmap.udm", attrs={"hnet": hnet}))

    return TelecomConfigModel(nfs=nfs, source_sha=MetricFrame.digest(raw))


def _sessions(cm: dict, base: str) -> list[dict]:
    out = []
    for i, s in enumerate(_as_list(_dig(cm, "session"))):
        out.append({"dnn": (str(_dig(s, "dnn")) if _dig(s, "dnn") is not None else ""),
                    "subnet": (str(_dig(s, "subnet")) if _dig(s, "subnet") is not None else ""),
                    "dev": (str(_dig(s, "dev")) if _dig(s, "dev") is not None else ""),
                    "loc": f"{base}[{i}]"})
    return out


def _addr_list(server: object) -> list[str]:
    out = []
    for e in _as_list(server):
        a = _dig(e, "address") if isinstance(e, dict) else e
        if a is not None:
            out.append(str(a))
    return out


def _upper(v: object) -> list[str]:
    return [str(x).upper() for x in _as_list(v)]


def _net(cidr: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except (ValueError, AttributeError):
        return None


# ============================================================================ rule helpers
_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}


def _mk(rule_id: str, check: str, sev: Severity, kind: IssueKind, msg: str,
        loc: str = "", **detail: object) -> Issue:
    import json
    detail = {"rule_id": rule_id, "check": check, **detail}
    conf = Confidence.HIGH if sev in (Severity.ERROR, Severity.CRITICAL) else Confidence.MEDIUM
    return Issue(kind=kind, severity=sev, source=GraderKind.TELECOM_CFG, confidence=conf,
                 message=msg, locator=loc or None, locator_precise=bool(loc),
                 detail_json=json.dumps(detail))


def _info(rule_id: str, check: str, msg: str, loc: str = "") -> Issue:
    return _mk(rule_id, check, Severity.INFO, IssueKind.OTHER, f"insufficient evidence: {msg}", loc)


# ============================================================================ the 7 Core rules
RID_SNSSAI = "snssai-consistency"
RID_POOL = "ue-pool-sanity"
RID_IFACE = "upf-interface-separation"
RID_REDUN = "redundancy-floor"
RID_SUCI = "suci-security-posture"
RID_SBI = "sbi-tls"
RID_MTU = "mtu-coherence"


def rule_snssai_consistency(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    ignore = {canonical_snssai(s) for s in params.get("ignore_snssais", [])}
    smfs, nssfs, amfs = tcm.of_kind("SMF"), tcm.of_kind("NSSF"), tcm.of_kind("AMF")
    smf_s = {s for nf in smfs for s in nf.snssais if s not in ignore}
    if not smf_s:
        return []
    nssf_s = {s for nf in nssfs for s in nf.snssais}
    amf_s = {s for nf in amfs for slist in (nf.attrs.get("plmn_slices") or {}).values() for s in slist}
    out: list[Issue] = []
    # d1 SMF→NSSF
    if not nssfs:
        # SMF declares slices but there's no NSSF to verify them against. With require_nssf → ERROR;
        # otherwise a WARNING (surfaced, verdict WARN) rather than a silent INFO — omitting the NSSF
        # section must not quietly dodge the strongest slice-selection invariant (red-team R1 F5).
        out.append(_mk(RID_SNSSAI, "smf-vs-nssf",
                       sev if params.get("require_nssf") else Severity.WARNING,
                       IssueKind.CROSS_NF_MISMATCH,
                       f"{RID_SNSSAI}: SMF declares slices but no NSSF is present — cannot verify they "
                       "are NSSF-selectable (TS 29.531 §5.2)", smfs[0].loc))
    else:
        for s in sorted(smf_s - nssf_s):
            out.append(_mk(RID_SNSSAI, "smf-vs-nssf", sev, IssueKind.CROSS_NF_MISMATCH,
                           f"{RID_SNSSAI}: S-NSSAI {s} is configured in SMF but missing from NSSF supported "
                           f"NSSAI — UEs on this slice fail NSSF slice selection (TS 29.531 §5.2)",
                           _snssai_loc(smfs, s), snssai=s, expected_at="nssf...sbi.client.nsi"))
    # d2 SMF→AMF
    if amfs:
        for s in sorted(smf_s - amf_s):
            out.append(_mk(RID_SNSSAI, "smf-vs-amf", sev, IssueKind.CROSS_NF_MISMATCH,
                           f"{RID_SNSSAI}: S-NSSAI {s} served by SMF is not supported by any AMF PLMN "
                           "(unreachable slice) (TS 23.501 §5.15.3)", _snssai_loc(smfs, s), snssai=s))
    # d3 NSSF→AMF (advisory)
    if amfs and nssfs:
        for s in sorted(nssf_s - amf_s - ignore):
            out.append(_mk(RID_SNSSAI, "nssf-vs-amf", Severity.WARNING, IssueKind.CROSS_NF_MISMATCH,
                           f"{RID_SNSSAI}: S-NSSAI {s} in NSSF is not in any AMF PLMN (dead slice)",
                           nssfs[0].loc, snssai=s))
    # d4 slice→UPF (via DNN)
    for smf in smfs:
        slice_dnns = smf.attrs.get("slice_dnns") or {}
        pool = smf.attrs.get("upf_pool") or []
        for s in sorted(set(slice_dnns) & smf_s):
            for dnn in slice_dnns[s]:
                covered = any((not p.get("dnns")) or dnn in p["dnns"] for p in pool)
                if not covered:
                    out.append(_mk(RID_SNSSAI, "slice-upf", sev, IssueKind.INVARIANT_VIOLATION,
                                   f"{RID_SNSSAI}: S-NSSAI {s} via DNN {dnn} has no UPF in the SMF selection "
                                   "pool (TS 23.501 §6.3.3)", smf.loc, snssai=s, dnn=dnn))
    return out


def _snssai_loc(smfs: list[NF], s: str) -> str:
    return f"{smfs[0].loc}.info[].s_nssai (S-NSSAI {s})" if smfs else ""


def rule_ue_pool_sanity(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    min_hosts = int(params.get("min_pool_hosts", 8))
    smfs = tcm.of_kind("SMF")
    all_sessions = [(nf, s) for nf in tcm.of_kind("SMF", "UPF") for s in (nf.attrs.get("sessions") or [])]
    out: list[Issue] = []
    # d1 every DNN pooled (SMF side)
    dnn_universe: set[str] = set()
    for smf in smfs:
        for dnns in (smf.attrs.get("slice_dnns") or {}).values():
            dnn_universe |= {d for d in dnns if d}
        for p in (smf.attrs.get("upf_pool") or []):
            dnn_universe |= {d for d in p.get("dnns", []) if d}
        pooled = {s["dnn"] for s in (smf.attrs.get("sessions") or [])}
        wildcard = "" in pooled
        for dnn in sorted(dnn_universe):
            if not wildcard and dnn not in pooled:
                out.append(_mk(RID_POOL, "dnn-pool", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_POOL}: DNN {dnn} has no UE IP pool (session subnet) in SMF "
                               "(TS 23.501 §5.8.2.2)", smf.loc, dnn=dnn))
    # d2 non-overlap. An O(n²) pairwise scan was an unauthenticated DoS within the 25MB cap (red-team
    # R1 F3): a flat file of many sessions hung the grader. Replaced with an O(n log n) interval sweep
    # per IP version — sort by network start, track the active (largest-end) interval, and report an
    # overlap when the next interval starts inside it. Gates on ANY overlap; enumerating every pair is
    # unnecessary for a gate.
    nets: list[tuple[dict, ipaddress._BaseNetwork]] = []
    for _nf, s in all_sessions:
        n = _net(s["subnet"]) if s.get("subnet") else None
        if n is not None:
            nets.append((s, n))
    for ver in (4, 6):
        group = sorted((t for t in nets if t[1].version == ver),
                       key=lambda t: (int(t[1].network_address), t[1].prefixlen))
        active: tuple[dict, ipaddress._BaseNetwork] | None = None
        for s, n in group:
            if active is not None:
                sa, na = active
                if int(n.network_address) <= int(na.broadcast_address):  # overlaps the active interval
                    same_dnn = sa["dnn"] and sa["dnn"] == s["dnn"]
                    if not (same_dnn and sa["subnet"] == s["subnet"]):  # SMF↔UPF same-DNN agreement is ok
                        out.append(_mk(RID_POOL, "pool-overlap", sev, IssueKind.CROSS_NF_MISMATCH,
                                       f"{RID_POOL}: UE pools overlap: {sa['subnet']} ({sa['loc']}) and "
                                       f"{s['subnet']} ({s['loc']}) — duplicate/misrouted UE addresses "
                                       "(TS 23.501 §5.8.2.2)", sa["loc"], other=s["loc"]))
            if active is None or int(n.broadcast_address) > int(active[1].broadcast_address):
                active = (s, n)
    # d3 size (warning)
    for s, n in nets:
        usable = n.num_addresses - (2 if n.version == 4 else 0)
        if usable < min_hosts:
            out.append(_mk(RID_POOL, "pool-size", Severity.WARNING, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_POOL}: pool {s['subnet']} has {usable} usable hosts (< {min_hosts})",
                           s["loc"]))
    return out


def rule_upf_interface_separation(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    mgmt_subnets = [n for n in (_net(c) for c in params.get("mgmt_subnets", [])) if n]
    out: list[Issue] = []
    for upf in tcm.of_kind("UPF"):
        # include bare /32,/128 hosts too: an exact N3==N6 host collision is strong evidence of
        # non-separation, not "absent evidence" (red-team R1 F6). `overlaps()` handles /32 equality.
        by = {i: [e for e in upf.endpoints if e.iface == i and _net(e.subnet) is not None]
              for i in ("N3", "N4", "N6")}
        for a, b, isev, kind in (("N3", "N6", sev, "N3/N6"), ):
            if not by[a] or not by[b]:
                out.append(_info(RID_IFACE, kind,
                                 f"{a}/{b} subnet not derivable for {upf.name}", upf.loc))
                continue
            for ea in by[a]:
                for eb in by[b]:
                    na, nb = _net(ea.subnet), _net(eb.subnet)
                    if na and nb and na.overlaps(nb):
                        out.append(_mk(RID_IFACE, kind, isev, IssueKind.INVARIANT_VIOLATION,
                                       f"{RID_IFACE}: UPF {a} ({ea.subnet}) overlaps {b} ({eb.subnet}) — "
                                       "user-plane / data-network not isolated (TS 23.501 §8.3; operator "
                                       "security baseline)", ea.loc, other=eb.loc))
        # N6 vs mgmt
        for eb in by["N6"]:
            nb = _net(eb.subnet)
            for mg in mgmt_subnets:
                if nb and nb.overlaps(mg):
                    out.append(_mk(RID_IFACE, "N6/mgmt", sev, IssueKind.INVARIANT_VIOLATION,
                                   f"{RID_IFACE}: UPF N6 ({eb.subnet}) on the management network ({mg}) — "
                                   "Internet-facing interface exposed to mgmt (operator security baseline)",
                                   eb.loc))
        # N4 sharing (warning)
        for ea in by["N4"]:
            for other in ("N3", "N6"):
                for eb in by[other]:
                    na, nb = _net(ea.subnet), _net(eb.subnet)
                    if na and nb and na.overlaps(nb):
                        out.append(_mk(
                            RID_IFACE, "N4-shared", Severity.WARNING, IssueKind.INVARIANT_VIOLATION,
                            f"{RID_IFACE}: UPF N4 ({ea.subnet}) shares a subnet with {other} "
                            f"({eb.subnet})", ea.loc))
    return out


def rule_redundancy_floor(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    floors = params.get("floors") or {"AMF": 2, "SMF": 2}
    out: list[Issue] = []
    for kind, floor in floors.items():
        for nf in tcm.of_kind(kind):
            eff = nf.replicas if nf.replicas is not None else 1
            if eff < int(floor):
                note = "" if nf.replicas is not None else " (replicaCount unset → defaults to 1)"
                out.append(_mk(RID_REDUN, "replicas", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_REDUN}: {kind} has {eff} replica(s) < declared floor {floor}{note} "
                               "(TS 23.501 §5.21.2 resiliency)", f"{nf.name}.replicaCount", nf=kind))
    return out


def rule_suci_security_posture(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    out: list[Issue] = []
    udms = tcm.of_kind("UDM")
    if params.get("require_hnet", True):
        if not udms:
            out.append(_info(RID_SUCI, "hnet", "no UDM in artifact"))
        else:
            has_key = any(h.get("key_present") for nf in udms for h in (nf.attrs.get("hnet") or []))
            if not any(nf.attrs.get("hnet") for nf in udms):
                out.append(_mk(RID_SUCI, "hnet", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_SUCI}: no home-network key configured — SUPI sent in clear "
                               "(TS 33.501 Annex C)", udms[0].loc))
            elif not has_key:
                out.append(_mk(RID_SUCI, "hnet-key", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_SUCI}: home-network profile present but no key material "
                               "(TS 33.501 Annex C)", udms[0].loc))
    for nf in udms:
        for h in (nf.attrs.get("hnet") or []):
            scheme = _as_int(h.get("scheme"))  # coerce: a quoted "0" must not evade the null-scheme gate
            if scheme == 0:
                out.append(_mk(RID_SUCI, "null-scheme", sev, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_SUCI}: null protection scheme (0) configured — SUPI privacy disabled "
                               "(TS 33.501 §6.12)", h.get("loc", nf.loc)))
            elif scheme not in (1, 2):  # only Profile A (1) / B (2) are defined (red-team R2 #1)
                out.append(_mk(
                    RID_SUCI, "scheme-invalid", Severity.WARNING, IssueKind.INVARIANT_VIOLATION,
                    f"{RID_SUCI}: unrecognized SUCI protection scheme {h.get('scheme')!r} "
                    "(only Profile A=1 / B=2 are defined, TS 33.501 Annex C)", h.get("loc", nf.loc)))
    allow_nea0 = params.get("allow_nea0_priority", False)
    for amf in tcm.of_kind("AMF"):
        integ = amf.attrs.get("integrity_order") or []
        ciph = amf.attrs.get("ciphering_order") or []
        if not integ and not ciph:
            out.append(_info(RID_SUCI, "algos", f"security order not set for {amf.name}", amf.loc))
            continue
        if "NIA0" in integ:  # null integrity must never be offered (§5.11.1), not downgradable
            out.append(_mk(RID_SUCI, "nia0", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SUCI}: NIA0 (null integrity) is offered (TS 33.501 §5.11.1)",
                           f"{amf.loc}.security.integrity_order"))
        if ciph and ciph[0] == "NEA0" and not allow_nea0:
            out.append(_mk(RID_SUCI, "nea0-priority", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_SUCI}: NEA0 (null ciphering) is top-priority (TS 33.501 §5.11.1)",
                           f"{amf.loc}.security.ciphering_order"))
    return out


def rule_sbi_tls(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    mesh = params.get("assume_mesh_mtls", False)
    exempt = {str(x).upper() for x in params.get("exempt_nfs", [])}
    eff = Severity.WARNING if mesh else sev
    out: list[Issue] = []
    for nf in tcm.nfs:
        if nf.kind.upper() in exempt:
            continue
        for u in (nf.attrs.get("sbi_client_uris") or []):
            if str(u["uri"]).strip().lower().startswith("http://"):
                suffix = " [assume_mesh_mtls: downgraded]" if mesh else ""
                out.append(_mk(RID_SBI, "client-uri", eff, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_SBI}: {nf.kind} SBI client URI is cleartext http:// ({u['uri']}) "
                               f"(TS 33.501 §13.1){suffix}", u["loc"]))
        if nf.attrs.get("sbi_scheme") == "unknown":
            out.append(_info(RID_SBI, "server-scheme", f"{nf.kind} SBI server TLS not derivable", nf.loc))
    return out


def rule_mtu_coherence(tcm: TelecomConfigModel, params: dict) -> list[Issue]:
    sev = _SEV[params["_severity"]]
    overhead = int(params.get("encap_overhead", 60))
    n3 = int(params.get("n3_transport_mtu", 1500))
    usable = n3 - overhead
    out: list[Issue] = []
    for smf in tcm.of_kind("SMF"):
        raw = smf.attrs.get("mtu")
        note = ""
        if raw is None:
            ue, note = 1400, " (SMF mtu unset → Open5GS default 1400)"
        else:
            f = _as_float(raw)  # accept int/float/numeric-string; a present-but-garbage mtu is NOT
            if f is None:       # silently defaulted (that hid an oversized MTU — red-team R1 F2)
                out.append(_mk(RID_MTU, "mtu", Severity.WARNING, IssueKind.INVARIANT_VIOLATION,
                               f"{RID_MTU}: SMF mtu {raw!r} is not numeric — cannot verify N3 coherence",
                               f"{smf.loc}.mtu"))
                continue
            ue = int(f)
        if ue > usable:
            out.append(_mk(RID_MTU, "mtu", sev, IssueKind.INVARIANT_VIOLATION,
                           f"{RID_MTU}: session MTU {ue} > {n3} - {overhead} = {usable} usable on N3 "
                           f"— GTP-U encapsulation blackhole{note} (TS 29.281 §5.1)", f"{smf.loc}.mtu"))
    return out


@dataclass(frozen=True)
class RuleDef:
    fn: Rule
    severity: str  # default gating severity
    clause: str
    params: dict = field(default_factory=dict)


BUILTIN_RULES: dict[str, RuleDef] = {
    RID_SNSSAI: RuleDef(rule_snssai_consistency, "error", "TS 23.501 §5.15",
                        {"require_nssf": False, "ignore_snssais": []}),
    RID_POOL: RuleDef(rule_ue_pool_sanity, "error", "TS 23.501 §5.8.2.2", {"min_pool_hosts": 8}),
    RID_IFACE: RuleDef(rule_upf_interface_separation, "error", "TS 23.501 §8.3", {"mgmt_subnets": []}),
    RID_REDUN: RuleDef(rule_redundancy_floor, "warning", "TS 23.501 §5.21.2",
                       {"floors": {"AMF": 2, "SMF": 2}}),
    RID_SUCI: RuleDef(rule_suci_security_posture, "error", "TS 33.501 §6.12",
                      {"require_hnet": True, "allow_nea0_priority": False}),
    RID_SBI: RuleDef(rule_sbi_tls, "error", "TS 33.501 §13.1",
                     {"assume_mesh_mtls": False, "exempt_nfs": []}),
    RID_MTU: RuleDef(rule_mtu_coherence, "error", "TS 29.281 §5.1",
                     {"encap_overhead": 60, "n3_transport_mtu": 1500}),
}


# ============================================================================ rule declaration + waivers
@dataclass(frozen=True)
class Waiver:
    id: str
    match: dict
    expiry: date
    reason: str


@dataclass(frozen=True)
class CfgRule:
    id: str
    fn: Rule
    severity: str
    params: dict
    clause: str
    waivers: tuple[Waiver, ...] = ()


def _parse_date(v: object, ctx: str) -> date:
    try:
        return date.fromisoformat(str(v))
    except (ValueError, TypeError) as e:
        raise ValueError(f"{ctx}: expiry must be an ISO date (YYYY-MM-DD), got {v!r}") from e


def load_cfg_rules(spec: str | dict | None) -> list[CfgRule]:
    """Parse `verel_telecom.yaml` (text or parsed dict) into active rules. Fail closed: an unknown rule
    id, a bad severity, or a malformed waiver RAISES (a declared rule is never silently dropped). `None`
    or empty → every built-in runs with its defaults."""
    if spec is None or spec == "":
        return [_cfg_rule(rid, rd, {}) for rid, rd in BUILTIN_RULES.items()]
    data = _yaml_load(spec) if isinstance(spec, str) else spec
    if not isinstance(data, dict):
        raise ValueError("verel_telecom.yaml must be a mapping")
    if int(data.get("version", 0)) != 1:
        raise ValueError(f"unsupported verel_telecom.yaml version: {data.get('version')!r} (expected 1)")
    default_enabled = bool((data.get("defaults") or {}).get("enabled", True))
    overrides: dict[str, dict] = {}
    for entry in (data.get("rules") or []):
        if not isinstance(entry, dict):
            raise ValueError(f"each rule must be a mapping, got {entry!r}")
        rid = str(entry.get("id", "")).strip()
        if rid not in BUILTIN_RULES:
            raise ValueError(f"unknown telecom rule id: {rid!r} (known: {sorted(BUILTIN_RULES)})")
        if rid in overrides:  # a duplicate id lets a later enabled:false silently override — reject it
            raise ValueError(f"duplicate telecom rule id in config: {rid!r}")
        overrides[rid] = entry
    out: list[CfgRule] = []
    for rid, rd in BUILTIN_RULES.items():
        entry = overrides.get(rid)
        if entry is None:
            if default_enabled:
                out.append(_cfg_rule(rid, rd, {}))
            continue
        en = entry.get("enabled", True)
        if en is None:  # present-but-null → treat as the default (True), not disabled
            en = True
        if not bool(en):
            continue
        out.append(_cfg_rule(rid, rd, entry))
    return out


def _cfg_rule(rid: str, rd: RuleDef, entry: dict) -> CfgRule:
    sev = str(entry.get("severity", rd.severity))
    if sev not in ("error", "warning"):
        raise ValueError(f"rule {rid!r}: severity must be 'error' or 'warning', got {sev!r}")
    params = {**rd.params, **(entry.get("params") or {})}
    waivers = []
    for w in (entry.get("waivers") or []):
        if not isinstance(w, dict):
            raise ValueError(f"rule {rid!r}: each waiver must be a mapping")
        wid = str(w.get("id", "")).strip()
        reason = str(w.get("reason", "")).strip()
        if not wid or not reason:
            raise ValueError(f"rule {rid!r}: every waiver needs a non-empty id and reason")
        waivers.append(Waiver(wid, dict(w.get("match") or {}),
                              _parse_date(w.get("expiry"), f"waiver {wid}"), reason))
    return CfgRule(rid, rd.fn, sev, params, rd.clause, tuple(waivers))


def _match(issue: Issue, sel: dict) -> bool:
    import fnmatch
    if not sel:
        return True
    d = issue.detail
    for k, v in sel.items():
        if k == "locator":
            if not fnmatch.fnmatch(issue.locator or "", str(v)):
                return False
        elif str(d.get(k, "")).lower() != str(v).lower():
            return False
    return True


def apply_waivers(issues: list[Issue], rules: list[CfgRule], today: date) -> list[Issue]:
    """Transform waived violations to non-gating INFO (never silently dropped); surface expired/stale
    waivers as WARNINGs. Returns a new issue list."""
    import json
    by_rule: dict[str, list[Waiver]] = {r.id: list(r.waivers) for r in rules}
    out: list[Issue] = []
    used: dict[str, set[str]] = {}
    for issue in issues:
        rid = issue.detail.get("rule_id", "")
        waived = False
        for w in by_rule.get(rid, []):
            if not _match(issue, w.match):
                continue
            if w.expiry < today:
                continue  # expired waivers don't suppress (an expired-waiver WARNING is added below)
            used.setdefault(w.id, set())
            d = {**issue.detail, "waived": True, "waiver_id": w.id,
                 "waiver_expiry": w.expiry.isoformat(), "original_severity": issue.severity.value}
            out.append(issue.model_copy(update={
                "severity": Severity.INFO, "confidence": Confidence.LOW,
                "message": f"[WAIVED until {w.expiry} by {w.id}: {w.reason}] {issue.message}",
                "detail_json": json.dumps(d)}))
            used[w.id].add(rid)
            waived = True
            break
        if not waived:
            out.append(issue)
    # expired + stale waiver notices
    for r in rules:
        for w in r.waivers:
            hit = any(_match(i, w.match) for i in issues if i.detail.get("rule_id") == r.id)
            if w.expiry < today and hit:
                out.append(_mk(r.id, "waiver-expired", Severity.WARNING, IssueKind.OTHER,
                               f"waiver {w.id} expired {w.expiry} — no longer suppresses {r.id}"))
            elif not hit:
                out.append(_mk(r.id, "waiver-stale", Severity.WARNING, IssueKind.OTHER,
                               f"waiver {w.id} matched nothing (stale — remove it)"))
    return out


# ============================================================================ offline entry-point
def grade_cfg(repo: str, *, values: str, rules: str | dict | None = None,
              today: date | None = None, attest: str = "hmac") -> Report:
    """Grade a telecom config artifact against declared invariants, OFFLINE, into one TELECOM_CFG Report
    with a signed receipt. `values` is a repo-relative Helm-values artifact; `rules` is a repo-relative
    `verel_telecom.yaml` path OR an in-memory dict (None → all built-ins at defaults)."""
    from .k8s import _read_in_repo

    raw = _read_in_repo(repo, values)
    tcm = normalize_helm_values(raw)
    cfg_rules = load_cfg_rules(_read_in_repo(repo, rules) if isinstance(rules, str) else rules)
    issues: list[Issue] = []
    for r in cfg_rules:
        issues.extend(r.fn(tcm, {**r.params, "_severity": r.severity}))
    issues = apply_waivers(issues, cfg_rules, today or date.today())
    if not cfg_rules:
        # a rules file that disables everything must NOT grade a clean PASS silently (red-team R1 F4)
        issues.append(_mk("_meta", "no-rules", Severity.WARNING, IssueKind.OTHER,
                          "no telecom invariants are active (defaults.enabled=false and none enabled) "
                          "— nothing was verified"))

    gating = any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in issues)
    warn = any(i.severity == Severity.WARNING for i in issues)
    verdict = Verdict.FAIL if gating else (Verdict.WARN if warn else Verdict.PASS)
    report = Report(verdict=verdict, issues=issues, grader=GraderKind.TELECOM_CFG,
                    summary=f"telecom-cfg: {len(issues)} finding(s) over {len(cfg_rules)} rule(s)")
    covers = [values] + ([rules] if isinstance(rules, str) else [])
    spec = GraderSpec(GraderKind.TELECOM_CFG, ["verel-ci", "telecom-cfg", "--values", values],
                      cwd=repo, covers=covers)
    report.run_receipt = _receipt(spec, report, nonce=tcm.source_sha, attest=attest)
    return report
