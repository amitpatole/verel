"""Canonical telecom data model — the normalized layer both telecom graders evaluate.

Design (see docs/use-cases-telecom.md and the Fable-5 advisory in the plan): adapters turn raw vendor
artifacts (Prometheus/OpenMetrics scrapes, PM XML, CSV/JSON exports; and — Phase 2+ — Helm values /
NETCONF NRM) into ONE canonical model, and pure deterministic evaluators run over that model. Grade
normalized artifacts, never raw formats — that is what lets one grader core serve RAN + Core and
cloud-native + classic.

The KPI half (Phase 1): `MetricSample` / `MetricFrame` (canonical PM counters, named per 3GPP TS
28.552/28.554) and the `KpiThreshold` rule; evaluators in `telecom_kpi.py`.

The config half (Phase 2): `TelecomConfigModel` (a slim projection of the 3GPP TS 28.541 NRM — `NF` +
`Endpoint`) that adapters build from a Helm-values / NETCONF artifact; declared-invariant evaluators in
`telecom_cfg.py`. Every field carries a `loc` (provenance) so a FAIL points at the exact source path.

Everything here is pure data + parsing — no I/O, no network.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from hashlib import blake2s
from typing import Any

# PyYAML is behind the `telecom` extra and lazy-imported (mirrors ci/k8s.py's helm YAML path) so the
# base wheel stays light. Thresholds/profiles may also be passed as plain dicts (no yaml needed).


class MissingTelecomDep(RuntimeError):
    """A telecom grader needs the `telecom` extra (PyYAML) but it is not installed."""


def _yaml_load(text: str) -> object:
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:  # pragma: no cover - exercised via the install-hint test
        raise MissingTelecomDep(
            "telecom KPI thresholds/profile are YAML — install `verel[telecom]` (PyYAML)"
        ) from e
    try:
        return yaml.safe_load(text or "")
    except (yaml.YAMLError, RecursionError) as e:
        # fail closed with a clean error — never let a raw parser traceback escape on untrusted input
        raise ValueError(f"invalid YAML artifact: {type(e).__name__}") from e


@dataclass(frozen=True)
class MetricSample:
    """One observed PM value in the canonical vocabulary. `kpi` is a canonical id (a 28.552 counter or
    a 28.554 KPI id); `samples` is the DENOMINATOR (attempts) behind a ratio — the statistical-
    sufficiency signal. `provenance` points back at the source artifact so a FAIL is grounded."""

    kpi: str
    value: float
    dims: dict[str, str] = field(default_factory=dict)
    window: str = ""
    samples: int = 0  # denominator (0 = unknown → treated as insufficient)
    provenance: str = ""

    def dim_label(self) -> str:
        if not self.dims:
            return ""
        return "{" + ",".join(f"{k}={v}" for k, v in sorted(self.dims.items())) + "}"


@dataclass
class MetricFrame:
    """A parsed set of samples plus a digest of the exact source bytes (bound into the receipt)."""

    samples: list[MetricSample] = field(default_factory=list)
    source_sha: str = ""

    def for_kpi(self, kpi: str) -> list[MetricSample]:
        return [s for s in self.samples if s.kpi == kpi]

    @staticmethod
    def digest(raw: str) -> str:
        return blake2s((raw or "").encode()).hexdigest()[:16]


# Direction semantics for a threshold. higher_is_better → a floor (min); lower_is_better → a ceiling.
_DIRECTIONS = frozenset({"higher_is_better", "lower_is_better"})
# Aggregation across the samples matching a KPI+dims selector. worst = the single worst cell/NF (never
# let a mean hide one dead cell); mean = average across matching samples.
_AGGREGATIONS = frozenset({"worst", "mean"})


@dataclass(frozen=True)
class KpiThreshold:
    """A declared gate on one KPI. Thresholds are ALWAYS operator-declared, never inferred (like COST/
    PERF). `min_samples` is the denominator floor: below it the verdict is emitted at LOW confidence and
    the bus clamps it to a non-gating WARNING (statistical insufficiency cannot fail a build)."""

    kpi: str
    direction: str = "higher_is_better"
    min: float | None = None
    max: float | None = None
    max_delta_vs_baseline: float | None = None  # absolute allowed drop vs the baseline window
    min_samples: int = 0
    aggregation: str = "worst"
    severity: str = "error"  # "error" gates; "warning" advises

    def __post_init__(self) -> None:
        if self.direction not in _DIRECTIONS:
            raise ValueError(f"KPI {self.kpi!r}: direction must be one of {sorted(_DIRECTIONS)}")
        if self.aggregation not in _AGGREGATIONS:
            raise ValueError(f"KPI {self.kpi!r}: aggregation must be one of {sorted(_AGGREGATIONS)}")
        if self.severity not in ("error", "warning"):
            raise ValueError(f"KPI {self.kpi!r}: severity must be 'error' or 'warning'")


@dataclass(frozen=True)
class KpiMeta:
    """Descriptive metadata for a canonical KPI id (from the built-in vitals profile): its exact
    formula and the 3GPP clause, so an Issue can cite chapter and verse rather than a bare name."""

    kpi: str
    title: str = ""
    formula: str = ""
    clause: str = ""
    unit: str = ""
    domain: str = ""  # "ran" | "core"


def _as_float(v: object) -> float | None:
    if isinstance(v, bool):  # bool is an int subclass — reject it explicitly
        return None
    if isinstance(v, (int, float)):
        f = float(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s.isascii():  # reject unicode digits (e.g. "９９") — parser/human must read the same value
            return None
        try:
            f = float(s)
        except ValueError:
            return None
    else:
        return None
    # Non-finite thresholds (NaN/inf) are meaningless as a gate — reject so a bad rule can't slip in.
    return f if math.isfinite(f) else None


def load_thresholds(spec: str | dict | list) -> list[KpiThreshold]:
    """Parse thresholds from YAML text, or an already-parsed dict/list. Two shapes accepted:
    a list of rule dicts, or a mapping {kpi_id: {rule fields}}. Unknown fields are ignored; a
    malformed rule raises ValueError (fail closed — never silently drop a declared gate)."""
    data: object = _yaml_load(spec) if isinstance(spec, str) else spec
    rows: list[dict] = []
    if isinstance(data, dict):
        for kpi, body in data.items():
            row = dict(body) if isinstance(body, dict) else {}
            row.setdefault("kpi", kpi)
            rows.append(row)
    elif isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    else:
        raise ValueError("thresholds must be a list of rules or a {kpi: {...}} mapping")
    out: list[KpiThreshold] = []
    for r in rows:
        kpi = str(r.get("kpi", "")).strip()
        if not kpi:
            raise ValueError(f"threshold missing 'kpi': {r!r}")
        # Fail closed: a bound that is PRESENT but uncoercible (garbage / non-finite / unicode) must
        # RAISE — never silently coerce to None and disable the gate (red-team Finding C).
        vmin = _bound(kpi, "min", r)
        vmax = _bound(kpi, "max", r)
        vdelta = _bound(kpi, "max_delta_vs_baseline", r)
        if vmin is None and vmax is None and vdelta is None:
            raise ValueError(f"threshold {kpi!r} declares no bound (min/max/max_delta_vs_baseline)")
        try:
            ms = int(r.get("min_samples", 0) or 0)
        except (TypeError, ValueError) as e:
            raise ValueError(f"threshold {kpi!r}: min_samples must be an integer") from e
        out.append(KpiThreshold(
            kpi=kpi, direction=str(r.get("direction", "higher_is_better")),
            min=vmin, max=vmax, max_delta_vs_baseline=vdelta,
            min_samples=max(0, ms),  # a negative floor is meaningless
            aggregation=str(r.get("aggregation", "worst")),
            severity=str(r.get("severity", "error")),
        ))
    return out


def _bound(kpi: str, field_name: str, r: dict) -> float | None:
    """Coerce a threshold bound; fail closed if it is present-but-unparseable (never a silent no-op)."""
    if field_name not in r or r[field_name] is None:
        return None
    v = _as_float(r[field_name])
    if v is None:
        raise ValueError(f"threshold {kpi!r}: {field_name}={r[field_name]!r} is not a finite number")
    return v


def load_profile(spec: str | dict) -> dict[str, KpiMeta]:
    """Parse the vitals profile (KPI id → metadata) from YAML text or a parsed dict."""
    data: object = _yaml_load(spec) if isinstance(spec, str) else spec
    if not isinstance(data, dict):
        raise ValueError("vitals profile must be a {kpi: {title, formula, clause, ...}} mapping")
    kpis = data.get("kpis", data) if isinstance(data.get("kpis"), dict) else data
    out: dict[str, KpiMeta] = {}
    for kpi, body in kpis.items():
        b = body if isinstance(body, dict) else {}
        out[str(kpi)] = KpiMeta(
            kpi=str(kpi), title=str(b.get("title", "")), formula=str(b.get("formula", "")),
            clause=str(b.get("clause", "")), unit=str(b.get("unit", "")), domain=str(b.get("domain", "")),
        )
    return out


# ============================================================================
# Config model (Phase 2) — a slim projection of the 3GPP TS 28.541 NRM. Adapters populate it from a
# Helm-values / rendered-manifest / NETCONF artifact; the declared-invariant evaluators in
# telecom_cfg.py run pure functions over it. Deliberately ~30 attributes, NOT full NRM fidelity.
# ============================================================================
_IFACES = frozenset({"N2", "N3", "N4", "N6", "SBI", "mgmt"})


@dataclass
class Endpoint:
    """A network-function interface endpoint. `iface` is the reference point (N2/N3/N4/N6/SBI/mgmt);
    `subnet` is the CIDR/address it binds. `loc` is the source-artifact provenance."""

    iface: str
    subnet: str = ""
    loc: str = ""


@dataclass
class NF:
    """A 5G network function projected from config. `snssais` are canonical "SST" or "SST-SD" strings;
    `attrs` carries rule-specific extras (dnn_pools, suci, ciphering, mtu, sbi_scheme, upf_pool …) so
    the model stays slim while rules read what they need. Every field's origin is in `loc`/`attr_locs`."""

    kind: str  # AMF | SMF | UPF | NSSF | NRF | AUSF | UDM | PCF | ... (compared case-insensitively)
    name: str = ""
    plmns: list[str] = field(default_factory=list)  # "MCC-MNC"
    snssais: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    replicas: int | None = None
    attrs: dict[str, Any] = field(default_factory=dict)  # rule-specific extension bag (heterogeneous)
    attr_locs: dict[str, str] = field(default_factory=dict)  # attr name → source provenance
    loc: str = ""

    def is_kind(self, kind: str) -> bool:
        return self.kind.upper() == kind.upper()


@dataclass
class TelecomConfigModel:
    """The normalized network model an artifact projects into; declared invariants evaluate over it."""

    nfs: list[NF] = field(default_factory=list)
    source_sha: str = ""

    def of_kind(self, *kinds: str) -> list[NF]:
        want = {k.upper() for k in kinds}
        return [nf for nf in self.nfs if nf.kind.upper() in want]


def canonical_snssai(sst: object, sd: object = None) -> str:
    """Canonical S-NSSAI id: "SST" (no SD) or "SST-SD" with SD zero-padded to 6 lowercase hex digits
    (3GPP TS 23.003 §28.4.2 — SD is a 3-octet HEX value). Tolerant of ints, hex/`0x` strings, and an
    already-joined "sst-sd". SD `0xffffff` (the "no SD" value) collapses to SST-only. An unparseable SD
    is kept verbatim (lower-cased) so two distinct values never canonicalize to the same id (no
    fail-open). Returns "" if SST is unusable."""
    if isinstance(sst, str) and "-" in sst and sd is None:
        head, _, tail = sst.partition("-")
        return canonical_snssai(head.strip(), tail.strip())
    s = _as_int(sst)
    if s is None:
        return ""
    if sd in (None, "", "null"):
        return str(s)
    v = _sd_int(sd)
    if v is None:
        return f"{s}-{str(sd).strip().lower()}"  # unparseable → keep raw so distinct stays distinct
    if v == 0xFFFFFF:
        return str(s)  # "no SD" per TS 23.003
    return f"{s}-{v:06x}"


def _sd_int(sd: object) -> int | None:
    # SD is a 3-octet HEX value (TS 23.003). Interpret an int and a string CONSISTENTLY by parsing the
    # value's TEXTUAL form as hex — this matches how a chart renders the YAML value into the NF config
    # (Open5GS parses it as hex), so `sd: 16` (int) and `sd: "10"` are treated identically to how they
    # deploy. (Red-team R2 #2 — removes the int-vs-string interpretation split.)
    if isinstance(sd, bool) or sd is None:
        return None
    s = str(sd).strip().lower().removeprefix("0x")
    # require pure hex digits: int(s, 16) also accepts "_" grouping ("1_0" == "10"), which could let
    # two differently-written SDs collide — reject anything but [0-9a-f] (red-team R3 observation).
    if not s or not all(c in "0123456789abcdef" for c in s):
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def _as_int(v: object) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s.isascii():
            return None
        try:
            return int(s, 0) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None
    return None
