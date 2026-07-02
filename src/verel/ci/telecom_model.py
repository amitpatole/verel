"""Canonical telecom data model — the normalized layer both telecom graders evaluate.

Design (see docs/use-cases-telecom.md and the Fable-5 advisory in the plan): adapters turn raw vendor
artifacts (Prometheus/OpenMetrics scrapes, PM XML, CSV/JSON exports; and — Phase 2+ — Helm values /
NETCONF NRM) into ONE canonical model, and pure deterministic evaluators run over that model. Grade
normalized artifacts, never raw formats — that is what lets one grader core serve RAN + Core and
cloud-native + classic.

This module holds the KPI half (Phase 1): `MetricSample` / `MetricFrame` (canonical PM counters, named
per 3GPP TS 28.552/28.554) and the `KpiThreshold` rule. Everything here is pure data + parsing — no
I/O, no network. The evaluators live in `telecom_kpi.py`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from hashlib import blake2s

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
    return yaml.safe_load(text or "")


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
