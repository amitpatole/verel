"""KPI/SLO vitals grader (Phase 1) — grade PM counters against DECLARED thresholds.

What it is: a deterministic threshold/regression gate over a supplied metrics artifact (a Prometheus/
OpenMetrics scrape, a CSV/JSON export). It emits a standard `Report` (grader=KPI) with grounded issues
naming the exact 3GPP counter + clause, and a signed `RunReceipt` bound to the input bytes.

What it is NOT (see the honesty section in docs/use-cases-telecom.md): a service-assurance system. It
does not observe the network, cannot attribute a regression to a cause, and grades only what is in the
file. A ratio below its declared `min_samples` floor is emitted at LOW confidence → the verdict bus
clamps it to a non-gating WARNING (statistical insufficiency must not fail a build). A threshold on a
counter absent from the file is WARNING "unmeasurable" — never a silent PASS (fail closed).
"""

from __future__ import annotations

import csv
import io
import json
import math
import re
from pathlib import Path

from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .graders import GraderSpec, _receipt
from .telecom_model import (
    KpiMeta,
    KpiThreshold,
    MetricFrame,
    MetricSample,
    load_profile,
    load_thresholds,
)

_BUILTIN_PROFILE = Path(__file__).resolve().parent / "telecom_rules" / "vitals_5g.yaml"
# Open5GS/free5GC expose Prometheus metrics whose names deliberately track TS 28.552; map the common
# ones to the canonical counter vocabulary. Unmapped metrics are dropped here and surface downstream as
# "unmeasurable" (never PASS) if a threshold references a canonical name with no sample.
_OPENMETRICS_MAP = {
    "fivegs_amffunction_rm_reginitreq": "RM.RegInitReq",
    "fivegs_amffunction_rm_reginitsucc": "RM.RegInitSucc",
    "fivegs_smffunction_sm_pdusessioncreationreq": "SM.PduSessionCreationReq",
    "fivegs_smffunction_sm_pdusessioncreationsucc": "SM.PduSessionCreationSucc",
    "gtp_inpacketsn3": "GTP.InDataPktN3UPF",
    "gtp_outpacketsn3": "GTP.OutDataPktN3UPF",
}
_OM_LINE = re.compile(r"^(?P<name>[a-zA-Z_:][\w:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<val>[-+0-9.eE]+)\s*$")
_OM_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
# The label match is only ever run on an input BOUNDED by these caps, so the `(\w+)` scan can't blow up
# quadratically on a long unmatched run (ReDoS / resource guard — red-team Finding D). A metric line's
# label section is small in practice; anything larger is pathological and its labels are dropped.
_MAX_LABELS_LEN = 4096
_MAX_LABELS = 64


# --------------------------------------------------------------------------- adapters
def frame_from_json(raw: str) -> MetricFrame:
    """Accept a list of sample dicts, `{"samples": [...]}`, or a flat `{"metrics": {name: value}}`."""
    try:
        data = json.loads(raw or "{}")
    except (json.JSONDecodeError, RecursionError) as e:
        # fail closed with a clear error (never let a raw traceback escape on attacker-controlled input);
        # RecursionError (deeply-nested array) is NOT a JSONDecodeError, so it must be caught explicitly.
        raise ValueError(f"invalid JSON metrics artifact: {type(e).__name__}") from e
    rows: list[dict] = []
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict) and isinstance(data.get("samples"), list):
        rows = [r for r in data["samples"] if isinstance(r, dict)]
    elif isinstance(data, dict):
        flat = data.get("metrics", data)
        if isinstance(flat, dict):
            rows = [{"kpi": k, "value": v} for k, v in flat.items()]
    samples: list[MetricSample] = []
    for r in rows:
        kpi = str(r.get("kpi", "")).strip()
        val = _num(r.get("value"))
        if not kpi or val is None:
            continue
        raw_dims = r.get("dims")
        dims = {str(k): str(v) for k, v in raw_dims.items()} if isinstance(raw_dims, dict) else {}
        samples.append(MetricSample(
            kpi=kpi, value=val, dims=dims, window=str(r.get("window", "")),
            samples=_samples(r.get("samples")), provenance=f"json#{kpi}{_dims_suffix(dims)}"))
    return MetricFrame(samples=samples, source_sha=MetricFrame.digest(raw))


def frame_from_csv(raw: str) -> MetricFrame:
    """Header row with at least `kpi,value`; optional `samples`, `window`, and any other columns
    become dims. Deterministic, dependency-free."""
    reader = csv.DictReader(io.StringIO(raw or ""))
    reserved = {"kpi", "value", "samples", "window"}
    samples: list[MetricSample] = []
    for row in reader:
        kpi = (row.get("kpi") or "").strip()
        val = _num(row.get("value"))
        if not kpi or val is None:
            continue
        dims = {k: str(v) for k, v in row.items() if k and k not in reserved and v not in (None, "")}
        samples.append(MetricSample(
            kpi=kpi, value=val, dims=dims, window=(row.get("window") or "").strip(),
            samples=_samples(row.get("samples")),
            provenance=f"csv#{kpi}{_dims_suffix(dims)}"))
    return MetricFrame(samples=samples, source_sha=MetricFrame.digest(raw))


def frame_from_openmetrics(raw: str, mapping: dict[str, str] | None = None) -> MetricFrame:
    """Parse Prometheus/OpenMetrics text exposition; map metric names → canonical counters. Labels
    become dims (comment/HELP/TYPE lines ignored). Unmapped metrics are dropped (→ 'unmeasurable')."""
    m = {**_OPENMETRICS_MAP, **(mapping or {})}
    samples: list[MetricSample] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hit = _OM_LINE.match(line)
        if not hit:
            continue
        name = hit.group("name")
        canon = m.get(name)
        val = _num(hit.group("val"))
        if canon is None or val is None:
            continue
        dims = _parse_labels(hit.group("labels") or "")
        samples.append(MetricSample(
            kpi=canon, value=val, dims=dims,
            provenance=f"openmetrics#{name}{_dims_suffix(dims)}"))
    return MetricFrame(samples=samples, source_sha=MetricFrame.digest(raw))


def _parse_labels(labels: str) -> dict[str, str]:
    """Extract Prometheus label dims, bounded in both input length and count (ReDoS guard)."""
    if not labels or len(labels) > _MAX_LABELS_LEN:
        return {}  # oversize label section is pathological → drop dims (metric value still parsed)
    dims: dict[str, str] = {}
    for i, mm in enumerate(_OM_LABEL.finditer(labels)):
        if i >= _MAX_LABELS:
            break
        dims[mm.group(1)] = mm.group(2)
    return dims


def parse_frame(raw: str, fmt: str = "auto", mapping: dict[str, str] | None = None) -> MetricFrame:
    # Strip a leading UTF-8 BOM / NUL before anything else: str.lstrip() does NOT remove U+FEFF, so a
    # BOM (emitted by default by Excel "CSV UTF-8", PowerShell Out-File, …) or a NUL would defeat format
    # autodetect → CSV fallback → 0 samples → a real breach silently downgraded to a non-gating WARN
    # (red-team R3). Removing it here fixes detection AND the actual parse for every format.
    raw = (raw or "").lstrip("\ufeff\x00")
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        head = (raw or "").lstrip()[:1]
        if head == "<":
            fmt = "pmxml"
        elif head in "{[":
            fmt = "json"
        elif _OM_LINE.match((raw or "").strip().splitlines()[0] if raw.strip() else ""):
            fmt = "openmetrics"
        else:
            fmt = "csv"
    if fmt == "json":
        return frame_from_json(raw)
    if fmt == "openmetrics":
        return frame_from_openmetrics(raw, mapping)
    if fmt == "csv":
        return frame_from_csv(raw)
    if fmt == "pmxml":  # 3GPP TS 32.435 measCollecFile \u2192 raw counters + derived ratio KPIs
        from .telecom_pmxml import derive_kpis, frame_from_pmxml
        return derive_kpis(frame_from_pmxml(raw, mapping))
    raise ValueError(f"unknown metrics format: {fmt!r} (expected auto|json|csv|openmetrics|pmxml)")


# --------------------------------------------------------------------------- evaluation
def _num(v: object) -> float | None:
    # Reject non-finite (NaN/±inf): NaN makes every threshold comparison False → a breaching KPI would
    # silently PASS (fail-open). A non-finite value is treated as no value → the counter reads as absent
    # → "unmeasurable" WARNING, never a silent pass. (Security cadence, Phase 1.)
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        f = float(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s.isascii():  # reject unicode digits so parser and human read the same value
            return None
        try:
            f = float(s)
        except ValueError:
            return None
    else:
        return None
    return f if math.isfinite(f) else None


def _samples(v: object) -> int:
    """A per-sample DENOMINATOR, coerced safely and clamped to >= 0. Prometheus/JSON often export
    counts as floats ("100.0") — accept them; a negative/garbage count becomes 0 (never let a
    negative denominator drag a well-sampled total below a min_samples floor — red-team Finding B/E)."""
    n = _num(v if v is not None else 0)
    return max(0, int(n)) if n is not None else 0


def _dims_suffix(dims: dict[str, str]) -> str:
    return ("{" + ",".join(f"{k}={v}" for k, v in sorted(dims.items())) + "}") if dims else ""


def _pick(samples: list[MetricSample], which: str) -> MetricSample:
    # which="min" → the lowest-value cell (worst for a floor); "max" → the highest (worst for a ceiling)
    return (min if which == "min" else max)(samples, key=lambda s: s.value)


def _mean(samples: list[MetricSample]) -> float:
    return sum(s.value for s in samples) / len(samples)


def _rep_value(samples: list[MetricSample], t: KpiThreshold) -> float:
    """The representative current value for a baseline-delta comparison."""
    if t.aggregation == "mean":
        return _mean(samples)
    return _pick(samples, "min" if t.direction == "higher_is_better" else "max").value


def _bound_breaches(samples: list[MetricSample], t: KpiThreshold
                    ) -> list[tuple[str, float, MetricSample]]:
    """Bound-aware breach detection (red-team Finding A): check each configured bound against the cell
    that is worst FOR THAT bound — a floor (`min`) against the LOWEST cell, a ceiling (`max`) against
    the HIGHEST cell — independent of `direction`. So a `max` ceiling with the default direction still
    catches the worst cell (the old direction-only pick could hide it). `aggregation="mean"` compares
    the mean instead. Returns (message, observed, worst_sample) for each breached bound."""
    use_mean = t.aggregation == "mean"
    mean_val = _mean(samples) if use_mean else 0.0
    out: list[tuple[str, float, MetricSample]] = []
    if t.min is not None:
        worst = _pick(samples, "min")
        observed = mean_val if use_mean else worst.value
        if observed < t.min:
            out.append((f"{observed:g} < min {t.min:g}", observed, worst))
    if t.max is not None:
        worst = _pick(samples, "max")
        observed = mean_val if use_mean else worst.value
        if observed > t.max:
            out.append((f"{observed:g} > max {t.max:g}", observed, worst))
    return out


def evaluate_kpis(frame: MetricFrame, thresholds: list[KpiThreshold],
                  profile: dict[str, KpiMeta] | None = None,
                  baseline: MetricFrame | None = None) -> list[Issue]:
    """Pure evaluation: declared thresholds over a MetricFrame → grounded Issues. No I/O."""
    profile = profile or {}
    issues: list[Issue] = []
    for t in thresholds:
        meta = profile.get(t.kpi)
        cite = _cite(t.kpi, meta)
        samples = frame.for_kpi(t.kpi)
        if not samples:
            issues.append(Issue(
                kind=IssueKind.THRESHOLD_BREACH, severity=Severity.WARNING, source=GraderKind.KPI,
                confidence=Confidence.LOW, locator=t.kpi,
                message=f"{cite} unmeasurable: counter absent from the metrics artifact (not gating)",
                detail_json=json.dumps({"kpi": t.kpi, "reason": "absent"})))
            continue
        total_samples = sum(s.samples for s in samples)
        # Statistical-sufficiency floor: below it, LOW confidence → the bus clamps to WARNING.
        insufficient = t.min_samples > 0 and total_samples < t.min_samples
        for msg, observed, worst in _bound_breaches(samples, t):
            sev = Severity.WARNING if insufficient else _severity(t)
            conf = Confidence.LOW if insufficient else Confidence.MEDIUM
            note = ""
            if insufficient:
                note = (" [denominator absent — not gating]" if total_samples == 0
                        else " [insufficient samples — not gating]")
            issues.append(Issue(
                kind=IssueKind.THRESHOLD_BREACH, severity=sev, source=GraderKind.KPI, confidence=conf,
                locator=t.kpi + worst.dim_label(),
                message=f"{cite}: {msg} ({t.aggregation}{worst.dim_label()}, n={total_samples}){note}",
                detail_json=json.dumps({
                    "kpi": t.kpi, "observed": observed, "min": t.min, "max": t.max,
                    "aggregation": t.aggregation, "samples": total_samples, "min_samples": t.min_samples,
                    "window": worst.window, "worst_dims": worst.dims, "provenance": worst.provenance,
                    "formula": (meta.formula if meta else ""), "clause": (meta.clause if meta else "")})))
        # Baseline regression (delta) — independent of the absolute threshold. Fail CLOSED: a declared
        # delta gate with no baseline available is UNMEASURABLE → a non-gating WARNING (never a silent
        # PASS — mirrors the absent-counter path). Otherwise run the real delta check. (Red-team R2.)
        if t.max_delta_vs_baseline is not None:
            base_samples = baseline.for_kpi(t.kpi) if baseline is not None else []
            if not base_samples:
                issues.append(Issue(
                    kind=IssueKind.BASELINE_REGRESSION, severity=Severity.WARNING, source=GraderKind.KPI,
                    confidence=Confidence.LOW, locator=t.kpi,
                    message=f"{cite}: regression gate unmeasurable — no baseline supplied (not gating)",
                    detail_json=json.dumps({"kpi": t.kpi, "reason": "no_baseline",
                                            "max_delta": t.max_delta_vs_baseline})))
            else:
                assert baseline is not None
                reg = _regression(t, samples, baseline, meta)
                if reg is not None:
                    issues.append(reg)
    return issues


def _regression(t: KpiThreshold, samples: list[MetricSample], baseline: MetricFrame,
                meta: KpiMeta | None) -> Issue | None:
    base_samples = baseline.for_kpi(t.kpi)
    if not base_samples:
        return None
    value = _rep_value(samples, t)
    base_value = _rep_value(base_samples, t)
    drop = (base_value - value) if t.direction == "higher_is_better" else (value - base_value)
    assert t.max_delta_vs_baseline is not None
    if drop <= t.max_delta_vs_baseline:
        return None
    return Issue(
        kind=IssueKind.BASELINE_REGRESSION, severity=_severity(t), source=GraderKind.KPI,
        confidence=Confidence.MEDIUM, locator=t.kpi,
        message=(f"{_cite(t.kpi, meta)}: regressed {drop:g} vs baseline "
                 f"(now {value:g}, was {base_value:g}; allowed Δ {t.max_delta_vs_baseline:g})"),
        detail_json=json.dumps({"kpi": t.kpi, "observed": value, "baseline": base_value,
                                "delta": drop, "max_delta": t.max_delta_vs_baseline}))


def _severity(t: KpiThreshold) -> Severity:
    return Severity.ERROR if t.severity == "error" else Severity.WARNING


def _cite(kpi: str, meta: KpiMeta | None) -> str:
    if meta and (meta.title or meta.clause):
        bits = [meta.title or kpi]
        if meta.formula:
            bits.append(f"[{meta.formula}]")
        if meta.clause:
            bits.append(f"({meta.clause})")
        return " ".join(bits)
    return kpi


# --------------------------------------------------------------------------- offline entry-point
def builtin_profile() -> dict[str, KpiMeta]:
    """Load the packaged 5G vitals profile (KPI id → formula + clause). Empty if PyYAML absent."""
    try:
        return load_profile(_BUILTIN_PROFILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — descriptive metadata only; grading proceeds without it
        return {}


def grade_kpi(repo: str, *, metrics: str, thresholds: str | dict | list,
              baseline: str | None = None, fmt: str = "auto",
              profile: dict[str, KpiMeta] | None = None, attest: str = "hmac") -> Report:
    """Grade a metrics artifact against declared thresholds, OFFLINE, into one KPI Report with a signed
    receipt. `metrics`/`baseline` are repo-relative files; `thresholds` is a repo-relative YAML file
    path OR an in-memory dict/list of rules (the latter needs no PyYAML)."""
    from .k8s import _read_in_repo  # path-traversal-safe reader (realpath-contained, size-capped)

    raw = _read_in_repo(repo, metrics)
    frame = parse_frame(raw, fmt)
    rules = load_thresholds(_read_in_repo(repo, thresholds)) if isinstance(thresholds, str) \
        else load_thresholds(thresholds)
    base_frame = parse_frame(_read_in_repo(repo, baseline), fmt) if baseline else None
    prof = profile if profile is not None else builtin_profile()

    issues = evaluate_kpis(frame, rules, prof, base_frame)
    # Fail closed (defense-in-depth beyond the BOM strip): a NON-EMPTY artifact that yields ZERO samples
    # is a format/encoding failure, not "some counters absent" — gate it as an ERROR so a mis-encoded or
    # unparseable metrics file can never let a would-be breach slip through as a non-gating WARN.
    if raw.strip() and rules and not frame.samples:
        issues.insert(0, Issue(
            kind=IssueKind.MISCONFIG, severity=Severity.ERROR, source=GraderKind.KPI,
            confidence=Confidence.MEDIUM, locator="(artifact)",
            message="metrics artifact is non-empty but parsed to zero samples (format/encoding problem?)",
            detail_json=json.dumps({"reason": "zero_samples", "bytes": len(raw)})))
    gating = any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in issues)
    verdict = Verdict.FAIL if gating else (Verdict.WARN if issues else Verdict.PASS)
    report = Report(verdict=verdict, summary=f"kpi: {len(issues)} issue(s) over {len(rules)} threshold(s)",
                    issues=issues, grader=GraderKind.KPI)

    covers = [metrics] + ([thresholds] if isinstance(thresholds, str) else []) \
        + ([baseline] if baseline else [])
    spec = GraderSpec(GraderKind.KPI, ["verel-ci", "telecom", "--kpi", metrics], cwd=repo, covers=covers)
    report.run_receipt = _receipt(spec, report, nonce=frame.source_sha, attest=attest)
    return report
