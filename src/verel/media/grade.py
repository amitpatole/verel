"""Grade supplied media facts against a declared delivery spec into one MEDIA Report + signed receipt."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any

from ..ci.graders import GraderSpec, _receipt
from ..verdict.fingerprint import assign
from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from ._io import clean, load_json, read_text, sha256_file
from .facts import MISSING, get_path, load_fact_docs
from .rules import Outcome, Rule, Spec, evaluate, parse_spec


def _yaml(text: str) -> Any:
    try:
        import yaml
    except ImportError as e:  # pragma: no cover - extras path
        raise ValueError("YAML specs need pyyaml: pip install 'verel[media]' (or pass a .json spec)") from e
    try:
        for n, ev in enumerate(yaml.parse(text)):  # reject aliases up front: shared-node expansion bomb
            if isinstance(ev, yaml.AliasEvent) or n > 200_000:
                raise ValueError("YAML anchors/aliases and very large documents are not allowed in specs")
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as e:
        raise ValueError(f"invalid YAML: {type(e).__name__}") from None


def load_spec(repo: str, rel: str) -> tuple[Spec, str]:
    raw = read_text(repo, rel)
    data = load_json(raw, rel) if rel.lower().endswith(".json") else _yaml(raw)
    return parse_spec(data), raw


def _conf(sev: Severity) -> Confidence:
    return Confidence.HIGH if sev in (Severity.ERROR, Severity.CRITICAL) else Confidence.MEDIUM


def _issue(o: Outcome, sev: Severity, msg: str, **extra: object) -> Issue:
    detail = {"rule_id": o.rule.id, "op": o.rule.op, "path": o.rule.path, **extra}
    return Issue(kind=IssueKind.SPEC_VIOLATION, severity=sev, source=GraderKind.MEDIA,
                 confidence=_conf(sev),
                 message=msg, locator=f"facts:{o.rule.path}", locator_precise=True,
                 detail_json=json.dumps(detail, default=str))


def _describe(r: Rule, o: Outcome) -> str:
    base = r.message or f"{r.path} {r.op} {clean(o.expected)}"
    if o.status == "missing":
        return f"{r.id}: fact {r.path!r} not supplied (unmeasured is not passed): {base}"
    if o.status == "invalid":
        return f"{r.id}: fact {r.path!r} has an unusable value {clean(o.actual)!r}: {base}"
    return f"{r.id}: {clean(o.actual)} violates {r.op} {clean(o.expected)}: {base}"


def grade_spec(facts: dict[str, Any], spec: Spec, *, today: dt.date | None = None) -> list[Issue]:
    today = today or dt.date.today()
    waivers = {w.rule: w for w in spec.waivers}
    issues: list[Issue] = []
    for r in spec.rules:
        o = evaluate(r, facts)
        if o.status in ("pass", "skipped"):
            continue
        if o.status == "missing" and r.on_missing == "warning":
            sev = Severity.WARNING
        elif o.status in ("missing", "invalid"):  # unmeasured / unusable is never below ERROR by default
            sev = max(r.severity, Severity.ERROR, key=lambda s: list(Severity).index(s))
        else:
            sev = r.severity
        w = waivers.get(r.id)
        if w is not None:
            w.used = True
            if w.expires >= today:
                why = clean(w.reason, 120)
                msg = f"WAIVED until {w.expires}: {_describe(r, o)} (reason: {why})"
                issues.append(_issue(o, Severity.INFO, msg, waived=True))
                continue
            msg = f"{r.id}: waiver expired {w.expires}; rule applies again"
            issues.append(_issue(o, Severity.WARNING, msg, waiver_expired=True))
        issues.append(_issue(o, sev, _describe(r, o), status=o.status))
    known = {r.id for r in spec.rules}
    for w in spec.waivers:
        if w.rule not in known:
            issues.append(Issue(kind=IssueKind.OTHER, severity=Severity.WARNING, source=GraderKind.MEDIA,
                                message=f"stale waiver: no active rule {clean(w.rule)!r}",
                                detail_json=json.dumps({"rule_id": "_waiver", "waiver": w.rule})))
    if not spec.rules:
        issues.append(Issue(kind=IssueKind.OTHER, severity=Severity.WARNING, source=GraderKind.MEDIA,
                            message="no delivery rules are active; nothing was verified",
                            detail_json=json.dumps({"rule_id": "_meta"})))
    return issues


def verdict_of(issues: list[Issue]) -> Verdict:
    if any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in issues):
        return Verdict.FAIL
    return Verdict.WARN if any(i.severity == Severity.WARNING for i in issues) else Verdict.PASS


def grade_media(repo: str, *, facts: list[str], spec: str, today: dt.date | None = None,
                asset: str | None = None, require_asset_binding: bool = False,
                attest: str = "hmac") -> Report:
    """OFFLINE grade of repo-relative facts file(s) against a repo-relative delivery spec.

    With `asset=`, the asset's SHA-256 is bound into the receipt, and if the facts carry `asset.sha256`
    it must MATCH (a facts file measured from a different file is a CRITICAL finding, not a pass).
    `require_asset_binding=True` (used wherever a verdict can block or release a file) also makes a MISSING
    `asset.sha256` fact a CRITICAL finding: facts that never say which file they measured prove nothing."""
    if not facts:
        raise ValueError("provide at least one --facts file")
    merged, raw_facts, fact_docs = load_fact_docs(repo, facts)
    sp, raw_spec = load_spec(repo, spec)
    issues = grade_spec(merged, sp, today=today)
    asset_digest = ""
    bound_ok = False
    if asset is not None:
        asset_digest = sha256_file(repo, asset)
        claimed = get_path(merged, "asset.sha256")
        # Every facts file must say which file it measured: a file that only names the hash, merged with
        # measurements that name nothing, would otherwise bind facts nobody tied to this asset.
        per_file = [get_path(d, "asset.sha256") for d in fact_docs]
        if require_asset_binding and claimed is not MISSING and any(c is MISSING for c in per_file):
            claimed = MISSING
        if claimed is MISSING and require_asset_binding:
            issues.append(Issue(
                kind=IssueKind.SPEC_VIOLATION, severity=Severity.CRITICAL, source=GraderKind.MEDIA,
                confidence=Confidence.HIGH, locator="facts:asset.sha256", locator_precise=True,
                message="facts do not say which file they measured (asset.sha256 missing); cannot bind them",
                detail_json=json.dumps({"rule_id": "_asset_binding_missing"})))
        elif claimed is not MISSING and str(claimed).lower() == asset_digest:
            bound_ok = all(c is not MISSING and str(c).lower() == asset_digest for c in per_file)
        elif claimed is not MISSING and str(claimed).lower() != asset_digest:
            issues.append(Issue(
                kind=IssueKind.SPEC_VIOLATION, severity=Severity.CRITICAL, source=GraderKind.MEDIA,
                confidence=Confidence.HIGH, locator="facts:asset.sha256", locator_precise=True,
                message="facts were measured from a DIFFERENT file than the asset supplied (sha256 mismatch)",
                detail_json=json.dumps({"rule_id": "_asset_binding"})))
    issues = assign_all(issues)
    report = Report(verdict=verdict_of(issues), issues=issues, grader=GraderKind.MEDIA,
                    summary=f"media: {sum(1 for i in issues if i.severity != Severity.INFO)} finding(s) "
                            f"over {len(sp.rules)} rule(s)")
    if asset_digest:
        report.artifacts["asset_sha256"] = asset_digest  # evidence can then count distinct FILES
    if bound_ok:
        report.artifacts["facts_bound"] = "1"  # the facts say which file they measured, and it is this one
    gs = GraderSpec(GraderKind.MEDIA, ["verel-ci", "media", "--facts", *facts, "--spec", spec],
                    cwd=repo, covers=[*facts, spec])
    nonce = hashlib.sha256((raw_facts + raw_spec + asset_digest).encode()).hexdigest()
    report.run_receipt = _receipt(gs, report, nonce=nonce, attest=attest)
    return report


def assign_all(issues: list[Issue]) -> list[Issue]:
    r = Report(verdict=Verdict.PASS, summary="", issues=issues)
    assign(r)
    return r.issues
