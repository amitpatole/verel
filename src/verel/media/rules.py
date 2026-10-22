"""Declared delivery-spec rules over supplied facts (`MediaFacts v1`). Deterministic and offline.

Operators declare the rules (or pick built-in profiles); nothing is inferred. A rule whose fact is
absent is an ERROR by default (`on_missing: error`) because "not measured" must never read as "passed".
"""

from __future__ import annotations

import datetime as dt
import math
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from ..verdict.models import Severity
from .facts import MISSING, as_number, get_path
from .profiles import PROFILES

OPS = {"gte", "gt", "lte", "lt", "eq", "ne", "between", "approx", "in", "not_in", "present",
       "superset", "subset"}
NUMERIC_OPS = {"gte", "gt", "lte", "lt", "between", "approx"}
_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO,
        "critical": Severity.CRITICAL}
_ON_MISSING = {"error", "warning", "skip"}
MAX_RULES = 500
MAX_LIST = 1000
_ID_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


@dataclass
class Rule:
    id: str
    path: str
    op: str
    value: Any = None
    ref: str | None = None
    tol: float = 0.0
    severity: Severity = Severity.ERROR
    on_missing: str = "error"
    message: str = ""


@dataclass
class Waiver:
    rule: str
    reason: str
    expires: dt.date
    used: bool = field(default=False)


@dataclass
class Spec:
    rules: list[Rule]
    waivers: list[Waiver]


def _scalar(x: Any) -> bool:
    return x is None or isinstance(x, (str, int, float, bool))


def _plain(v: Any) -> bool:
    """A scalar, or a bounded list of scalars: nothing that can hide an alias-expanded structure."""
    return _scalar(v) or (isinstance(v, list) and len(v) <= MAX_LIST and all(_scalar(x) for x in v))


def _num(x: Any, what: str) -> float:
    n = as_number(x)
    if n is None:
        raise ValueError(f"{what}: expected a finite number, got {x!r}")
    return n


def _rule(raw: Any, prefix: str = "") -> Rule:
    if not isinstance(raw, dict):
        raise ValueError(f"each rule must be a mapping, got {raw!r}")
    rid = str(raw.get("id", "")).strip()
    if not rid or len(rid) > 128 or not set(rid) <= _ID_OK:
        raise ValueError(f"bad rule id: {rid!r}")
    rid = f"{prefix}{rid}"
    unknown = set(raw) - {"id", "path", "op", "value", "ref", "tol", "severity", "on_missing", "message"}
    if unknown:
        raise ValueError(f"{rid}: unknown field(s) {sorted(unknown)}")  # a typo must not silently no-op
    op = str(raw.get("op", ""))
    if op not in OPS:
        raise ValueError(f"{rid}: unknown op {op!r} (known: {sorted(OPS)})")
    path = str(raw.get("path", ""))
    if not path or len(path) > 256:
        raise ValueError(f"{rid}: missing path")
    sev = str(raw.get("severity", "error")).lower()
    if sev not in _SEV:
        raise ValueError(f"{rid}: bad severity {sev!r}")
    om = str(raw.get("on_missing", "error")).lower()
    if om not in _ON_MISSING:
        raise ValueError(f"{rid}: bad on_missing {om!r}")
    ref = raw.get("ref")
    value = raw.get("value")
    tol = _num(raw.get("tol", 0.0), f"{rid}.tol")
    if tol < 0:
        raise ValueError(f"{rid}: tol must be >= 0")
    if op == "approx":
        if ref is None and value is None:
            raise ValueError(f"{rid}: approx needs `value` or `ref`")
        if value is not None:
            _num(value, f"{rid}.value")
    elif op == "between":
        if not (isinstance(value, list) and len(value) == 2):
            raise ValueError(f"{rid}: between needs value: [lo, hi]")
        lo, hi = _num(value[0], f"{rid}.lo"), _num(value[1], f"{rid}.hi")
        if lo > hi:
            raise ValueError(f"{rid}: between lo > hi")
    elif op in NUMERIC_OPS:
        if ref is None:
            _num(value, f"{rid}.value")
    elif op in {"in", "not_in", "superset", "subset"}:
        if not isinstance(value, list) or len(value) > MAX_LIST or not all(_scalar(x) for x in value):
            raise ValueError(f"{rid}: {op} needs a list of scalars (<= {MAX_LIST})")
    elif op in {"eq", "ne"}:
        if value is None and ref is None:
            raise ValueError(f"{rid}: {op} needs `value` or `ref`")
        if not _plain(value):
            raise ValueError(f"{rid}: {op} value must be a scalar or a short list of scalars")
    return Rule(id=rid, path=path, op=op, value=value, ref=None if ref is None else str(ref), tol=tol,
                severity=_SEV[sev], on_missing=om, message=str(raw.get("message", ""))[:300])


def parse_spec(data: Any) -> Spec:
    """Parse a spec document (`version: 1`, `profiles`, `rules`, `waivers`). Fail closed on anything odd."""
    if not isinstance(data, dict):
        raise ValueError("media spec must be a mapping")
    if data.get("version") != 1:
        raise ValueError(f"unsupported media spec version: {data.get('version')!r} (expected 1)")
    unknown = set(data) - {"version", "profiles", "rules", "waivers", "disable"}
    if unknown:
        raise ValueError(f"unknown media spec key(s): {sorted(unknown)}")
    rules: list[Rule] = []
    for name in data.get("profiles") or []:
        if name not in PROFILES:
            raise ValueError(f"unknown profile {name!r} (known: {sorted(PROFILES)})")
        rules += [_rule(r, f"{name}.") for r in PROFILES[name]]
    rules += [_rule(r) for r in data.get("rules") or []]
    disabled = set(data.get("disable") or [])
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate rule id(s) in spec")
    missing = disabled - set(ids)
    if missing:
        raise ValueError(f"`disable` names unknown rule(s): {sorted(missing)}")
    rules = [r for r in rules if r.id not in disabled]
    if len(rules) > MAX_RULES:
        raise ValueError(f"too many rules (> {MAX_RULES})")
    waivers: list[Waiver] = []
    for w in data.get("waivers") or []:
        if not isinstance(w, dict) or not w.get("rule") or not str(w.get("reason", "")).strip():
            raise ValueError("a waiver needs `rule` and a non-empty `reason`")
        exp = w.get("expires")
        try:
            d = exp.date() if isinstance(exp, dt.datetime) else (
                exp if isinstance(exp, dt.date) else dt.date.fromisoformat(str(exp)))
        except ValueError:
            raise ValueError(f"waiver for {w.get('rule')!r} needs an ISO `expires` date") from None
        waivers.append(Waiver(str(w["rule"]), str(w["reason"])[:300], d))
    return Spec(rules, waivers)


@dataclass
class Outcome:
    rule: Rule
    status: str  # "pass" | "fail" | "missing" | "invalid" | "skipped"
    actual: Any = None
    expected: Any = None


def _same(a: Any, b: Any) -> bool:
    """Equality that is strict about kind (True is not 1, "1" is not 1) but treats the numbers 48000 and
    48000.0 as the same value, because ffprobe-style tools emit either for the same fact."""
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) \
            and not isinstance(b, bool):
        try:
            return Fraction(a) == Fraction(b)  # exact: 2**53+1 is not 2**53, 48000 equals 48000.0
        except (ValueError, OverflowError):  # nan / inf
            return False
    return type(a) is type(b) and a == b


def _key(x: Any) -> str:
    """Type-tagged set key: True, 1 and "1" are three different values."""
    return f"{type(x).__name__}:{x}"


def _cmp_num(r: Rule, a: float, b: float) -> bool:
    return {"gte": a >= b, "gt": a > b, "lte": a <= b, "lt": a < b}[r.op]


def evaluate(rule: Rule, facts: dict[str, Any]) -> Outcome:
    try:
        return _evaluate(rule, facts)
    except (TypeError, ValueError, OverflowError, RecursionError):
        # hostile / ill-typed fact or ref: unusable, never a crash and never a pass
        return Outcome(rule, "invalid", get_path(facts, rule.path), rule.value)


def _evaluate(rule: Rule, facts: dict[str, Any]) -> Outcome:
    actual = get_path(facts, rule.path)
    if actual is None:  # a null measurement is "not measured"
        actual = MISSING
    if actual is MISSING:
        return Outcome(rule, "skipped" if rule.on_missing == "skip" else "missing")
    if rule.op == "present":
        return Outcome(rule, "pass", actual)
    target: Any = rule.value
    if rule.ref is not None:
        target = get_path(facts, rule.ref)
        if target is MISSING:
            status = "skipped" if rule.on_missing == "skip" else "missing"
            return Outcome(rule, status, actual, f"ref:{rule.ref}")
    if rule.op in NUMERIC_OPS:
        a = as_number(actual)
        if a is None:
            return Outcome(rule, "invalid", actual, target)  # present but not a finite number → never a pass
        if rule.op == "between":
            if not (isinstance(target, list) and len(target) == 2):
                return Outcome(rule, "invalid", actual, target)
            blo, bhi = as_number(target[0]), as_number(target[1])
            if blo is None or bhi is None or blo > bhi:  # bounds must be finite numbers
                return Outcome(rule, "invalid", actual, target)
            lo, hi = blo, bhi
            return Outcome(rule, "pass" if lo <= a <= hi else "fail", a, [lo, hi])
        b = as_number(target)
        if b is None:
            return Outcome(rule, "invalid", actual, target)
        if rule.op == "approx":
            close = math.isclose(a, b, abs_tol=rule.tol, rel_tol=0.0)
            return Outcome(rule, "pass" if close else "fail", a, b)
        return Outcome(rule, "pass" if _cmp_num(rule, a, b) else "fail", a, b)
    if rule.op == "eq":
        return Outcome(rule, "pass" if _same(actual, target) else "fail", actual, target)
    if rule.op == "ne":
        return Outcome(rule, "fail" if _same(actual, target) else "pass", actual, target)
    if rule.op in {"in", "not_in"}:
        # A non-scalar fact (list/dict) can't be a member of anything: that is "unusable", never a pass
        # for `not_in` (fail-open) and never a fail for `in` by accident. Membership is type-strict.
        if not _scalar(actual) or not isinstance(target, list):
            return Outcome(rule, "invalid", actual, target)
        member = any(_same(actual, t) for t in target)
        return Outcome(rule, "pass" if member == (rule.op == "in") else "fail", actual, target)
    # superset / subset over list facts
    if not isinstance(actual, list) or len(actual) > MAX_LIST:
        return Outcome(rule, "invalid", actual, target)
    if not isinstance(target, list) or not all(_scalar(x) for x in [*actual, *target]):
        return Outcome(rule, "invalid", actual, target)
    a_set, t_set = {_key(x) for x in actual}, {_key(x) for x in target}
    ok = a_set >= t_set if rule.op == "superset" else a_set <= t_set
    return Outcome(rule, "pass" if ok else "fail", sorted(map(str, actual)), sorted(map(str, target)))
