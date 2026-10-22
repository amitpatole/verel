"""Content-credentials (C2PA) policy grading.

Verel does NOT do the cryptography. A C2PA implementation (`c2patool` or the `c2pa-python` library)
validates the manifest, signature and hashes; Verel grades the *result* of that validation against a
declared policy and binds the verdict into a signed receipt. Honest limits:

- "No manifest" is not "fake". Most real media has none. Policy decides whether that is acceptable.
- A VALID manifest proves who signed what and that bytes are unchanged since signing. It does not prove
  the content is true, and this module does not detect deepfakes.
- If no C2PA backend is available the grader FAILS CLOSED (it never reports PASS for unverified media).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..ci.graders import GraderSpec, _receipt
from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity
from ._io import clean, confine, load_json, read_text, sha256_file
from .grade import _yaml, assign_all, verdict_of

AI_SOURCE_TYPES = ("trainedalgorithmicmedia", "compositewithtrainedalgorithmicmedia", "algorithmicmedia",
                   "compositesynthetic")
# C2PA validation_status entries mix informational SUCCESS codes with failures. We classify the codes we
# KNOW to be benign and treat everything else as a failure, because the failure list is open-ended
# (claimSignature.*, signingCredential.ocsp.*, timeStamp.*, algorithm.*, general.* …) and an unknown code
# must never read as "valid". The only non-failure special case is an untrusted signer.
_BENIGN_SUFFIXES = (".validated", ".match", ".trusted", ".accessible", ".insidevalidity", ".notrevoked")
# Informational: revocation status could not be checked. Not a tamper finding, but surfaced as a WARNING.
_INFO_CODES = ("signingcredential.ocsp.skipped", "signingcredential.ocsp.inaccessible")
_UNTRUSTED_CODES = ("signingcredential.untrusted",)


def _is_failure(code: str) -> bool:
    c = code.strip().lower()
    return bool(c) and c not in _UNTRUSTED_CODES and c not in _INFO_CODES and not c.endswith(_BENIGN_SUFFIXES)
AI_POLICIES = {"allow", "flag", "deny"}


@dataclass
class Policy:
    require_manifest: bool = True
    trusted_issuers: list[str] = field(default_factory=list)  # empty = do not restrict by issuer name
    require_trusted_credential: bool = False                  # require the library to report a trusted chain
    ai_generated: str = "flag"                                # allow | flag | deny


def parse_policy(data: Any) -> Policy:
    if data is None:
        return Policy()
    if not isinstance(data, dict):
        raise ValueError("provenance policy must be a mapping")
    if data.get("version") != 1:
        raise ValueError(f"unsupported provenance policy version: {data.get('version')!r} (expected 1)")
    unknown = set(data) - {"version", "require_manifest", "trusted_issuers", "require_trusted_credential",
                           "ai_generated"}
    if unknown:
        raise ValueError(f"unknown provenance policy key(s): {sorted(unknown)}")
    ai = str(data.get("ai_generated", "flag")).lower()
    if ai not in AI_POLICIES:
        raise ValueError(f"ai_generated must be one of {sorted(AI_POLICIES)}")
    ti = data.get("trusted_issuers") or []
    if not isinstance(ti, list) or not all(isinstance(x, str) for x in ti):
        raise ValueError("trusted_issuers must be a list of strings")
    return Policy(bool(data.get("require_manifest", True)), [x.strip().lower() for x in ti],
                  bool(data.get("require_trusted_credential", False)), ai)


@dataclass
class Facts:
    has_manifest: bool = False
    state: str = "unknown"          # valid | trusted | invalid | untrusted | unknown
    failure_codes: list[str] = field(default_factory=list)
    issuer: str = ""
    claim_generator: str = ""
    ai_generated: bool = False


def parse_manifest_report(doc: Any) -> Facts:
    """Interpret c2patool-style JSON (`active_manifest`, `manifests`, `validation_status`/`validation_state`).
    Unknown shapes degrade to `has_manifest=False`/`state=unknown`, never to a pass."""
    if doc is None:
        return Facts()
    if not isinstance(doc, dict):
        raise ValueError("manifest report must be a JSON object")
    manifests = doc.get("manifests")
    active = doc.get("active_manifest")
    m = manifests.get(active) if isinstance(manifests, dict) and isinstance(active, str) else None
    if not isinstance(m, dict):
        return Facts()
    f = Facts(has_manifest=True)
    raw_status = doc.get("validation_status")
    entries = raw_status if isinstance(raw_status, list) else []
    codes = [str(s.get("code", "")).lower() if isinstance(s, dict) else "" for s in entries]
    # An entry we cannot interpret (not an object, no code, blank code) or a status that is not a list is
    # treated as a FAILURE: unknown must never read as valid.
    malformed = (raw_status is not None and not isinstance(raw_status, list)) or any(
        not isinstance(s, dict) or not str(s.get("code", "")).strip() for s in entries
    )
    f.failure_codes = codes
    declared = str(doc.get("validation_state", "")).lower()
    # FAILURE CODES ALWAYS WIN: a report listing a tamper code is invalid no matter what state it declares.
    if declared == "invalid" or malformed or any(_is_failure(c) for c in codes):
        f.state = "invalid"
    elif declared == "trusted" and not any(c in _UNTRUSTED_CODES for c in codes):
        f.state = "trusted"
    elif any(c in _UNTRUSTED_CODES for c in codes):
        f.state = "untrusted"
    elif declared == "valid" or isinstance(raw_status, list) or "validation_state" in doc:
        f.state = "valid"
    si = m.get("signature_info")
    if isinstance(si, dict):
        f.issuer = str(si.get("issuer") or si.get("common_name") or "")
    f.claim_generator = str(m.get("claim_generator") or "")
    f.ai_generated = isinstance(manifests, dict) and any(
        _manifest_is_ai(x) for x in manifests.values() if isinstance(x, dict))
    return f


def _manifest_is_ai(m: dict) -> bool:
    """AI source type anywhere in this manifest's actions or templates (C2PA v1 and v2 shapes)."""
    assertions = m.get("assertions")
    for a in assertions if isinstance(assertions, list) else []:
        if not isinstance(a, dict) or not str(a.get("label", "")).startswith("c2pa.actions"):
            continue
        data = a.get("data")
        if not isinstance(data, dict):
            continue
        entries = []
        for key in ("actions", "templates"):
            v = data.get(key)
            entries += v if isinstance(v, list) else []
        for e in entries:
            src = str(e.get("digitalSourceType", "")) if isinstance(e, dict) else ""
            if src.rsplit("/", 1)[-1].lower() in AI_SOURCE_TYPES:
                return True
    return False


def _prov(sev: Severity, rid: str, msg: str) -> Issue:
    hard = sev in (Severity.ERROR, Severity.CRITICAL)
    return Issue(kind=IssueKind.PROVENANCE_ISSUE, severity=sev, source=GraderKind.PROVENANCE,
                 confidence=Confidence.HIGH if hard else Confidence.MEDIUM,
                 message=msg, locator="c2pa:active_manifest", locator_precise=True,
                 detail_json=json.dumps({"rule_id": rid}))


def grade_facts(f: Facts, p: Policy, *, backend_note: str = "") -> list[Issue]:
    out: list[Issue] = []
    if not f.has_manifest:
        if p.require_manifest:
            extra = f" ({backend_note})" if backend_note else ""
            msg = "no content credentials (C2PA manifest) found" + extra
            out.append(_prov(Severity.ERROR, "PROV-001", msg))
        return out
    if f.state == "invalid":
        codes = ", ".join(clean(c, 60) for c in f.failure_codes[:5]) or "validation failed"
        out.append(_prov(Severity.CRITICAL, "PROV-002",
                         f"content credentials FAILED validation (tampered or corrupt): {codes}"))
        return out
    if any(c in _INFO_CODES for c in f.failure_codes):
        out.append(_prov(Severity.WARNING, "PROV-010",
                         "revocation status could not be checked (OCSP skipped or unreachable)"))
    if f.state == "unknown":
        out.append(_prov(Severity.ERROR, "PROV-006", "credentials present but validation state unknown"))
    if p.require_trusted_credential and f.state != "trusted":
        out.append(_prov(Severity.ERROR, "PROV-004", "signing credential is not reported as trusted"))
    elif f.state == "untrusted":
        out.append(_prov(Severity.WARNING, "PROV-004", "signing credential is not on a trusted list"))
    if p.trusted_issuers and f.issuer.strip().lower() not in p.trusted_issuers:
        out.append(_prov(Severity.ERROR, "PROV-003",
                         f"issuer {clean(f.issuer) or '(none)'!r} is not in the trusted issuer list"))
    if f.ai_generated:
        if p.ai_generated == "deny":
            out.append(_prov(Severity.ERROR, "PROV-005", "declared AI-generated; policy denies it"))
        elif p.ai_generated == "flag":
            out.append(_prov(Severity.WARNING, "PROV-005", "declared AI-generated; needs human review"))
    return out


ManifestReader = Any  # Callable[[str], dict | None]; a path -> c2patool-style JSON (None = no manifest)


def read_with_c2patool(path: str, *, timeout: int = 60) -> dict | None:
    exe = shutil.which("c2patool")
    if exe is None:
        raise RuntimeError("c2patool not found")
    try:
        r = subprocess.run([exe, "--", path], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("c2patool timed out") from None
    except OSError as e:
        raise RuntimeError(f"c2patool could not run ({type(e).__name__})") from None
    if r.returncode != 0:
        # The file name is attacker-influenced and tools echo it: strip it BEFORE matching, and only
        # accept the tool's own leading diagnostic, so "No claim found.jpg" can't fake "no manifest".
        first = (r.stderr + r.stdout).replace(path, "").strip().splitlines()[:1]
        head = first[0].lower().removeprefix("error:").strip() if first else ""
        if head.startswith(("no claim found", "no jumbf", "no manifest")):
            return None
        raise RuntimeError(f"c2patool failed (exit {r.returncode})")
    data = load_json(r.stdout[: 8 * 1024 * 1024], "c2patool output")
    return data if isinstance(data, dict) else None


def read_with_c2pa_python(path: str) -> dict | None:
    try:
        import c2pa  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("c2pa-python not installed") from e
    try:
        reader = c2pa.Reader(path) if not hasattr(c2pa.Reader, "from_file") else c2pa.Reader.from_file(path)
        data = load_json(reader.json(), "c2pa reader output")
    except Exception as e:  # noqa: BLE001 - library error taxonomy varies by version
        if "ManifestNotFound" in type(e).__name__ or "no manifest" in str(e).lower():
            return None
        raise RuntimeError(f"c2pa reader failed ({type(e).__name__})") from None
    return data if isinstance(data, dict) else None


def default_reader(path: str) -> dict | None:
    errs = []
    for fn in (read_with_c2patool, read_with_c2pa_python):
        try:
            return fn(path)
        except RuntimeError as e:
            errs.append(str(e))
    raise RuntimeError("no usable C2PA backend: " + "; ".join(errs)
                       + " (install c2patool or `pip install 'verel[provenance]'`)")


def load_policy(repo: str, rel: str | None) -> tuple[Policy, str]:
    if rel is None:
        return Policy(), ""
    raw = read_text(repo, rel)
    data = load_json(raw, rel) if rel.lower().endswith(".json") else _yaml(raw)
    return parse_policy(data), raw


def grade_provenance(repo: str, *, asset: str | None = None, manifest_json: str | None = None,
                     policy: str | None = None, reader: ManifestReader | None = None,
                     attest: str = "hmac") -> Report:
    """Grade an asset's content credentials. Exactly one of `asset` (read via a C2PA backend) or
    `manifest_json` (a saved c2patool report, fully offline) is required."""
    if asset is None and manifest_json is None:
        raise ValueError("provide --asset and/or --manifest-json")
    pol, raw_pol = load_policy(repo, policy)
    note = ""
    asset_hash = ""
    covers = [policy] if policy else []
    if manifest_json is not None:
        raw = read_text(repo, manifest_json)
        doc = load_json(raw, manifest_json)
        # Alone, a saved report is UNVERIFIED input (anyone can hand-write one) and says so in the report.
        # With --asset, the asset is read through the C2PA backend and its manifest must AGREE with the
        # saved report; the asset bytes are then bound into the receipt.
        if asset is not None:
            asset_hash = sha256_file(repo, asset)
        bound = ("asset:" + asset_hash) if asset is not None else "unbound"
        nonce = f"manifest:{hashlib.sha256(raw.encode()).hexdigest()}:{bound}:{raw_pol}"
        covers.append(manifest_json)
        saved = parse_manifest_report(doc)
        issues = grade_facts(saved, pol)
        if asset is None:
            issues.append(_prov(Severity.INFO, "PROV-009",
                                "manifest report is unverified input: it is not tied to any asset"))
        else:
            try:
                live = parse_manifest_report((reader or default_reader)(confine(repo, asset)))
            except RuntimeError as e:
                issues.append(_prov(Severity.ERROR, "PROV-007",
                                    f"cannot confirm the report matches the asset: {clean(e, 160)}"))
            else:
                if (live.has_manifest, live.state, live.issuer, live.ai_generated, live.claim_generator) != (
                        saved.has_manifest, saved.state, saved.issuer, saved.ai_generated,
                        saved.claim_generator):
                    issues.append(_prov(Severity.CRITICAL, "PROV-008",
                                        "saved report does not match the asset's actual credentials"))
    else:
        assert asset is not None
        path = confine(repo, asset)
        asset_hash = sha256_file(repo, asset)
        nonce = "asset:" + asset_hash + raw_pol
        try:
            doc = (reader or default_reader)(path)
            issues = grade_facts(parse_manifest_report(doc), pol)
        except RuntimeError as e:
            note = clean(e, 200)
            issues = [_prov(Severity.ERROR, "PROV-007", f"provenance could not be verified: {note}")]
    issues = assign_all(issues)
    report = Report(verdict=verdict_of(issues), issues=issues, grader=GraderKind.PROVENANCE,
                    summary=f"provenance: {len(issues)} finding(s)")
    if asset_hash:
        report.artifacts["asset_sha256"] = asset_hash
    gs = GraderSpec(GraderKind.PROVENANCE, ["verel-ci", "provenance"], cwd=repo, covers=covers)
    report.run_receipt = _receipt(gs, report, nonce=nonce, attest=attest)
    return report
