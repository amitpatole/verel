"""Hot-folder connector: the media industry's native integration. Drop a file in, get a verdict out.

Layout under `root` (all one filesystem):

    incoming/            watched. For `ep.mxf` the measurements sidecar is `ep.mxf.facts.json`
    spec.yaml            the delivery spec (grade_media)
    passed/ review/ quarantine/    destinations, used only outside shadow mode
    ep.mxf.verel.json    the verdict sidecar written next to the asset

Guardrails (this moves business files, so they are strict):
- default mode is SHADOW: grade and record, never move anything;
- files are only RENAMED within `root` (never copied-then-deleted, never overwritten, never deleted);
- symlinks, non-regular files, hidden/temp names and anything still changing are ignored;
- a missing measurements sidecar waits, then quarantines with an explicit FAIL after `facts_timeout_s`:
  an asset nobody measured is never passed;
- bounded work per scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .._chainlog import _eq, _mac, _write_atomic
from ..pilot import Mode, parse_mode, run_pilot
from ..pilot.log import DuplicateArtifact
from ..pilot.tenancy import current_policy, pilot_log, tenant_dir
from ..verdict.fingerprint import assign
from ..verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict

_SKIP = re.compile(r"(^\.)|(\.(part|tmp|partial|crdownload|swp)$)|(~$)|(\.verel\.json$)|(\.facts\.json$)")
_ID_BAD = re.compile(r"[^A-Za-z0-9._:/@+=-]")
DEST = {Verdict.PASS: "passed", Verdict.WARN: "review", Verdict.FAIL: "quarantine"}


@dataclass
class HotFolder:
    root: Path
    data_dir: Path
    tenant: str
    spec: str = "spec.yaml"
    mode: str = "shadow"
    settle_s: float = 5.0
    facts_timeout_s: float = 3600.0
    max_per_scan: int = 200
    continuous: bool = False  # True for the long-running watcher (adds observed-stability)
    # The facts must name the file they measured (asset.sha256) and it must match the dropped file.
    # Anyone who can write into incoming/ can otherwise pair a bad file with a good file's facts.
    require_binding: bool = True
    _cursor: int = field(default=0, repr=False)
    _seen: dict[str, tuple[int, int, float]] = field(default_factory=dict, repr=False)


@dataclass
class Outcome:
    name: str
    action: str  # graded | waiting | settling | skipped
    enforced: str = ""
    would_be: str = ""
    moved_to: str = ""
    note: str = ""


MAX_VERSIONS_PER_NAME = (
    50  # a sender can touch a file endlessly; each new version is evidence, so it is capped
)
MAX_SEEN = 20_000
VERSION_WINDOW_S = 86_400


def _sig(st: os.stat_result) -> list[int]:
    """size, mtime and ctime. ctime cannot be reset by a writer, so swapping content under a restored mtime
    still changes the signature."""
    return [st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _aid(rel: str, st: os.stat_result, content: str = "") -> str:
    """Artifact id = path + version (size, mtime): a modified file is a NEW artifact. A metadata-only change
    keeps the id and is re-decided without a new record."""
    # raw-name digest: two names that sanitize alike ("a b" / "a_b") are still different artifacts;
    # content digest: swapped bytes under a restored mtime are a different version, hence recorded
    raw = hashlib.sha256(rel.encode("utf-8", "replace")).hexdigest()[:8]
    tail = f"-{content[:12]}" if content else ""
    return f"hf:{_ID_BAD.sub('_', rel)[:140]}+{raw}@{st.st_size}-{st.st_mtime_ns}{tail}"


def _load_seen(path: Path) -> dict[str, float]:
    try:
        d = json.loads(path.read_text())
        return {str(k): float(v) for k, v in d.items()} if isinstance(d, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _save_seen(path: Path, seen: dict[str, float]) -> None:
    try:
        _write_atomic(path, json.dumps(seen))
    except OSError:
        pass


def _load_cursor(path: Path) -> int:
    try:
        return max(0, int(path.read_text().strip()))
    except (OSError, ValueError):
        return 0


def _save_cursor(path: Path, value: int) -> None:
    try:
        _write_atomic(path, str(value))
    except OSError:
        pass


def _unique(dest: Path) -> Path:
    if not dest.exists():
        return dest
    stem, suf = dest.stem, dest.suffix
    for i in range(1, 1000):
        cand = dest.with_name(f"{stem}-{i}{suf}")
        if not cand.exists():
            return cand
    raise OSError("no free destination name")


def _regular(path: Path) -> os.stat_result | None:
    try:
        st = path.lstat()  # lstat: a symlink is NOT followed
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def _stable(hf: HotFolder, key: str, st: os.stat_result, now: float) -> bool:
    """Has the file stopped changing? The mtime must be old enough; in a long-running watcher it must also
    have kept the same size/mtime for `settle_s` of OBSERVED time (catches a writer that keeps mtime)."""
    old_enough = now - st.st_mtime >= hf.settle_s
    if not hf.continuous:
        return old_enough
    sig = (st.st_size, st.st_mtime_ns)
    prev = hf._seen.get(key)
    if prev is None or prev[:2] != sig:
        hf._seen[key] = (*sig, now)
        return False
    return old_enough and now - prev[2] >= hf.settle_s


def _missing_facts_report(spec: str) -> Report:
    iss = [
        Issue(
            kind=IssueKind.SPEC_VIOLATION,
            severity=Severity.ERROR,
            source=GraderKind.MEDIA,
            message="no measurements were supplied for this asset (unmeasured is not passed)",
            locator="facts:(sidecar)",
            locator_precise=True,
            detail_json=json.dumps({"rule_id": "_no_facts"}),
        )
    ]
    r = Report(verdict=Verdict.FAIL, summary="media: no facts sidecar", issues=iss, grader=GraderKind.MEDIA)
    return assign(r)


def scan_once(hf: HotFolder, *, now: float | None = None) -> list[Outcome]:
    from ..media import grade_media

    t = time.time() if now is None else now
    mode = parse_mode(hf.mode)
    incoming = hf.root / "incoming"
    out: list[Outcome] = []
    if not incoming.is_dir():
        return out
    log = pilot_log(hf.data_dir, hf.tenant)
    policy = current_policy(hf.data_dir, hf.tenant) if mode is Mode.POLICY else None
    if mode is Mode.POLICY and policy is None:
        raise ValueError("mode 'policy' needs a tenant promotion policy (verel pilot promote)")
    root_real = hf.root.resolve()
    # Hidden/temp/sidecar names are filtered BEFORE the per-scan limit, so a pile of them cannot starve real
    # assets. The rotating start is persisted, so repeated `--once` runs also make progress.
    all_names = sorted(n for n in (p.name for p in incoming.iterdir()) if not _SKIP.search(n))
    tag = hashlib.sha256(str(root_real).encode()).hexdigest()[:12]
    cursor_file = tenant_dir(hf.data_dir, hf.tenant) / f"hotfolder-{tag}.cursor"
    seen_file = tenant_dir(hf.data_dir, hf.tenant) / f"hotfolder-{tag}.seen.json"
    seen = _load_seen(
        seen_file
    )  # when we FIRST saw each version of each file (not its mtime, which the sender controls)
    seen_before = dict(seen)
    begin = hf._cursor or _load_cursor(cursor_file)
    start = begin % len(all_names) if all_names else 0
    names = (all_names[start:] + all_names[:start])[: hf.max_per_scan]
    hf._cursor = start + len(names)
    _save_cursor(cursor_file, hf._cursor)
    done = 0
    for name in names:
        if _SKIP.search(name):
            continue
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:  # a name that is not valid text cannot be signed, recorded or reported
            shown = name.encode("utf-8", "replace").decode()
            out.append(Outcome(shown, "skipped", note="file name is not valid UTF-8"))
            continue
        asset = incoming / name
        st = _regular(asset)
        if st is None:
            out.append(Outcome(name, "skipped", note="not a regular file"))
            continue
        rel = f"incoming/{name}"
        sidecar = incoming / f"{name}.verel.json"
        doc = _verified_doc(sidecar, name)
        if doc is not None and doc.get("asset_sig") == _sig(st):
            # Already graded at this exact version (our own signed sidecar). In shadow mode that is all.
            # Otherwise finish a move that a crash interrupted, but only if it was decided in this mode.
            if (
                mode is Mode.SHADOW
                or doc.get("mode") != mode.value
                or doc.get("enforced") not in ("pass", "warn", "fail")
            ):
                continue
            try:
                moved_to = _move(root_real, incoming, name, DEST[Verdict(doc["enforced"])])
            except OSError as e:
                out.append(Outcome(name, "skipped", note=f"could not finish: {type(e).__name__}"))
                continue
            out.append(
                Outcome(
                    name,
                    "graded",
                    doc["enforced"],
                    str(doc.get("would_be")),
                    moved_to,
                    "finished a move that an earlier run did not complete",
                )
            )
            continue
        if not _stable(hf, rel, st, t):
            out.append(Outcome(name, "settling"))
            continue
        facts_rel = f"incoming/{name}.facts.json"
        facts_ok = _regular(hf.root / facts_rel) is not None
        if not facts_ok:
            first = seen.setdefault(f"{name}|{st.st_size}|{st.st_mtime_ns}", t)
            if t - first < hf.facts_timeout_s:
                out.append(Outcome(name, "waiting", note="waiting for measurements sidecar"))
                continue
            report = _missing_facts_report(hf.spec)
        else:
            try:
                report = grade_media(
                    str(hf.root),
                    facts=[facts_rel],
                    spec=hf.spec,
                    asset=rel,
                    require_asset_binding=hf.require_binding,
                )
            except (ValueError, OSError) as e:
                out.append(Outcome(name, "skipped", note=f"cannot grade: {type(e).__name__}"))
                continue
        aid = _aid(rel, st, report.artifacts.get("asset_sha256", ""))
        vkey, wkey = f"#v|{name}", f"#w|{name}"
        if t - seen.get(wkey, 0.0) > VERSION_WINDOW_S:  # the cap is per 24 h: no permanent block
            seen[wkey], seen[vkey] = t, 0
        versions = int(seen.get(vkey, 0))
        if versions >= MAX_VERSIONS_PER_NAME:
            out.append(Outcome(name, "skipped", note="too many recorded versions of this file name"))
            continue
        dec: Any
        try:
            dec = run_pilot(
                [report],
                artifact_id=aid,
                mode=mode,
                log=log,
                tenant=hf.tenant,
                policy=policy,
                unique=True,
                ref="hotfolder",
                recorded_by="hotfolder",
            )
            seen[vkey] = versions + 1
        except DuplicateArtifact as dup:
            prior = dup.existing
            if prior is None or getattr(prior, "ref", "") != "hotfolder":
                out.append(Outcome(name, "skipped", note="this exact version was already recorded"))
                continue
            # We recorded this exact version before and did not finish (a crash, or a metadata-only change).
            # Do NOT copy the old verdict: it may have been decided in another mode (a shadow PASS must never
            # release a file under enforce). Decide again under the CURRENT mode/policy, without a new record.
            dec = run_pilot([report], artifact_id=aid, mode=mode, log=None, tenant=hf.tenant, policy=policy)
        moved = ""
        note = ""
        try:
            _write_sidecar(sidecar, name, st, report, dec.would_be.value, dec.enforced.value, mode.value)
            if mode is not Mode.SHADOW:
                now_st = _regular(asset)
                if now_st is None or _sig(now_st) != _sig(st):
                    note = "file changed while it was being graded; left in place and graded again next scan"
                else:
                    moved = _move(root_real, incoming, name, DEST[dec.enforced])
        except (
            OSError,
            ValueError,
        ) as e:  # e.g. a hostile directory where the sidecar belongs: skip THIS file
            out.append(Outcome(name, "skipped", note=f"could not finish: {type(e).__name__}"))
            continue
        out.append(Outcome(name, "graded", dec.enforced.value, dec.would_be.value, moved, note))
        done += 1
    live_names = set(all_names)

    def base(k: str) -> str:  # O(1) per key: a version/window counter, or "<name>|<size>|<mtime>"
        return k[3:] if k.startswith(("#v|", "#w|")) else k.rsplit("|", 2)[0]

    pruned = {k: v for k, v in seen.items() if base(k) in live_names}
    stamps = {k: v for k, v in pruned.items() if not k.startswith("#")}
    if (
        len(stamps) > MAX_SEEN
    ):  # drop the OLDEST first-seen times; the per-name version counters are never evicted
        keep = dict(sorted(stamps.items(), key=lambda kv: kv[1], reverse=True)[:MAX_SEEN])
        pruned = {k: v for k, v in pruned.items() if k.startswith("#") or k in keep}
    if pruned != seen_before:
        _save_seen(seen_file, pruned)
    return out


def _sidecar_mac(name: str, sig: list[int], would_be: str, enforced: str, mode: str) -> str:
    return _mac(f"{name}|{sig[0]}|{sig[1]}|{sig[2]}|{would_be}|{enforced}|{mode}", "hotfolder-sidecar")


def _verified_doc(sidecar: Path, name: str) -> dict | None:
    """OUR sidecar's contents, or None. Sidecars are signed with the installation's key, so a hand-written or
    copied one (which would otherwise suppress grading and carry a PASS) is ignored."""
    try:
        if _regular(sidecar) is None or sidecar.stat().st_size > 2_000_000:
            return None
        doc = json.loads(sidecar.read_text())
        sig = doc.get("asset_sig")
        if not (isinstance(sig, list) and len(sig) == 3 and all(isinstance(x, int) for x in sig)):
            return None
        want = _sidecar_mac(
            name, sig, str(doc.get("would_be")), str(doc.get("enforced")), str(doc.get("mode"))
        )
        return doc if _eq(want, str(doc.get("mac", ""))) else None
    except (OSError, ValueError, AttributeError):
        return None


def _write_sidecar(
    path: Path, name: str, st: os.stat_result, report: Report, would_be: str, enforced: str, mode: str
) -> None:
    sig = _sig(st)
    body = {
        "asset_sig": sig,
        "would_be": would_be,
        "enforced": enforced,
        "mode": mode,
        "mac": _sidecar_mac(name, sig, would_be, enforced, mode),
        "report": report.model_dump(mode="json"),
    }
    _write_atomic(path, json.dumps(body, indent=2))  # exclusive unique temp: no symlink clobber


def _move(root_real: Path, incoming: Path, name: str, dest_name: str) -> str:
    """Rename the asset and its sidecars into <root>/<dest>/ — never overwrite, never leave the root."""
    dest_dir = root_real / dest_name
    dest_dir.mkdir(exist_ok=True)
    if dest_dir.resolve().parent != root_real:
        raise OSError("destination escapes the hot-folder root")
    base = _unique(dest_dir / name).name  # one collision-free base name for the asset and its sidecars
    moved = ""
    for suffix in ("", ".facts.json", ".verel.json"):
        src = incoming / f"{name}{suffix}"
        if _regular(src) is None:
            continue
        dst = dest_dir / f"{base}{suffix}"
        if dst.exists():
            raise OSError(f"refusing to overwrite {dst.name}")
        os.rename(src, dst)  # same filesystem or it raises: no copy+delete fallback
        if suffix == "":
            moved = str(dst.relative_to(root_real))
    return moved
