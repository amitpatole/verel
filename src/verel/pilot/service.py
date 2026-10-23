"""Multi-tenant pilot service: the pilot workflow over HTTP, with identity, roles and per-tenant data.

- Authentication is ALWAYS required (tenants need an identity), even on loopback. Transport rules (a
  routable bind needs TLS) come from `verel.transport`.
- The tenant comes ONLY from the authenticated principal. No request field, header or path can name
  another tenant, so there is nothing to tamper with: tenant data lives under `<data>/tenants/<id>/`.
- Least privilege: `viewer` reads, `operator` records/labels/enqueues (shadow or advisory), `admin` may
  also request `enforce`, archive logs, and promote or demote graders.
- Every AUTHENTICATED allow/deny is written to the tenant's own hash-chained audit log. Unauthenticated
  attempts are only counted in memory: letting anonymous traffic write to a shared log would be a
  denial-of-service lever against every tenant.
- Evidence logs are MAC-domain-separated per tenant and kind, so one tenant's evidence cannot be replayed
  into another's.
"""

from __future__ import annotations

import json
import math
import os
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .._chainlog import LogBusy, LogCorrupt
from ..auth import Authenticator, Principal
from ..jobs import JobQueue, QuotaExceeded
from ..media._io import clean
from ..transport import TLSThreadingHTTPServer, build_server_context, enforce_bind_policy, scheme
from ..verdict.models import Report
from .evaluate import Evaluation, Label, evaluate
from .log import DuplicateArtifact
from .log import LogCorrupt as _PilotLogCorrupt
from .mode import Mode, parse_mode
from .policy import PolicyError, autodemote
from .shadow import run_pilot
from .tenancy import (
    LabelRecord,
    audit_log,
    current_labels,
    current_policy,
    label_log,
    pilot_log,
    policy_store,
    require_private_dir,
    tenant_dir,
)

MAX_BODY = 4 * 1024 * 1024
MAX_REPORTS = 64
MAX_LABELS = 500
MAX_INFLIGHT_PER_TENANT = 8  # concurrent mutating requests per tenant; the rest get 429, not a parked thread
PRIVILEGED = {"pilot:promote", "pilot:archive"}  # denials of these are rare and important: own, larger budget
PRIVILEGED_DENIAL_AUDIT_PER_MIN = 200
DENIAL_AUDIT_PER_MIN = 20  # audited 403s per principal per minute; beyond that they are only counted
MIN_REVIEWER_LABELS = 5  # a reviewer must have labeled at least this many (and 10% of all) to count
MIN_LABEL_AUTHORS = 2  # promotion to ENFORCE needs labels from at least this many reviewers
HTTP_JOB_KINDS = {"media_grade", "provenance_grade"}  # `webhook` jobs are created only by workers
_CORRUPT = (LogCorrupt, _PilotLogCorrupt)

# Server-side FLOORS for the readiness flag. A caller may ask for something STRICTER, never weaker, so a
# viewer cannot make a grader look "ready to enforce" by choosing thresholds.
DEFAULT_MIN_SAMPLES = 30
DEFAULT_MIN_PRECISION = 0.95
DEFAULT_MIN_RECALL = 0.5
DEFAULT_MAX_ERRORED = 0.05


class _HTTPError(Exception):
    def __init__(self, code: int, msg: str):
        self.code, self.msg = code, msg


class _Conflict(Exception):
    pass


def _num(q: dict[str, list[str]], key: str, default: float, *, stricter: str) -> float:
    if key not in q:
        return default
    try:
        v = float(q[key][0])
    except ValueError:
        raise _HTTPError(400, f"bad {key}") from None
    if not math.isfinite(v):
        raise _HTTPError(400, f"bad {key}")
    return max(v, default) if stricter == "higher" else min(v, default)


def _make_handler(root: Path, auth: Authenticator, queue: JobQueue, stats: dict[str, int]):
    denials: dict[tuple[str, str, bool], deque] = defaultdict(deque)
    inflight: dict[str, threading.BoundedSemaphore] = defaultdict(
        lambda: threading.BoundedSemaphore(MAX_INFLIGHT_PER_TENANT)
    )

    class H(BaseHTTPRequestHandler):
        _held: threading.BoundedSemaphore | None = None
        _last_body: dict = {}

        protocol_version = "HTTP/1.1"
        timeout = 30

        def log_message(self, *_a):
            pass

        def _send(self, code: int, body: dict, extra: dict | None = None) -> None:
            self.close_connection = True  # no keep-alive: structurally no request smuggling/desync
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _framing(self) -> None:
            if self.headers.get("Transfer-Encoding"):
                raise _HTTPError(400, "Transfer-Encoding not supported")
            if len(self.headers.get_all("Content-Length") or []) > 1:
                raise _HTTPError(400, "duplicate Content-Length")

        def _body(self) -> dict:
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise _HTTPError(400, "bad Content-Length") from None
            if n < 0 or n > MAX_BODY:
                raise _HTTPError(413, "request body too large")
            try:
                obj = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, RecursionError):
                raise _HTTPError(400, "body is not valid JSON") from None
            if not isinstance(obj, dict):
                raise _HTTPError(400, "body must be a JSON object")
            return obj

        def _principal(self) -> Principal:
            p = auth.authenticate(self.headers.get("Authorization"))
            if p is None:
                stats["unauthenticated"] = stats.get("unauthenticated", 0) + 1  # counted, never persisted
                raise _HTTPError(401, "unauthorized")
            return p

        def _audit(
            self, p: Principal, action: str, allowed: bool, reason: str = "", *, best_effort: bool = False
        ) -> None:
            """Mutations and denials are audited; reads are not (a read-only token must not be able to fill
            the audit log). If the record cannot be written the action is refused, except for
            `best_effort` housekeeping (archiving) that is needed to make room."""
            try:
                audit_log(root, p.tenant).log(p, action, allowed, reason)
            except Exception:  # noqa: BLE001
                if not best_effort:
                    raise _HTTPError(503, "audit log unavailable") from None

        def _need(self, p: Principal, perm: str, action: str) -> None:
            if not p.can(perm):
                # Denials are audited, but at most DENIAL_AUDIT_PER_MIN per principal per minute: a token that
                # keeps hitting 403 must not be able to fill the log. The rest are only counted.
                now = time.monotonic()
                recent = denials[(p.tenant, p.id, perm in PRIVILEGED)]
                while recent and now - recent[0] > 60:
                    recent.popleft()
                budget = PRIVILEGED_DENIAL_AUDIT_PER_MIN if perm in PRIVILEGED else DENIAL_AUDIT_PER_MIN
                if len(recent) < budget:
                    recent.append(now)
                    self._audit(p, action, False, f"missing {perm}")
                else:
                    stats["denials_not_audited"] = stats.get("denials_not_audited", 0) + 1
                raise _HTTPError(403, "forbidden")

        def _reviewers(self, p: Principal, *, exclude: str = "") -> int:
            """Distinct people who ORIGINALLY labeled a meaningful share of the evidence that actually scores.
            Only labels that count count: the artifact must be in the evidence set and the label must not come
            from the one who recorded it. Amendments, the promoter, and a reviewer who labeled one stray
            artifact do not count."""
            recorder: dict[str, str] = {}
            for r in self._evidence_records(p):
                recorder.setdefault(r.artifact_id, r.recorded_by)
            originals = [
                r
                for r in label_log(root, p.tenant).records()
                if not r.amend and r.artifact_id in recorder and recorder[r.artifact_id] != r.by
            ]
            if not originals:
                return 0
            per: dict[str, int] = defaultdict(int)
            for r in originals:
                per[r.by] += 1
            floor = max(MIN_REVIEWER_LABELS, len(originals) // 10)
            return sum(1 for who, n in per.items() if who != exclude and n >= floor)

        def _evaluation(self, p: Principal, q: dict[str, list[str]]) -> Evaluation:
            kw: dict = {
                "warn_is_positive": q.get("warn_positive", ["0"])[0] == "1",
                "min_samples": int(_num(q, "min_samples", DEFAULT_MIN_SAMPLES, stricter="higher")),
                "min_precision": min(1.0, _num(q, "min_precision", DEFAULT_MIN_PRECISION, stricter="higher")),
                "min_recall": min(1.0, _num(q, "min_recall", DEFAULT_MIN_RECALL, stricter="higher")),
                "max_errored_rate": _num(q, "max_errored_rate", DEFAULT_MAX_ERRORED, stricter="lower"),
            }
            return evaluate(self._evidence_records(p), self._labels(p), **kw)

        def _evidence_records(self, p: Principal) -> list:
            """Decisions that may count as EVIDENCE for promotion, demotion and the readiness flag.

            Over HTTP the caller supplies the grader's report, so those decisions are SELF-REPORTED and prove
            nothing about the grader. By default only decisions Verel produced itself (a worker, or the hot
            folder grading a file it hashed) count. `VEREL_EVIDENCE_ALLOW_SELF_REPORTED=1` opts a pilot that
            has no workers back in."""
            recs = pilot_log(root, p.tenant).records()
            flag = os.environ.get("VEREL_EVIDENCE_ALLOW_SELF_REPORTED", "").strip().lower()
            if flag in ("1", "true", "yes"):
                return recs
            # ...and only when the facts named THIS file's hash: otherwise an enqueue-only operator could
            # point jobs at any facts file and mint "measured" decisions for assets never examined.
            # `bound` is only set by a trusted in-process grader; the ref check also covers older records.
            return [r for r in recs if (r.ref.startswith("job:") or r.ref == "hotfolder") and r.bound]

        def _labels(self, p: Principal) -> list[Label]:
            """Labels usable as EVIDENCE: a person who recorded a decision cannot also be the one whose label
            scores it. Otherwise a single operator can fabricate both halves (fake FAILs plus matching labels)
            to earn a promotion or to get a good grader demoted."""
            recorder: dict[str, str] = {}
            for r in pilot_log(root, p.tenant).records():
                recorder.setdefault(r.artifact_id, r.recorded_by)  # first decision, as in evaluation
            cur = current_labels(label_log(root, p.tenant).records())
            return [
                Label(artifact_id=r.artifact_id, defect=r.defect)
                for r in cur.values()
                if not recorder.get(r.artifact_id) or recorder[r.artifact_id] != r.by
            ]

        def _dispatch(self, method: str) -> None:
            self._framing()
            u = urlsplit(self.path)
            route, q = u.path, parse_qs(u.query, max_num_fields=16)
            if method == "GET" and route == "/health":
                return self._send(200, {"status": "ok"})
            action = f"{method} {route}"
            p = self._principal()
            tenant_dir(root, p.tenant)
            if method == "POST":
                sem = inflight[p.tenant]
                if not sem.acquire(blocking=False):
                    raise _HTTPError(429, "too many concurrent write requests for this tenant")
                self._held = sem

            if method == "POST" and route == "/v1/pilot/record":
                self._need(p, "pilot:record", action)
                b = self._body()
                policy = current_policy(root, p.tenant)
                if policy is not None:
                    if str(b.get("mode", "policy")).strip().lower() != "policy":
                        raise _HTTPError(
                            400, "this tenant has a promotion policy; the mode is not selectable"
                        )
                    mode = Mode.POLICY
                else:
                    mode = parse_mode(b.get("mode", "shadow"))
                    if mode is Mode.POLICY:
                        raise _HTTPError(400, "this tenant has no promotion policy")
                    if mode is Mode.ENFORCE:
                        self._need(p, "pilot:promote", action + " mode=enforce")
                raw = b.get("reports")
                if not isinstance(raw, list) or not raw or len(raw) > MAX_REPORTS:
                    raise _HTTPError(400, f"reports must be a list of 1..{MAX_REPORTS} Reports")
                self._audit(p, action, True, "record")
                try:
                    dec = run_pilot(
                        [Report.model_validate(r) for r in raw],
                        artifact_id=str(b.get("artifact_id", "")),
                        mode=mode,
                        log=pilot_log(root, p.tenant),
                        tenant=p.tenant,
                        policy=policy,
                        unique=True,
                        ref=p.id,
                        recorded_by=p.id,
                    )
                except DuplicateArtifact:
                    raise _HTTPError(
                        409, "this artifact id already has a decision; record a new version under a new id"
                    ) from None
                return self._send(200, dec.model_dump(mode="json"))

            if method == "POST" and route in ("/v1/pilot/labels", "/v1/pilot/labels/amend"):
                amend = route.endswith("/amend")
                self._need(p, "pilot:promote" if amend else "pilot:label", action)
                rows = self._body().get("labels")
                if not isinstance(rows, list) or not rows or len(rows) > MAX_LABELS:
                    raise _HTTPError(400, f"labels must be a list of 1..{MAX_LABELS}")
                parsed = [Label.model_validate(r) for r in rows]
                # Labels may only describe artifacts that were actually graded: a reviewer cannot pre-label
                # (and so lock in the ground truth for) assets that have not been recorded yet.
                known = {r.artifact_id for r in pilot_log(root, p.tenant).records()}
                if any(lab.artifact_id not in known for lab in parsed):
                    raise _HTTPError(409, "labels may only describe artifacts with a recorded decision")
                stamp = datetime.now(timezone.utc).isoformat()

                llog = label_log(root, p.tenant)

                def make(existing):
                    seen = {
                        r.artifact_id: r.defect for r in current_labels(existing).values()
                    }  # UNDER the lock
                    new = []
                    for lab in parsed:
                        if lab.artifact_id in seen:
                            if seen[lab.artifact_id] == lab.defect:
                                continue
                            if not amend:
                                raise _Conflict  # only an admin amendment may change a label
                        elif amend:
                            continue  # nothing to amend
                        elif llog.archived_has(lab.artifact_id):
                            raise _Conflict  # labeled before and archived: retention does not reopen a label
                        seen[lab.artifact_id] = lab.defect
                        new.append(
                            LabelRecord(
                                ts=stamp, by=p.id, artifact_id=lab.artifact_id, defect=lab.defect, amend=amend
                            )
                        )
                    return new

                self._audit(
                    p, action, True, f"attempt n={len(parsed)}"
                )  # intent is recorded BEFORE it takes effect
                try:
                    added = len(llog.append_batch(make))
                except _Conflict:
                    self._audit(p, action, False, "conflicting label")
                    raise _HTTPError(
                        409, "conflicting label for an already-labeled artifact (an admin can amend)"
                    ) from None
                return self._send(200, {"added": added})

            if method == "POST" and route == "/v1/pilot/health":
                self._need(
                    p, "pilot:promote", action
                )  # demotion is triggered by an admin or a scheduled job,
                self._audit(p, action, True, "autodemote check")
                demoted = autodemote(  # never as a side effect of an operator's own labels
                    policy_store(root, p.tenant), self._evidence_records(p), self._labels(p)
                )
                return self._send(
                    200, {"autodemoted": [{"grader": h.grader, "reason": h.reason} for h in demoted]}
                )

            if method == "GET" and route == "/v1/pilot/evaluation":
                self._need(p, "pilot:read", action)
                ev = self._evaluation(p, q)
                out = ev.model_dump(mode="json")
                cur = current_labels(label_log(root, p.tenant).records())
                out["label_authors"] = len({r.by for r in cur.values()})
                out["reviewers"] = self._reviewers(p)  # distinct people with a meaningful share of the labels
                all_recs = pilot_log(root, p.tenant).records()
                out["self_reported_excluded"] = len(all_recs) - len(self._evidence_records(p))
                out["thresholds_are_server_floors"] = True
                return self._send(200, out)

            if method == "GET" and route == "/v1/pilot/verify":
                self._need(p, "pilot:read", action)
                log = pilot_log(root, p.tenant)
                n, lab_n = log.verify(), label_log(root, p.tenant).verify()
                return self._send(
                    200,
                    {
                        "decisions": n,
                        "labels": lab_n,
                        "head": log.head(),
                        "missing_archive_segments": log.missing_segments(),
                    },
                )

            if method == "POST" and route == "/v1/pilot/archive":
                self._need(p, "pilot:archive", action)
                self._last_body = self._body()
                keep = self._last_body.get("keep_last")
                if isinstance(keep, bool) or not isinstance(keep, int) or keep < 0:
                    raise _HTTPError(400, "keep_last must be a non-negative integer")
                which = str(self._last_body.get("log", "pilot"))
                if which not in ("pilot", "labels", "audit"):
                    raise _HTTPError(400, "log must be pilot, labels or audit")
                log = {"pilot": pilot_log, "labels": label_log, "audit": audit_log}[which](root, p.tenant)
                total = log.verify()
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                # best effort: archiving frees a FULL audit log, so it must not need a free slot
                # Only the audit log's own archive may proceed unaudited (it is what frees a FULL audit log).
                self._audit(p, action, True, f"{which} keep_last={keep}", best_effort=(which == "audit"))
                moved = log.archive_first(
                    max(0, total - keep), tenant_dir(root, p.tenant) / f"{which}.{stamp}.archive"
                )
                return self._send(200, {"archived": moved, "live": log.verify(), "head": log.head()})

            if route == "/v1/pilot/policy" and method == "GET":
                self._need(p, "pilot:read", action)
                store = policy_store(root, p.tenant)
                pol = store.current()
                return self._send(
                    200,
                    {
                        "default": pol.default.value,
                        "graders": {g: m.value for g, m in pol.graders.items()},
                        "history": [
                            r.model_dump(mode="json", exclude={"prev_hash", "hash", "mac"})
                            for r in store.records()
                        ][-50:],
                    },
                )

            if method == "POST" and route in ("/v1/pilot/promote", "/v1/pilot/demote", "/v1/pilot/default"):
                self._need(p, "pilot:promote", action)
                b = self._body()
                store = policy_store(root, p.tenant)
                self._audit(p, action, True, f"requested {clean(b.get('grader', ''), 24)}")
                try:
                    if route.endswith("promote"):
                        ev = self._evaluation(p, {})  # evidence is computed HERE from the tenant's own data
                        override = b.get("override_reason")
                        rec = store.promote(
                            str(b.get("grader", "")),
                            str(b.get("to", "")),
                            p.id,
                            ev,
                            reason=str(b.get("reason", "")),
                            override_reason=override if isinstance(override, str) else None,
                            label_authors=self._reviewers(p, exclude=p.id),
                            require_label_authors=MIN_LABEL_AUTHORS,
                        )
                    elif route.endswith("demote"):
                        rec = store.demote(
                            str(b.get("grader", "")),
                            str(b.get("to", "advisory")),
                            p.id,
                            str(b.get("reason", "")),
                        )
                    else:
                        rec = store.set_default(str(b.get("mode", "")), p.id, str(b.get("reason", "")))
                except PolicyError as e:
                    self._audit(p, action, False, clean(e, 120))
                    raise _HTTPError(409, clean(e, 300)) from None
                return self._send(200, rec.model_dump(mode="json", exclude={"prev_hash", "hash", "mac"}))

            if method == "POST" and route == "/v1/jobs":
                self._need(p, "jobs:enqueue", action)
                b = self._body()
                kind, payload = b.get("kind"), b.get("payload")
                if kind not in HTTP_JOB_KINDS or not isinstance(payload, dict):
                    raise _HTTPError(
                        400, f"kind must be one of {sorted(HTTP_JOB_KINDS)} with an object payload"
                    )
                asked = payload.get("mode")
                if current_policy(root, p.tenant) is not None:
                    if asked not in (None, "policy"):
                        raise _HTTPError(
                            400, "this tenant has a promotion policy; the mode is not selectable"
                        )
                elif str(asked).strip().lower() == "enforce":
                    self._need(p, "pilot:promote", action + " mode=enforce")
                dedupe, attempts = b.get("dedupe_key"), b.get("max_attempts", 3)
                if dedupe is not None and not isinstance(dedupe, str):
                    raise _HTTPError(400, "dedupe_key must be a string")
                if isinstance(attempts, bool) or not isinstance(attempts, int):
                    raise _HTTPError(400, "max_attempts must be an integer")
                self._audit(p, action, True, str(kind))
                try:
                    jid = queue.enqueue(
                        p.tenant,
                        str(kind),
                        payload,
                        dedupe_key=dedupe,
                        max_attempts=attempts,
                        by=p.id,
                    )
                except QuotaExceeded as e:
                    raise _HTTPError(429, clean(e, 200)) from None
                return self._send(202, {"id": jid})

            if method == "GET" and route == "/v1/jobs":
                self._need(p, "jobs:read", action)
                return self._send(200, queue.stats(p.tenant))

            if method == "GET" and route.startswith("/v1/jobs/"):
                self._need(p, "jobs:read", action)
                row = queue.get(p.tenant, route[len("/v1/jobs/") :][:64])
                if row is None:
                    raise _HTTPError(404, "not found")
                return self._send(200, row)

            raise _HTTPError(404, "not found")

        def _run(self, method: str) -> None:
            try:
                self._dispatch(method)
            except LogBusy:
                self._send(503, {"error": "evidence log is busy; retry shortly"}, {"Retry-After": "2"})
            except _HTTPError as e:
                hdr = {"WWW-Authenticate": "Bearer"} if e.code == 401 else None
                self._send(e.code, {"error": e.msg}, hdr)
            except _CORRUPT:
                self._send(500, {"error": "evidence log failed integrity verification"})
            except ValueError as e:  # includes pydantic ValidationError: never echo raw input back
                self._send(400, {"error": "invalid request: " + clean(e, 160)})
            except Exception as e:  # noqa: BLE001 - never leak internals
                self._send(500, {"error": type(e).__name__})
            finally:
                if self._held is not None:
                    self._held.release()
                    self._held = None

        def do_GET(self):  # noqa: N802
            self._run("GET")

        def do_POST(self):  # noqa: N802
            self._run("POST")

    return H


class PilotServer:
    def __init__(
        self,
        data_dir: str | Path,
        authenticator: Authenticator,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        certfile=None,
        keyfile=None,
        ssl_context: ssl.SSLContext | None = None,
        insecure: bool = False,
        max_connections: int = 128,
        max_per_ip: int | None = None,
    ):
        self.root = Path(data_dir)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        require_private_dir(self.root)
        self.queue = JobQueue(self.root / "jobs.sqlite")
        self.stats: dict[str, int] = {}
        ctx = build_server_context(certfile, keyfile, ssl_context)
        self._tls = ctx is not None
        # Auth is always on, so the bind policy's token requirement is satisfied by construction.
        enforce_bind_policy(host, auth_token="x", tls=self._tls, service="pilot service", insecure=insecure)
        handler = _make_handler(self.root, authenticator, self.queue, self.stats)
        self._httpd = TLSThreadingHTTPServer(
            (host, port), handler, ssl_context=ctx, max_connections=max_connections, max_per_ip=max_per_ip
        )
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"{scheme(self._tls)}://{host}:{port}"

    def start(self) -> PilotServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
