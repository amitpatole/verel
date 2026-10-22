"""Workers: claim → handle → complete/fail, with a lease heartbeat for slow handlers.

Handlers are an allowlist keyed by job kind. A payload never names a path directly: it names a configured
ROOT (operator config) plus repo-relative paths that the graders confine themselves, and it never names a
webhook destination, only a sink id the operator configured for that tenant."""

from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from ..connectors.webhook import DeliveryError, Sink, deliver
from ..pilot import run_pilot
from ..pilot.log import DuplicateArtifact
from ..pilot.tenancy import current_policy, pilot_log, tenant_dir
from .queue import Job, JobQueue, LeaseLost

log = logging.getLogger("verel.jobs")


class PermanentError(Exception):
    """Do not retry: the job itself is wrong (bad payload, forbidden path, unknown root)."""


@dataclass
class WorkerContext:
    data_dir: Path
    # tenant -> root name -> directory. A tenant can only name roots the operator bound to IT.
    roots: dict[str, dict[str, Path]] = field(default_factory=dict)
    # (tenant, root name, "spec" | "policy") -> repo-relative path of the delivery spec / provenance policy.
    # A pinned spec cannot be swapped by the requester; policy/enforce modes REQUIRE a pinned spec.
    pins: dict[tuple[str, str, str], str] = field(default_factory=dict)
    sinks: dict[str, dict[str, Sink]] = field(default_factory=dict)  # tenant -> sink id -> Sink
    queue: JobQueue | None = None


Handler = Callable[[Job, WorkerContext], dict[str, Any]]


def _root(job: Job, ctx: WorkerContext) -> str:
    name = job.payload.get("root")
    mine = ctx.roots.get(job.tenant, {})
    if not isinstance(name, str) or name not in mine:
        raise PermanentError("unknown root")
    return str(mine[name])


def _pinned(job: Job, ctx: WorkerContext, kind: str, requested: object, mode: str) -> str | None:
    """The spec/policy to use: the operator's pin if there is one (a conflicting request is refused);
    otherwise the requested path, but only in modes that cannot block (shadow/advisory)."""
    pin = ctx.pins.get((job.tenant, str(job.payload.get("root")), kind))
    if pin is not None:
        if requested not in (None, pin):
            raise PermanentError(f"the {kind} for this root is pinned by the operator")
        return pin
    if mode in ("policy", "enforce"):
        raise PermanentError(f"{mode} mode requires an operator-pinned {kind} for this root")
    return requested if isinstance(requested, str) else None


def _mode(job: Job, ctx: WorkerContext) -> str:
    """policy tenants always run in `policy`; others choose shadow/advisory/enforce. No mode confusion."""
    asked = job.payload.get("mode")
    has_policy = current_policy(ctx.data_dir, job.tenant) is not None
    if has_policy:
        if asked not in (None, "policy"):
            raise PermanentError("this tenant has a promotion policy; the mode is not selectable")
        return "policy"
    mode = "shadow" if asked is None else asked
    if mode not in ("shadow", "advisory", "enforce"):
        raise PermanentError("bad mode")
    return str(mode)


def _artifact_id(job: Job) -> str:
    aid = job.payload.get("artifact_id")
    if not isinstance(aid, str):
        raise PermanentError("artifact_id is required")
    return aid


def _validate(job: Job, ctx: WorkerContext) -> None:
    """Reject a bad job BEFORE any grading or recording, so a hostile payload has no side effects."""
    from ..pilot.log import valid_artifact_id

    try:
        valid_artifact_id(_artifact_id(job))
        tenant_dir(ctx.data_dir, job.tenant)
    except ValueError:
        raise PermanentError("bad artifact_id or tenant") from None
    sink = job.payload.get("notify")
    if sink is not None and (not isinstance(sink, str) or sink not in ctx.sinks.get(job.tenant, {})):
        raise PermanentError("unknown notify sink")


@dataclass
class _Prior:
    would_be: Any
    enforced: Any


def _finish(job: Job, ctx: WorkerContext, report: Any) -> dict[str, Any]:
    mode = _mode(job, ctx)
    policy = current_policy(ctx.data_dir, job.tenant) if mode == "policy" else None
    dec: Any
    try:
        dec = run_pilot(
            [report],
            artifact_id=_artifact_id(job),
            mode=mode,
            tenant=job.tenant,
            log=pilot_log(ctx.data_dir, job.tenant),
            policy=policy,
            unique=True,
            ref=f"job:{job.id}",
            recorded_by=job.by,
        )
    except DuplicateArtifact as dup:
        prior = dup.existing
        if prior is None or getattr(prior, "ref", "") != f"job:{job.id}":
            raise PermanentError(
                "this artifact id already has a decision; use a new id for a new version"
            ) from None
        prior_v: Any = prior
        dec = _Prior(prior_v.would_be, prior_v.enforced)  # our own earlier attempt: the retry is idempotent
    result = {
        "verdict": report.verdict.value,
        "would_be": dec.would_be.value,
        "enforced": dec.enforced.value,
        "findings": len([i for i in report.issues if i.severity.value != "info"]),
    }
    sink = job.payload.get("notify")
    if sink is not None and ctx.queue is not None:
        if not isinstance(sink, str) or sink not in ctx.sinks.get(job.tenant, {}):
            raise PermanentError("unknown notify sink")
        digest = hashlib.sha256(_artifact_id(job).encode()).hexdigest()[:16]
        ctx.queue.enqueue(
            job.tenant,
            "webhook",
            {
                "sink": sink,
                "event": {
                    "event_id": uuid.uuid4().hex,
                    "type": "verel.pilot.decision",
                    "tenant": job.tenant,
                    "artifact": digest,
                    **result,
                },
            },
            dedupe_key=f"internal:notify:{job.id}:{job.attempts}",
            max_attempts=5,
            internal=True,
        )
    return result


def media_grade(job: Job, ctx: WorkerContext) -> dict[str, Any]:
    from ..media import grade_media

    p = job.payload
    _validate(job, ctx)
    mode = _mode(job, ctx)
    facts = p.get("facts")
    spec = _pinned(job, ctx, "spec", p.get("spec"), mode)
    asset = p.get("asset")
    if not isinstance(facts, list) or not all(isinstance(f, str) for f in facts) or spec is None:
        raise PermanentError("facts (list of paths) and a spec are required")
    if asset is not None and not isinstance(asset, str):
        raise PermanentError("asset must be a path")
    if asset is None and mode in ("policy", "enforce"):
        raise PermanentError(f"{mode} mode needs the asset, so the facts can be bound to its bytes")
    try:
        rep = grade_media(
            _root(job, ctx),
            facts=facts,
            spec=spec,
            asset=asset,
            today=date.today(),
            require_asset_binding=mode in ("policy", "enforce"),
        )
    except (ValueError, FileNotFoundError, TypeError) as e:
        raise PermanentError(f"cannot grade: {type(e).__name__}") from None
    except OSError as e:
        raise RuntimeError(type(e).__name__) from None  # retryable, and the message cannot leak a path
    return _finish(job, ctx, rep)


def provenance_grade(job: Job, ctx: WorkerContext) -> dict[str, Any]:
    from ..media import grade_provenance

    p = job.payload
    _validate(job, ctx)
    mode = _mode(job, ctx)
    asset, manifest = p.get("asset"), p.get("manifest_json")
    if not isinstance(asset, str) or (manifest is not None and not isinstance(manifest, str)):
        raise PermanentError("provenance jobs need an asset: a report alone is unverified input")
    policy = _pinned(job, ctx, "policy", p.get("policy"), mode)
    try:
        rep = grade_provenance(_root(job, ctx), asset=asset, manifest_json=manifest, policy=policy)
    except (ValueError, FileNotFoundError, TypeError) as e:
        raise PermanentError(f"cannot grade: {type(e).__name__}") from None
    except OSError as e:
        raise RuntimeError(type(e).__name__) from None
    return _finish(job, ctx, rep)


def webhook(job: Job, ctx: WorkerContext) -> dict[str, Any]:
    sink = ctx.sinks.get(job.tenant, {}).get(str(job.payload.get("sink")))
    if sink is None:
        raise PermanentError("unknown sink for this tenant")
    event = job.payload.get("event")
    if not isinstance(event, dict):
        raise PermanentError("event must be an object")
    try:
        return {"status": deliver(sink, event)}
    except DeliveryError as e:
        if e.permanent:
            raise PermanentError(str(e)) from None
        raise


BUILTIN: dict[str, Handler] = {
    "media_grade": media_grade,
    "provenance_grade": provenance_grade,
    "webhook": webhook,
}


class _Heartbeat:
    def __init__(self, queue: JobQueue, job: Job, lease_s: float):
        self.q, self.job, self.lease_s = queue, job, lease_s
        self.lost = False
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self.lease_s / 3):
            try:
                self.q.heartbeat(self.job, lease_s=self.lease_s)
            except LeaseLost:
                self.lost = True
                return
            except Exception:  # noqa: BLE001 - a transient db error must not kill the handler
                log.warning("heartbeat failed for %s", self.job.id)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *_a):
        self._stop.set()
        self._t.join(timeout=5)


class Worker:
    def __init__(
        self,
        queue: JobQueue,
        ctx: WorkerContext,
        *,
        worker_id: str | None = None,
        lease_s: float = 60.0,
        handlers: dict[str, Handler] | None = None,
    ):
        self.queue = queue
        self.ctx = ctx
        ctx.queue = queue
        self.id = worker_id or f"w-{uuid.uuid4().hex[:8]}"
        self.lease_s = lease_s
        self.handlers = dict(BUILTIN if handlers is None else handlers)

    def run_once(self) -> bool:
        """Process at most one job. Returns True if a job was claimed."""
        job = self.queue.claim(self.id, list(self.handlers), lease_s=self.lease_s)
        if job is None:
            return False
        try:
            with _Heartbeat(self.queue, job, self.lease_s):
                result = self.handlers[job.kind](job, self.ctx)
            self.queue.complete(job, result)
        except LeaseLost:
            log.warning("lease lost for %s; another worker owns it now", job.id)
        except PermanentError as e:
            self._fail(job, str(e), permanent=True)
        except Exception as e:  # noqa: BLE001 - any handler failure is a retry, never a crash of the worker
            log.warning("job %s failed: %s: %s", job.id, type(e).__name__, e)  # detail stays server-side
            self._fail(job, f"handler failed ({type(e).__name__}); see server logs")
        return True

    def _fail(self, job: Job, msg: str, *, permanent: bool = False) -> None:
        try:
            self.queue.fail(job, msg, permanent=permanent)
        except LeaseLost:
            log.warning("lease lost before failing %s", job.id)

    def run_forever(self, stop: threading.Event, *, poll_s: float = 1.0) -> None:
        import os
        import time as _t

        keep_s = float(os.environ.get("VEREL_JOBS_RETENTION_DAYS", "7")) * 86400
        next_purge = 0.0
        while not stop.is_set():
            if _t.monotonic() >= next_purge:  # retention: finished jobs do not live forever
                next_purge = _t.monotonic() + 3600
                try:
                    self.queue.purge(keep_s)
                except Exception:  # noqa: BLE001
                    log.warning("job purge failed")
            try:
                busy = self.run_once()
            except Exception:  # noqa: BLE001 - a transient database error must not kill a worker thread
                log.exception("worker %s: queue error; backing off", self.id)
                busy = False
            if not busy:
                stop.wait(poll_s)


def run_pool(
    queue: JobQueue,
    ctx: WorkerContext,
    *,
    concurrency: int,
    stop: threading.Event,
    lease_s: float = 60.0,
    poll_s: float = 1.0,
) -> list[threading.Thread]:
    threads = []
    for _ in range(max(1, concurrency)):
        w = Worker(queue, ctx, lease_s=lease_s)
        t = threading.Thread(target=w.run_forever, args=(stop,), kwargs={"poll_s": poll_s}, daemon=True)
        t.start()
        threads.append(t)
    return threads
