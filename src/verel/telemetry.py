"""OpenTelemetry export for pilot decisions. Optional and inert by default.

`pip install "verel[otel]"` adds the OpenTelemetry API. Without an SDK/exporter configured by the host
application, the API is a no-op, so this costs nothing and sends nothing. Verel never configures an
exporter or endpoint itself: where telemetry goes is the operator's decision.

Privacy: spans carry verdicts, mode, grader outcomes and counts. The artifact id is exported only as a
short (unsalted) SHA-256 prefix unless `include_artifact_id=True`, because ids often embed titles.
"""

from __future__ import annotations

import hashlib
from typing import Any

_tracer: Any = None
_counter: Any = None
_loaded = False


def _load() -> None:
    global _tracer, _counter, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        from opentelemetry import metrics, trace
    except ImportError:
        return
    from . import __version__
    _tracer = trace.get_tracer("verel.pilot", __version__)
    _counter = metrics.get_meter("verel.pilot", __version__).create_counter(
        "verel.pilot.decisions", description="pilot decisions by would-be verdict, enforced verdict, mode")


def reset_for_tests() -> None:
    global _tracer, _counter, _loaded
    _tracer = _counter = None
    _loaded = False


def emit_decision(dec: Any, *, tenant: str = "", graders: dict[str, str] | None = None,
                  include_artifact_id: bool = False) -> None:
    """Record one pilot decision as a span + counter. Never raises: telemetry must not break a gate."""
    try:
        _load()
        if _tracer is None:
            return
        aid = dec.artifact_id
        if not include_artifact_id:
            aid = hashlib.sha256(aid.encode()).hexdigest()[:12]
        attrs = {"verel.artifact": aid, "verel.mode": dec.mode.value, "verel.would_be": dec.would_be.value,
                 "verel.enforced": dec.enforced.value, "verel.gate_error": bool(dec.gate_error)}
        if tenant:
            attrs["verel.tenant"] = tenant
        for g, v in (graders or {}).items():
            attrs[f"verel.grader.{g}"] = v
        with _tracer.start_as_current_span("verel.pilot.decision", attributes=attrs):
            pass
        if _counter is not None:
            _counter.add(1, {"verel.mode": dec.mode.value, "verel.would_be": dec.would_be.value,
                             "verel.enforced": dec.enforced.value})
    except Exception:  # noqa: BLE001, S110
        return
