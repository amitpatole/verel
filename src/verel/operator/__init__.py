"""The Verel Kubernetes operator (Kopf) — reconciles the Verel CRDs into native objects.

CRDs (group `verel.dev`, version `v1alpha1`):
  - GateRun        a one-shot "grade this repo/PR" → a HARDENED Job; verdict + receipt to .status.
  - Brain          a Postgres/Redis-backed shared brain (connection Secret + pod wiring).
  - GatewayService a long-running `verel serve` (Deployment + Service) — the chart's GatewayService.
  - VerelFleet     a scalable multi-worker loop sharing one Brain.

The reconcile glue lives in `handlers` (needs a cluster); the security-critical, pure, unit-tested
piece is `jobs.build_gaterun_job` — it produces the GateRun Job manifest with defense-in-depth
isolation, because that Job EXECUTES UNTRUSTED REPOSITORY CODE in the cluster.

Run: `python -m verel.operator` (or the hardened image in `--operator` mode). Needs `verel[operator]`.
"""

from __future__ import annotations

API_GROUP = "verel.dev"
API_VERSION = "v1alpha1"

from .jobs import build_gaterun_job, build_gaterun_netpol  # noqa: E402

__all__ = ["API_GROUP", "API_VERSION", "build_gaterun_job", "build_gaterun_netpol"]
