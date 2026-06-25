"""Run the Verel operator: `python -m verel.operator` (or the `verel-operator` console script, which
the hardened image uses in `--operator` mode). Importing `handlers` registers the kopf decorators."""

from __future__ import annotations


def main() -> int:
    import kopf

    from . import handlers  # noqa: F401  — registers the @kopf.on.* handlers on the global registry

    kopf.configure(verbose=False)
    # Serve kopf's liveness probe so the operator Deployment has a real health signal (k8s probes).
    kopf.run(liveness_endpoint="http://0.0.0.0:8080/healthz")  # nosec B104 — in-pod probe endpoint
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
