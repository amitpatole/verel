# Verel deployment artifacts (Kubernetes / k3s)

Toward **v1.0.0** — the deployable, signed, multi-tenant Verel. Full design:
`docs/K8S_DEPLOYMENT_DESIGN.md`. Everything here targets vanilla Kubernetes and is validated on **k3s**
too (via k3d) — the chart parameterizes the only seams that differ (ingress class, storage class,
LoadBalancer).

## Layout
```
deploy/
  Dockerfile        hardened image (Chainguard Wolfi base, distroless, nonroot) — the build path
  apko.yaml         declarative apko/Wolfi assembly (CI alternative; see "Image" below)
  chart/            Helm chart (GatewayService, probes, HPA, PodSecurity, NetworkPolicy)   [phase 2]
  operator/         Kopf operator (verel[operator], --operator mode)                       [phase 3]
  crds/             CustomResourceDefinitions: GateRun, Brain, GatewayService, VerelFleet  [phase 3]
.github/workflows/image.yml   build → multi-arch → SBOM → SLSA provenance → trivy/grype gate → cosign
```

## Image
The image is built **FROM Chainguard's Wolfi-based `python` images** — the same low-/zero-CVE Wolfi base
the user chose, but via a Dockerfile so it builds in any standard CI (and locally). The final stage is
**distroless + nonroot (UID 65532) + no shell / no package manager**.

```bash
docker build -f deploy/Dockerfile -t verel:dev .
docker run --rm -p 8000:8000 -v "$PWD:/workspace:ro" verel:dev \
    serve --host 0.0.0.0 --repo /workspace --no-lint     # GET /health, /ready
docker run --rm --entrypoint python verel:dev -c "import verel; print(verel.__version__)"
```

**Supply chain (`.github/workflows/image.yml`, on a `v*` tag):** multi-arch (amd64+arm64) build/push to
`ghcr.io/amitpatole/verel`, BuildKit **SBOM** (SPDX) + **SLSA provenance** attestations, a **trivy +
grype** gate that fails on any HIGH/CRITICAL, and a **cosign keyless** (GitHub OIDC) signature over the
pushed digest. Consumers verify with `cosign verify ghcr.io/amitpatole/verel:<tag> --certificate-identity-regexp … --certificate-oidc-issuer https://token.actions.githubusercontent.com`.

> The image entrypoint is `verel`; `CMD` runs the gate server. The same image runs the MCP server
> (`verel-mcp`) and the operator (`--operator`, phase 3) — one image, three roles.

> apko/melange (`apko.yaml`) is provided as the fully-declarative reproducible-build alternative for CI
> that prefers it; the Dockerfile is the buildable-anywhere primary and produces the same Wolfi base.

## Status
- [x] **Pre-work** — `verel serve` `/health` + `/ready` probes, SIGTERM drain, `verel[operator]` extra.
- [x] **Phase 1 — image** — hardened Wolfi Dockerfile (built + smoke-tested), supply-chain CI workflow.
- [ ] **Phase 2 — Helm chart** — GatewayService + probes + HPA + PodSecurity + NetworkPolicy; OCI → ghcr + Artifact Hub.
- [ ] **Phase 3 — operator + CRDs** — Kopf operator; GateRun / Brain / GatewayService / VerelFleet (full security cadence — GateRun runs untrusted code in-cluster).
- [ ] **Phase 4 — publish + docs + verify-live** — OIDC publish, Artifact Hub, k3s/k8s install docs, live GateRun demo.
- [ ] **v1.0.0** — the complete, signed, hosted deployment story.
