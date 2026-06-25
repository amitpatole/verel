# Verel on Kubernetes & k3s — deployment track design (DRAFT for approval)

**Status:** proposed · **Milestone:** the **v1.0.0** line (the major release the user flagged) — Verel
goes from "pip-installable library" to "**deployable, signed, multi-tenant platform**." Intermediate
phases ship as `0.52.0 → 0.55.0`; the complete, verified-live story is tagged **v1.0.0**.

**Design once, run on both.** k3s is CNCF-conformant Kubernetes, so every artifact (image, chart,
operator, CRDs) targets vanilla k8s and is *validated on k3s too*. The only portability seams the
chart parameterizes: **ingress class** (Traefik on k3s / nginx|cloud on k8s), **storage class**
(local-path on k3s / cloud PVCs), and **LoadBalancer** (klipper-lb on k3s / cloud LB). Local dev/CI
uses **k3d** (k3s-in-docker) and **kind** (vanilla) so both are exercised.

## Locked decisions (from the user, 2026-06-24)
- **Hosting:** `ghcr.io` for BOTH the image and the OCI Helm chart; OIDC + **cosign keyless**; listed
  on **Artifact Hub**.
- **Base image:** **Chainguard Wolfi via apko/melange** — minimal, daily-zero-CVE base, nonroot, no
  shell, native SBOM + signature. The "unique, near-0-flaw" image.
- **Operator:** **Kopf (Python)**, shipped as the `verel[operator]` extra; the same hardened image run
  in `--operator` mode.
- **CRDs (comprehensive / best-in-class):** **GateRun · Brain · GatewayService · VerelFleet.**

## Pre-work in Verel itself (small, lands first)
1. **Health/readiness on `verel serve`** — add `GET /health` (liveness) + `GET /ready` (readiness:
   brain reachable) so k8s probes have a real signal. Graceful **SIGTERM** drain for rolling updates.
2. **`verel[operator]` extra** — `kopf`, `kubernetes` (client); an `--operator` entrypoint on the
   image.
3. **`deploy/` tree** — `deploy/apko/`, `deploy/melange/`, `deploy/chart/`, `deploy/operator/`,
   `deploy/crds/`, plus CI workflows.

## Phases (each gated; each with the security cadence where there's attack surface)

### Phase 1 — Hardened image (`0.52.0`)
- **melange** builds the `verel` APK from the wheel; **apko** assembles a Wolfi image: `nonroot`
  (UID 65532), **no shell / no package manager**, pinned package versions, **multi-arch**
  (amd64+arm64), entrypoints for `verel serve`, `verel-mcp`, and `--operator`.
- **Supply chain:** apko-native **SBOM** (SPDX), **cosign keyless** signature (GH OIDC), **SLSA**
  provenance (slsa-github-generator), pushed to `ghcr.io/amitpatole/verel`.
- **Scan gate:** **trivy + grype** in CI → build fails on any **HIGH/CRITICAL**. `docker scout`/grype
  diff tracked. This is the security cadence for the image (build → scan → sign → verify-signature).
- **Verify-live:** `cosign verify` + `trivy image` the published tag; pull on k3d + kind.

### Phase 2 — Helm chart (`0.53.0`)
- **GatewayService deployment** of `verel serve`: Deployment + Service + Ingress (class-param) + **HPA**
  + liveness/readiness probes + **PodSecurityContext** (runAsNonRoot, readOnlyRootFilesystem, drop ALL
  caps, `seccompProfile: RuntimeDefault`, no privilege escalation) + resource requests/limits +
  **NetworkPolicy** (egress only to the brain) + least-privilege ServiceAccount.
- **Config via Secret/ConfigMap:** `VEREL_POSTGRES_URL`/`VEREL_REDIS_URL`, `VEREL_BRAIN_TOKEN`,
  `VEREL_CLUSTER_TOKEN`, TLS certs (mounted), `VEREL_EMBEDDER`. Brain backend selectable
  (postgres/redis/lancedb-PVC).
- **OCI chart** → `ghcr.io` via `helm push`; **Artifact Hub** `artifacthub-repo.yml` + signed
  provenance (`helm sign`/cosign). Validated on **k3d AND kind** in CI (`helm install` → probe green).

### Phase 3 — Operator + CRDs (`0.54.0`)  [full security cadence — cluster privileges]
- **Kopf operator** (`--operator`) reconciling four CRDs (OpenAPI-v3-validated, status subresources,
  finalizers, leader election):
  - **GateRun** — one-shot "grade this repo/PR" → a **Job** running the hardened gate; writes
    `verdict + receipt` to `.status`. **Biggest attack surface: it executes untrusted repo code in a
    pod** → reuse Verel's existing bwrap+seccomp container runner *inside* the pod **and** pod-level
    isolation (nonroot, readOnlyRootFilesystem, no service-account token, NetworkPolicy deny-all,
    resource caps; **gVisor/Kata RuntimeClass** where available). This is the security-critical piece.
  - **Brain** — provision/manage the Postgres/Redis-backed shared brain (connection Secret,
    schema/extension bootstrap, pod wiring).
  - **GatewayService** — the long-running `verel serve` as a managed Deployment+Service+HPA+probes.
  - **VerelFleet** — a scalable multi-worker ultracode/loop sharing one Brain.
- **Operator RBAC:** least-privilege ClusterRole (only the verbs/resources it reconciles), no
  wildcard, no `escalate`/`bind`. Security cadence: CR-input validation (admission via the CRD schema
  + a validating step), no privilege escalation, the GateRun sandbox proven (run an exploit repo, show
  it's contained), ≥3 red-team rounds on the operator + GateRun isolation.

### Phase 4 — Publish, docs, verify-live (`0.55.0`)
- OIDC publish workflows for image + chart + operator; Artifact Hub live. Docs: an **"Install on
  Kubernetes / k3s"** page (quickstarts for both), the CRD reference, a copy-paste **GateRun** demo.
- **Verify-live on a real k3s cluster:** `helm install`, apply a `GateRun` against a sample repo,
  confirm the **verdict + signed receipt** in `.status`; confirm `cosign verify` on the pulled image.

### Phase 5 — **v1.0.0**
The complete, signed, hosted deployment story: one hardened image, a chart, an operator with 4 CRDs,
published to ghcr.io + Artifact Hub, validated on k3s and k8s, security-cadenced. Tag **v1.0.0**.

## Security cadence focus (where the real surface is)
1. **The image** — supply chain: SBOM, signature, provenance, 0 HIGH/CRITICAL scan, pinned + daily
   rebuild. 2. **GateRun** — runs untrusted code in-cluster: defense-in-depth isolation (container
   runner + pod securityContext + NetworkPolicy + no SA token + gVisor/Kata), exploit-proven. 3. **The
   operator** — cluster RBAC least-privilege, CR validation, no privesc. 4. **GatewayService** —
   inherits the existing transport hardening (TLS/mTLS/auth, body caps) + NetworkPolicy.

## Decisions (locked by the user, 2026-06-25)
- **Milestone:** **single v1.0.0** — build the whole track on a `feat/k8s` branch and ship it all at
  once as **v1.0.0** (no intermediate 0.5x publishes).
- **GateRun isolation:** **bwrap+seccomp + pod-hardening is the always-on floor** (every cluster,
  fail-closed strong); use a **gVisor/Kata RuntimeClass when the cluster offers one** (bonus tier).
- **Brain:** **external-only for production** (the `Brain` CRD wires an existing managed Postgres/Redis)
  **+ an optional bundled subchart for dev/demo** (off by default).

## Build/verify split (this environment vs CI)
Authored + statically validated locally: pre-work Python (+ tests), apko/melange config, Helm chart
(`helm lint`/`template`/unit tests), CRD YAML, operator code (+ unit tests), GH Actions workflows.
Requires CI / a cluster (k3d + kind) to fully verify: the image build+scan+sign+SBOM+provenance, the
`helm install` smoke, the operator reconcile + the GateRun isolation exploit-proof. Those run in CI;
locally we go as far as lint/template/unit + (if a cluster is reachable) a k3d smoke.
