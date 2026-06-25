# Deploy on Kubernetes / k3s

Verel ships a hardened container image, a secure-by-default **Helm chart**, and a **Kopf operator** with
four CRDs. Everything targets vanilla Kubernetes and is validated on **k3s** too (via k3d) — the chart
parameterizes only the seams that differ (ingress class, storage class, LoadBalancer).

Two ways to run it:

- **The gate server** (`GatewayService`) — a long-running `verel serve` REST gate (POST `/gate`, GitHub
  webhook), installed with the Helm chart. Start here if you just want a gate endpoint.
- **The operator + CRDs** — declarative `GateRun` / `Brain` / `GatewayService` / `VerelFleet` resources
  reconciled into Jobs/Deployments. Start here for in-cluster, multi-tenant grading.

> **Secure by default.** The gate binds a routable address, so it **fails closed**: it requires a bearer
> token **and** TLS (or an explicit `insecure` opt-out behind a TLS-terminating ingress). Pods run
> nonroot + read-only-rootfs + drop-ALL-caps + seccomp, with no mounted ServiceAccount token. Every
> deployed workload comes up **green on Polaris, kube-linter, and kube-score** (see
> [Security & cluster prerequisites](#security-cluster-prerequisites)).

## Quickstart A — the gate server (Helm)

From a clone of the repo (the chart lives in `deploy/chart`):

```bash
# 1. a TLS Secret for the routable bind (cert-manager Certificate, or self-signed for a smoke test)
kubectl create secret tls verel-tls --cert=cert.pem --key=key.pem

# 2. install — bearer token + TLS are required (it fails closed otherwise)
helm install verel ./deploy/chart \
  --set tls.secretName=verel-tls \
  --set auth.token="$(openssl rand -hex 16)"

# 3. confirm the gate is serving
helm test verel
kubectl get pods -l app.kubernetes.io/name=verel
```

Behind a TLS-terminating ingress/mesh you can waive in-pod TLS (auth is still required):

```bash
helm install verel ./deploy/chart --set tls.insecure=true --set auth.token="$(openssl rand -hex 16)"
```

Key values (`deploy/chart/values.yaml`): `image.tag` (defaults to the chart `appVersion`), `replicaCount`
+ `autoscaling.*` (HPA), `ingress.className` (`traefik` on k3s / `nginx`|cloud on k8s), `repo.source`
(`emptyDir`|`pvc`|`hostPath`), `brain.existingSecret` (wire a Postgres/Redis brain), `networkPolicy.*`,
`podDisruptionBudget.*`.

## Quickstart B — the operator + CRDs

```bash
# CRDs, then the operator (least-privilege RBAC + a hardened Deployment in verel-system)
kubectl apply -f deploy/crds/
kubectl apply -f deploy/operator/

kubectl -n verel-system get deploy verel-operator
```

The operator runs the **same hardened image** in `--operator` mode and reconciles four CRDs.

### Grade a repo with a GateRun (copy-paste demo)

A `GateRun` runs Verel's gate over a repo in a one-shot, **defense-in-depth-isolated** Job and writes the
verdict to `.status`:

```yaml
# gaterun-demo.yaml
apiVersion: verel.dev/v1alpha1
kind: GateRun
metadata:
  name: grade-hello
  namespace: default
spec:
  repo: https://github.com/octocat/Hello-World   # any public https git URL
  ref: master                                    # optional
  stage: pre_merge                               # inner_loop | pre_commit | pre_merge | post_merge
```

```bash
kubectl apply -f gaterun-demo.yaml
# watch the verdict land in .status (Running → Passed/Failed)
kubectl get gaterun grade-hello -o wide
kubectl get gaterun grade-hello -o jsonpath='{.status.phase} {.status.verdict}{"\n"}'
```

The Job runs untrusted repo code under a default-deny-egress NetworkPolicy (cloud metadata + all private
ranges blocked), nonroot + read-only-rootfs + drop-ALL caps + seccomp, no ServiceAccount token, capped
CPU/memory/ephemeral-storage, `backoffLimit 0`, and a hard `activeDeadlineSeconds` — plus, inside the
container, Verel's bwrap + seccomp runner. The verdict mirror trusts **only** the Job whose
server-assigned uid the operator recorded (verdict-forgery is closed).

## CRD reference (`verel.dev/v1alpha1`)

| Kind | Purpose | Key spec fields |
|---|---|---|
| **GateRun** | One-shot "grade this repo/PR" → a hardened Job; verdict + receipt to `.status`. | `repo` (https git URL, required), `ref`, `stage` (enum), `runtimeClassName` (gVisor/Kata), `timeoutSeconds` (30–7200) |
| **Brain** | Wire a Postgres/Redis-backed shared brain (validates the connection Secret exists). | `backend` (`postgres`\|`redis`\|`lancedb`), `connectionSecret`, `embedder` |
| **GatewayService** | A managed long-running `verel serve` (Deployment + Service + NetworkPolicy). | `replicas`, `insecure`, `repoMountPath` |
| **VerelFleet** | A scalable pool of gate workers sharing one Brain. | `workers`, `brain` (a Brain CR name), `goal` |

Workload images, resource limits, and the projected Secrets are **operator-controlled** (never from a CR
spec) — a CR author can't make the operator run an attacker image or read an arbitrary Secret.

## Published artifacts (signed)

At each release the image is built multi-arch (amd64+arm64) with an SBOM + SLSA provenance, scanned
(trivy + grype, **0 HIGH/CRITICAL**), and **cosign keyless**-signed, then pushed to
`ghcr.io/amitpatole/verel`:

```bash
cosign verify ghcr.io/amitpatole/verel:<version> \
  --certificate-identity-regexp 'https://github.com/amitpatole/verel/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The OCI Helm chart (`oci://ghcr.io/amitpatole/charts/verel`) and the Artifact Hub listing land with the
v1.0.0 release; until then install from `deploy/chart` as above.

## Security & cluster prerequisites

Verel's in-cluster isolation is defense-in-depth, but two controls live at the cluster layer and **must**
be in place for the guarantees to hold:

- **A policy-enforcing CNI** (Calico, Cilium, …). NetworkPolicy is the load-bearing egress fence on the
  GateRun pod; it is a no-op on a CNI that doesn't enforce it.
- **`--pod-max-pids` set on the kubelet** — Kubernetes has no pod-spec PID cap, so this is the fork-bomb
  backstop (the memory cgroup + in-container bwrap PID namespace also bound it).
- **Don't grant GateRun authors `pods`/`networkpolicies`/`gateruns/status` create.** The threat model is
  "a tenant who can create `GateRun` CRs but not raw pods." Granting raw pod/NP create lets them bypass
  the operator's fences; granting `gateruns/status` write lets them forge a verdict.

The deployed workloads are gated, in CI, on **Polaris + kube-linter + kube-score** (see `deploy/policy/`)
— run `bash deploy/policy/scan.sh` to reproduce the green result locally.
