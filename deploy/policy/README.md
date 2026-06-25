# Config-scanner policy — Verel on Kubernetes/k3s comes up green

Every Verel deploy artifact (the Helm chart + the operator manifests + the CRD-generated workloads)
is gated, in CI, by three independent Kubernetes config scanners. The deployed workloads come up
**green** on all three:

| Scanner | What it checks | Gate |
|---|---|---|
| **Polaris** (Fairwinds) | pod security + reliability best practices | `polaris audit --config deploy/policy/polaris.yaml` → **fail on any Danger** |
| **kube-linter** (StackRox) | security + correctness lint | `kube-linter lint` → **zero findings** |
| **kube-score** | opinionated security + reliability scoring | `kube-score score` (ignore-list below) → **zero CRITICALs** |

Run locally: `make policy-scan` (or see `.github/workflows/policy.yml`).

## What makes them green (the substantive controls)

All workloads are hardened at the pod + container level: `runAsNonRoot` (UID 65532), `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, drop **ALL** capabilities, `seccompProfile: RuntimeDefault`, no mounted
ServiceAccount token (except the operator, which needs the API and uses a least-privilege SA). Every
container sets CPU/memory **and ephemeral-storage** requests+limits; every long-running container has
liveness+readiness probes; multi-replica Deployments declare soft pod **anti-affinity**; the chart ships
a **NetworkPolicy** + a **PodDisruptionBudget**; the GateRun untrusted-code Job adds a default-deny-egress
NetworkPolicy. **All images are pinned** — the Verel image to the release version, the git clone image to
a Chainguard **digest** — never `:latest`.

## The few deliberate overrides (and why)

These are policy decisions, documented so the "green" is honest — not blanket suppressions.

- **`container-image-pull-policy` / `pullPolicyNotAlways` (ignored everywhere).** kube-score/Polaris
  default to wanting `imagePullPolicy: Always`. Our images are **pinned** (version tag / digest), so
  `IfNotPresent` is the correct, more-robust choice — `Always` adds a needless registry round-trip on
  every pod start and a hard runtime dependency on registry availability. Pinning gives the immutability
  that `Always` is a proxy for.
- **`pod-probes` (test pod only, via annotation).** The Helm `test-connection` Pod is a one-shot hook
  (`restartPolicy: Never`) that runs once and exits — liveness/readiness probes don't apply. Exempted
  narrowly on that single object (`kube-score/ignore` + `polaris.fairwinds.com/*-exempt` annotations).
- **`pod-networkpolicy` / `deployment-has-poddisruptionbudget` (operator-managed GatewayService/VerelFleet
  only).** The **chart** (the primary install path) ships both a NetworkPolicy and a PDB. For the
  operator-managed long-running services, namespace-scoped NetworkPolicy is a cluster-admin concern, and a
  PDB over the default single-replica gateway would *deadlock node drains* — so the operator does not emit
  one by default. The GateRun Job (the security-critical, untrusted-code path) **does** get its
  default-deny-egress NetworkPolicy unconditionally.

The exact kube-score ignore-lists are encoded in `.github/workflows/policy.yml` (chart: only the
pull-policy override; operator-managed: + the two above).
