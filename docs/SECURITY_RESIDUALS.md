# Security residuals (internal)

Known security findings that are **not yet closed in code**, why, and when to recheck. Internal — NOT
in the public mkdocs nav. Process: a residual is either (a) deferred-by-design to a scoped follow-up,
or (b) unfixable at Verel's layer (upstream dependency / OS) — in which case, if upstream is open
source, we open an issue + PR and shepherd it to merge. Recheck on the date and close when fixed.

| ID | Finding | Severity | Why open / mitigation | Recheck |
|----|---------|----------|-----------------------|---------|
| R-002 | **GateRun pod DNS egress is unrestricted** (`src/verel/operator/jobs.py` netpol: port 53 to any destination). Untrusted repo code could DNS-tunnel/exfiltrate through the cluster resolver. | Low | Inherent to plain NetworkPolicy (no egress-DNS firewall). **Bounded:** nothing of value (cloud metadata / API server) listens on :53, so it is exfil-only — no pivot. `:443` egress to the public internet is already permitted by necessity (the git clone), so DNS adds no capability an attacker doesn't already have. Closing needs an egress-DNS policy engine (Cilium FQDN policy / a DNS proxy) which is a cluster-level control, not the operator's. | When the chart documents a Cilium/FQDN-policy option. |
| R-003 | **No per-pod PID cap on the GateRun Job** (Kubernetes has no pod-spec PID field). A fork bomb in untrusted code is bounded only by the memory cgroup + node `--pod-max-pids`. | Low | **Bounded:** the 2Gi memory cgroup OOM-kills before PID exhaustion, and untrusted repo code additionally runs under the in-container bwrap `--unshare-all` PID namespace. Documented as a cluster prerequisite (set kubelet `--pod-max-pids`) in the `jobs.py` netpol docstring + the k8s install docs. | If/when a Pod-level PID limit lands in core k8s. |

## Closed

| ID | Finding | Severity | Resolution |
|----|---------|----------|------------|
| R-004 | Operator liveness endpoint (`:8080/healthz`) reachable by trusted co-located pods (no ingress NetworkPolicy fronted it). | Info | **Fixed (v1.0.0 track, feat/k8s).** `deploy/operator/operator.yaml` now ships a default-deny-ingress NetworkPolicy on the operator (`podSelector` = the operator, `policyTypes:[Ingress]`, `ingress: []`), so `:8080` is reachable only by the kubelet (host-sourced probes bypass NetworkPolicy) — no co-pod can reach it. Confirmed by R7 red-team. |
| R-001 | Hosted `/all` returned the whole brain to any bearer-authenticated peer (cross-backend HTTP layer in `src/verel/memory/hosted.py`). | Low | **Fixed in v0.51.1.** In signed-writes mode an **unscoped** `/all` (full-brain dump of every scope/principal) requires the **cluster credential** (`X-Cluster-Token`); a **scoped** `/all` stays a normal bearer read (the scope-lattice recall + consolidation use it, and a client could already `/recall` that scope). Legacy single-trust mode unchanged. Pinned by `test_signed_mode_unscoped_all_requires_cluster_credential`; a focused adversarial review ran live coercion exploits (empty/null/wildcard/list scope) and confirmed the boundary holds (all backends use exact-match scope equality; gate and sink read the same value → no parse differential). |
