# Changelog

## Unreleased — telecom Phase 5 (stretch)

- **RF resolver: eliminated the >8-deep DN fail-safe residual.** The PRACH neighbor resolver's O(1)
  index now uses a **reversed-name trie** (every node caches the min list-index cell in its subtree),
  so it indexes every DN separator-suffix and is **fully faithful to the linear `_resolve` for
  arbitrarily deep DNs** — with no O(len²) suffix materialization (the prior last-8 bound dropped
  >8-deep targets; red-team R3/R4/R5). Proven by a 300k-iteration differential fuzz (0 divergences vs
  `_resolve`, incl. deep/None/empty/unicode/NUL targets) and bounded (20k deep-DN cells in ~1.5s).

## 1.5.0 — telecom RAN RF rules (prach-root-nonoverlap + ssb-raster)

The two RF-math RAN rules deferred in v1.4.0, now shipped — the exact 3GPP lookup tables were
**cross-verified by two independent research passes** (a domain advisor + an adversarial web-research
workflow, 3-0 agreement on the N_CS / GSCN / ARFCN tables; the N_RB grid validated against guard-band
physics + canonical anchors), then pinned by unit tests.

- **`prach-root-nonoverlap`** (TS 38.211 §6.3.3.1) — two co-sited / neighbor cells on the same frequency
  layer must not use overlapping PRACH logical root-sequence ranges. Encodes all three N_CS unrestricted
  tables (6.3.3.1-5/-6/-7) — crucially the **format-3 ΔfRA=5 kHz table is distinct** from formats 0/1/2
  (a wrong-table split would silently miscount roots); `roots_needed = ⌈64/⌊L_RA/N_CS⌋⌉` with the N_CS=0
  edge; wrap-aware overlap over the correct modulus (838/138). Same-site overlap → ERROR; neighbor-only
  overlap → WARNING (msg1 FDM/time offsets are unmodeled). Restricted sets → INFO (skip).
- **`ssb-raster`** (TS 38.104 §5.4.2.1 / §5.4.3.1 / TS 38.101-1 Table 5.3.2-1) — the SSB must sit on the
  NR sync raster (a valid GSCN), within the band's GSCN range (per-band first/last/step + the n38
  discrete set), and each BWP must fit the carrier's N_RB. All frequency math in integer kHz. The
  SSB-in-carrier sub-check needs `arfcn_dl` to be the carrier CENTRE — **off by default**
  (`arfcn_is_centre`), so a Point-A value can't false-FAIL.
- New `verel.ci.telecom_rf` (the pure tables + math, unit-testable in isolation); the NRM adapter now
  extracts `prach.format` / `config_index` / `restricted_set`, `ssb_scs_khz`, and BWPs.
- **Honest scope:** checks DECLARED config only — not msg1 frequency/time separation, not restricted-set
  suitability, not kSSB/offsetToPointA/CORESET#0 alignment (needs MIB fields not in the model).

## 1.4.0 — telecom RAN/Core graders

A new grader track: **deterministic, offline, receipt-signed grading of 5G RAN + Core** — declared config
invariants and PM-counter KPIs — with one rule body grading both cloud-native (Helm) and classic
(NETCONF) artifacts. New `GraderKind.KPI` + `TELECOM_CFG`, the `verel[telecom]` extra, `verel-ci telecom`
/ `verel-ci telecom-cfg`, and `docs/use-cases-telecom.md`. Built over four gated phases, each hardened
under the security cadence (KPI 5 rounds, config 3, classic/RAN 6 — terminal-clean). Honest scope is
explicit: it grades declared config and reported KPIs, not the live network. Details below by phase.

### Phase 4 — positioning, honest scope, and the combined flagship

The capstone: makes the telecom track adoptable and honestly scoped.

- **`docs/use-cases-telecom.md`** — who it's for (Core / RAN / automation), what the three graders do,
  the one-machinery story (Helm ≡ NETCONF), a copy-paste offline quickstart, how it fits CI (a step,
  like the IaC track), and an explicit **honest-scope / non-goals** section (correlation≠causation,
  config≠runtime, vendor dialects, topological-not-RF-planning, no message-level conformance, no
  drive-test, no slice-SLA delivery). Wired into the docs nav + the homepage "Is Verel for you?".
- **`examples/demo_telecom_flagship.py`** — one gNB TAC change caught two ways on one gate: the config
  grader FAILs the declared change (`tac-plmn-consistency`) AND the KPI grader FAILs the synthetic
  post-window (registration SR collapse) — the config CAUSE and the KPI EFFECT, two signed receipts.

### Phase 3 — classic/appliance path + RAN rules + the RAN↔Core cross-check

Extends the telecom track to the **classic/appliance** world and RAN, proving **one machinery**: the
identical rule bodies grade a cloud-native (Helm) *and* a classic (NETCONF/NRM) artifact.

- **XXE-safe XML** (`telecom_model.xml_root`): defusedxml with DTD/entities/external all forbidden,
  plus a cheap pre-parse element+attribute bound and post-parse depth/count/text/attr caps (fails
  closed to a clean `ValueError` on any malformed/oversized input — no XXE, no billion-laughs, no DoS).
- **NETCONF / TS 28.541 NRM adapter** (`telecom_nrm.py`) → the SAME `TelecomConfigModel` the Helm
  adapter fills (cells + NFs + AMF served-TAIs). Namespace-tolerant (matched by local name); NRCellRelation
  neighbors attach gNB-scoped by `(gNBId, cellLocalId)`.
- **PM-XML / TS 32.435 adapter** (`telecom_pmxml.py`) → `MetricFrame`; `derive_kpis` turns raw counters
  into the Phase-1 ratio KPIs (RRC/HO/registration/PDU-session success rates) so the same `verel_kpi.yaml`
  thresholds work on Prometheus scrapes and EMS ROP files alike. `verel-ci telecom --kpi --fmt pmxml`.
- **RAN rules** in the shared registry: `pci-collision-confusion`, `neighbor-symmetry`, `eirp-cap`, and
  the **flagship cross-domain `tac-plmn-consistency`** — a gNB-broadcast (PLMN,TAC) not in any AMF's
  served-TAI list → Registration Reject 'tracking area not allowed' (5GMM cause #12). `verel-ci
  telecom-cfg` auto-dispatches Helm (YAML) vs NETCONF (XML). Demo: `examples/demo_telecom_ran.py`
  (the same FAIL fires on both forms; only the locator differs).
- **Deferred (documented, not shipped half-right):** `prach-root-nonoverlap` and `ssb-raster` — the
  N_CS / GSCN raster arithmetic is error-prone offline; a specialized follow-up beats a shaky gate.
- Hardened over a **6-round security cadence** (terminal-clean): closed a late XML-size guard, an
  attribute bomb, string-typed/float fail-opens, PM-XML impossible-ratio & negative-subcounter
  laundering, a suspect-flag bypass, and — across three rounds — the NRM neighbor-relation join
  (nested-relation drop → RDN-vs-cellLocalId mismatch → cross-gNB cellLocalId reuse).

### Phase 2 — declared config-invariant grader (5G Core)

A **deterministic** grader (no LLM — a telecom gate that can hallucinate is worse than useless) that
normalizes an Open5GS-shaped Helm-values artifact into a canonical network model and runs declared
invariants over it. Clones the `iac.py` normalize-then-evaluate pattern; every finding is grounded with
a `locator` into the exact source values path.

- **New `GraderKind.TELECOM_CFG`** (gates) + `IssueKind.INVARIANT_VIOLATION` / `CROSS_NF_MISMATCH`.
  `verel.ci.telecom_model` gains `TelecomConfigModel` / `NF` / `Endpoint` + `canonical_snssai`;
  `verel.ci.telecom_cfg` holds the adapter + 7 built-in Core rules + loader + waivers + `grade_cfg`.
- **7 Core invariants** with 3GPP clauses: `snssai-consistency` (flagship cross-NF: an SMF slice missing
  from NSSF / unsupported by AMF / with no UPF → FAIL), `ue-pool-sanity` (overlap/missing pool),
  `upf-interface-separation` (N3/N6 + mgmt), `redundancy-floor`, `suci-security-posture` (null-scheme /
  NEA0-priority / NIA0), `sbi-tls` (cleartext SBI), `mtu-coherence` (GTP-U encapsulation blackhole).
- **`verel_telecom.yaml` rule declaration** (`load_cfg_rules`, fail-closed): enable/parameterize built-ins
  + **receipt-visible waivers** (a waived violation → non-gating INFO, never silently dropped; expired
  waiver → gates + a WARNING; stale waiver → WARNING). `verel-ci telecom-cfg --values … --rules …`.
- Demo: `examples/demo_telecom_cfg.py` (offline, Open5GS-shaped values, slice-mismatch FAIL → fix → PASS).
- **Honest scope:** grades DECLARED config, not the running network; chart-dependent fields that aren't
  derivable emit a non-gating INFO ("insufficient evidence"), never a false FAIL or a silent PASS.

### Phase 1 — KPI/SLO vitals grader

First slice of the telecom track (see the plan): a **deterministic** KPI vitals grader that gates a 5G
RAN/Core change against **operator-declared** PM-counter thresholds — never inferred, like `COST`/`PERF`.

- **New `GraderKind.KPI`** (in `PRECISE_GRADERS`, it gates) + `IssueKind.THRESHOLD_BREACH` /
  `BASELINE_REGRESSION`. `TELECOM_CFG` + `INVARIANT_VIOLATION` / `CROSS_NF_MISMATCH` are reserved for
  Phase 2 (declared config-invariant grader).
- **Canonical MetricFrame + adapters** (`verel.ci.telecom_model`, `verel.ci.telecom_kpi`): parse a
  metrics artifact — JSON, CSV, or a Prometheus/OpenMetrics scrape (Open5GS/free5GC names mapped to
  3GPP TS 28.552 counters) — into one normalized model, then evaluate pure threshold/delta rules.
- **`grade_kpi(repo, metrics=, thresholds=)`** and **`verel-ci telecom --kpi … --thresholds …`** →
  a signed `Report` bound to the input bytes; `direction`, `min`/`max`, `max_delta_vs_baseline`,
  `min_samples`, and `worst`/`mean` aggregation. A ratio below `min_samples` is emitted at `LOW`
  confidence → the bus clamps it to a non-gating WARNING (statistical insufficiency can't fail a build);
  a threshold on an absent counter is WARNING "unmeasurable", **never a silent PASS** (fail closed).
- **Built-in 5G vitals profile** (`telecom_rules/vitals_5g.yaml`, ~14 RAN+Core KPIs with formula +
  clause) so a FAIL cites chapter and verse (e.g. `RM.RegInitSucc/RM.RegInitReq`, TS 28.552 §5.2.1).
- New `verel[telecom]` extra (PyYAML for threshold/profile YAML; defusedxml reserved for the Phase-3
  PM-XML/NETCONF adapters). Demo: `examples/demo_telecom_kpi.py` (offline, synthetic Open5GS-shaped data).
- **Honest scope:** a threshold gate over supplied PM data, not a service-assurance system — it does not
  observe the network and cannot attribute a regression to a cause. Fail-closed everywhere: an absent
  counter, a renamed/unmapped counter, a non-finite value, or a declared delta-gate with no baseline all
  surface as a non-gating WARNING ("unmeasurable") — never a silent PASS. A Prometheus/OpenMetrics scrape
  carries no denominator, so `min_samples`-gated KPIs surface as WARNING on scrape data (supply the
  denominator via JSON/CSV or a ROP window to gate). Hardened over a 3-round security cadence.

## 1.3.1 — portability & scan hardening

Cross-platform correctness and static-scan fixes; no API or behavior change on the supported path.
Every change was verified byte-equivalent or empirically re-proven under the security cadence
(4 independent adversarial passes + 2 manual equivalence proofs, terminal-clean).

- **Interpreter portability** — the trusted-local test-runner and the fleet pre-receive hook now use
  `sys.executable` instead of a bare `python`/`/usr/bin/env python3`, so the *running* interpreter is
  used and the only PATH-hijackable argv element is removed (a hardening, not just portability).
- **Runner hardening** — the `isolation="subprocess"` test tier now sets
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` (no env-driven third-party plugin code-exec) and, on Windows,
  forwards the minimal system env vars a Python subprocess needs to start. Default isolation stays
  `container` (fail-closed); untrusted code never reaches this tier.
- **Lease store fd-leak fixed** — `SqliteLeaseStore._conn` is now a context manager that closes each
  connection; the distributed-fence compare-and-swap (`BEGIN IMMEDIATE`/`COMMIT`) and rollback-on-error
  are unchanged and were re-proven atomic under concurrency. Fixes a real file-descriptor leak
  (notably on Windows, where an unclosed handle blocks deletion).
- **Sandbox belt-and-suspenders** — a best-effort in-child `open()` write guard fails a tool's
  `open(...,'w')` fast with a clear error. It is **not** a containment boundary (bypassable via
  `os.open`); the hard write guard remains `RLIMIT_FSIZE=0` and true isolation the container runner —
  documented as such.
- **Canonical-text gate** — the invisible/zero-width/control regexes in the memory trust gate were
  rewritten from literal characters to `\uXXXX` escapes for portability and static scanners.
  **Provably byte-for-byte identical** coverage (ZERO_WIDTH 20/20, CTRL 68/68, zero divergence across
  the full codepoint space) — no bypass reopened.
- **Encoding** — explicit `utf-8` on hook writes and test fixtures; BOM/credential test literals
  assembled from escapes rather than raw bytes (clean static scans).

## 1.3.0 — FTS5 BM25 hybrid retrieval

Upgrades the memory **retrieval** layer — the one on-mission gap a third-party comparative report
flagged (hybrid retrieval is the field's recurring winning pattern; Verel's *ranking* was best-in-set
but the *relevance signal* underneath was naive token-overlap).

- **FTS5 BM25 recall** — `LocalMemory` recall now uses SQLite **FTS5 + BM25** instead of set-intersection
  token-overlap: real term weighting, matches in the **text body** (not just subject/predicate), and
  **SQL-side scope/kind/rejected filtering** instead of a full-table scan + Python scoring. The
  trust-aware `rank` (verified-first + confidence + recency + budget) re-ranks the BM25 candidates on
  top, so the moat is unchanged and recall stays fenced as untrusted DATA. Dependency-free (FTS5 ships
  with `sqlite3`); falls back to token-overlap where a build lacks FTS5; the optional embedder/cosine
  semantic path is retained. `recall_budgeted` now respects the BM25 order. The index is kept in sync at
  the single write chokepoint + prune path, backfills for pre-existing dbs, and reconciles a partial
  index on open.
- **Security** — the untrusted FTS query is sanitized (decomposed to `\w+` tokens, each quoted as an
  FTS5 string and OR-joined) so no FTS5 operator can inject, error the matcher, or scan wide (40k-fuzz
  clean); SQL is parameter-bound. Recall `k` is clamped (`_MAX_RECALL_K=1000`) and reinforcement batched
  into one transaction, closing a k-amplification DoS where a large `k` drove a committed write per
  result. Hardened over a 2-round red-team cadence.

## 1.2.0 — graded conversational memory

Closes the two most-felt agent-memory gaps (conversational fact extraction + prompt-size
minimization) **without diluting the moat**: a fact is extracted like Mem0/Engram, but it only
compounds after it's **graded**. See
[MEMORY-EXTRACTION-KICKOFF.md](https://github.com/amitpatole/verel/blob/main/MEMORY-EXTRACTION-KICKOFF.md).

- **`extract_facts`** — turn a conversation (string or `[{role,content}]`) into candidate SPO `FACT`
  records (`Trust.CANDIDATE`, content-addressed, deduped last-wins so an in-conversation correction
  supersedes). Extraction only *proposes*; the LLM `ChatFn` is injected (offline-tested, no key); the
  parser fails closed on hostile/garbage output (the transcript is untrusted input).
- **`remember_conversation`** — the grade gate: only **verified** facts compound. A fact graduates
  `CANDIDATE → VERIFIED` **only** when it is **attested** (a signed receipt) or corroborated by **≥2
  distinct *authenticated* principals** (a caller-supplied `authenticate` resolves a source to a verified
  identity). Raw repetition never promotes — one author (or one attacker) repeating a claim N times, or
  minting N self-asserted source labels, stays `CANDIDATE`; a one-off / hallucinated fact stays candidate
  forever; a changed value **supersedes** with a queryable correction chain, and a value that was ever
  **rejected stays un-promotable**. Pure composition over the existing `MemoryView.write`/`promote` — no
  bypass of the trust model.
- **`recall_budgeted`** — token-budgeted, **graded-first** recall (`view.rank`: relevance + confidence
  + a trust term, with a verified-strength floor), so under prompt pressure a `VERIFIED` fact beats an
  equally-relevant `CANDIDATE` and a poisoned candidate can't crowd out a verified one. Dependency-free
  token estimate (injectable). Recalled memories render inside an untrusted-DATA fence (one inert line
  per record, control/zero-width/whitespace neutralized, angle brackets defanged) so a stored fact can't
  forge an instruction line — a second-order prompt-injection defense.
- **Surfaces** — MCP `verel_remember_conversation` (extract+grade, needs an LLM key) and `verel_recall`
  gains a `token_budget` (graded-first budgeted recall, no key). New `examples/demo_memory.py` (offline,
  no key). Docs: a *Conversational memory* section + `api.md` autodoc.
- **Security** — the untrusted-transcript surface was hardened through a multi-round red-team cadence:
  credentials/PII and encoded/obfuscated payloads are dropped at extraction (a *decode-and-rescan*
  layer, not just a surface denylist); memory never becomes a secret store and never reaches a
  decode-then-execute sink; and the trust gate, recall renderer, and rejection ledger share one
  canonical text form so confusable/whitespace variants can't launder a rejected value.

## 1.1.0 — IaC / DevOps graders, the cloud-IAM change sensor, and act-then-verify

A feature release that brings **Infrastructure-as-Code, the DevOps toolchain, and cloud IAM** onto the
verdict bus — and gates `terraform apply`/`destroy` through the action gateway. The throughline:
**catch dangerous cloud-IAM changes before they execute**, instead of discovering them in an incident
or a failed audit. See [IAC-KICKOFF.md](https://github.com/amitpatole/verel/blob/main/IAC-KICKOFF.md).

- **New grader kinds** — `IAC`, `IAM`, `POLICY` join `PRECISE_GRADERS`; `COST` is promoted (it gates
  against an explicit budget, like `PERF`). New `IssueKind`s: `IAC_DRIFT`, `IAM_RISK`, `MISCONFIG`.
- **IaC graders** (pure parsers, offline-tested; runner injected) — `terraform/tofu validate` & `plan`
  (`IAC`), `tflint` (`LINT`), `trivy config` + `checkov` (`SECURITY`), `conftest`/OPA (`POLICY`),
  `infracost` (`COST` vs budget), `helm template`/`kubectl --dry-run` + `kube-score`/`kube-linter`/
  `polaris` (K8s), Parliament + Cloudsplaining (`IAM` least-privilege).
- **The cloud-IAM change sensor** — normalizes every IAM-affecting change from a `terraform show
  -json` plan **and** native Kubernetes RBAC, and runs deterministic rules (wildcard action/resource,
  `iam:PassRole`-style privilege escalation, public principal, admin grants, open `0.0.0.0/0` ingress,
  cluster-admin / `system:masters`, anonymous subjects) across AWS/GCP/Azure/Kubernetes.
- **Act-then-verify** — `verel.actuators.TerraformActuator`: plan → grade the **bound** plan file →
  apply *exactly* that file (a re-plan/substitution between approval and apply is refused — the
  plan-binding / TOCTOU defense) → re-plan to confirm convergence. The gateway escalates dynamically:
  any destroy/replace or IAM widening ⇒ `IRREVERSIBLE` (dry-run + human approval); direct IAM-mutating
  tool calls are intercepted the same way.
- **Effective-access verification** — `EffectiveAccessVerifier` confirms what the cloud *actually*
  grants (AWS IAM Access Analyzer / GCP Policy Analyzer / Azure role assignments) with read creds
  resolved from `~/.config` (never logged). Accurate, but not a pure offline gate.
- **Security cadence (audit → 14 adversarial red-team rounds, fixing between each, until a round came
  back empty)** — the IaC/IAM sensor is the gate's whole point, so it was hardened against a hostile
  repo's `terraform show -json` / manifests as untrusted input. Closed across the rounds: the
  *"plan is not reality"* class — `local-exec`/`remote-exec` provisioners + `data.external` run
  unauditable commands at apply (now gated + escalated to `IRREVERSIBLE`), computed
  *(known after apply)* IAM content fails **closed** (`UNKNOWN_IAM_CONTENT`), and out-of-band
  `resource_drift` that the apply won't revert gates as live; RBAC parity (write-all over `*`,
  `admin`/`edit` ClusterRole bindings, proxy subresources, webhook/CSR/node escalation primitives,
  privileged-namespace secret reads); cross-cloud open-ingress (`google_compute_firewall` /
  `azurerm_network_security_rule`, incl. split-CIDR coverage via real `ipaddress` math) and non-policy
  public exposure (`aws_s3_bucket_acl`, `publicly_accessible` DBs, Azure public-blob, public Lambda
  invoke); and the live `EffectiveAccessVerifier` is held to a **superset** of the offline sensor's
  privesc set (AWS now runs `simulate-principal-policy`, not just document validation). A
  false-positive sweep fixed an over-gate on ordinary IAM-role trust policies, and an exhaustive
  ~5,000-variant fuzz pass hardened every parser to fail closed on malformed input. argv-only +
  charset-validated args throughout; **244 IaC/IAM regression pins**; residuals (R-007/R-010 same-uid
  planfile TOCTOU, R-012 coverage denylist, R-018 egress, R-014..R-017) documented in
  [`docs/SECURITY_RESIDUALS.md`](https://github.com/amitpatole/verel/blob/main/docs/SECURITY_RESIDUALS.md).
- **Surfaces** — the offline sensor is wired to the **`verel_iac_check`** MCP tool and the
  **`verel-ci iac`** CLI (`--plan` / `--manifests`, exit 1 on FAIL). Effective-access is a separate
  **opt-in, online** `verel verify-access --cloud {aws,gcp,azure}` subcommand (fails closed without
  creds; never in the offline gate).
- **`verel doctor`** probes the IaC binaries and the resolved cloud credentials. `verel[iac]` extra
  (pyyaml for helm YAML scanning). New `examples/demo_iac.py` (no cloud creds).

## 1.0.1 — operator RBAC fix + release-pipeline & Artifact Hub hardening

A patch release. The headline is a **Kubernetes operator RBAC fix** verified by running the operator on a
real k3s cluster:

- **Operator RBAC** — kopf must `list`/`watch` `customresourcedefinitions` cluster-wide to discover the CRDs
  it watches; without that grant the operator failed to start (`APIForbiddenError`, never reconciled). Added
  the grant to `deploy/operator/rbac.yaml`. Caught by a live k3d run (the verb-by-verb audit missed it) and
  locked in by a new `operator-e2e` CI job: operator → GatewayService (Ready Deployment+Service+NetworkPolicy)
  → GateRun (hardened Job + deny-egress NetworkPolicy with the server-assigned `jobUID` recorded in `.status`).
- **Release pipeline** — `chart-release` now authenticates cosign to ghcr (the chart signature push was
  `UNAUTHORIZED`); the image `grype` step gates on **fixable** HIGH/CRITICAL only (matching trivy) and uses a
  current scanner (the pinned one shipped a 15-week-stale vuln DB). `renovate.json` auto-bumps the SHA-pinned
  actions + the Chainguard git digest.
- **Artifact Hub** — added the `artifacthub.io/images` annotation so the chart's **security scan** runs (it
  came back **clean**, 0 across all severities); the chart is a **verified publisher**.
- **Docs & site polish** — comprehensive audit-driven docs pass (new *Graders* + *Integrations* reference
  pages; corrected the precise/advisory clamp rule); the HF Space + docs *Adoption* page swapped a slow, dark
  jsvectormap choropleth for a fast, dependency-free country bar-table.

**754 tests.**

## 1.0.0 — Verel on Kubernetes / k3s: a deployable, signed, multi-tenant platform

The major release: Verel goes from a pip-installable library to a **deployable, signed, multi-tenant
platform**. Design once, run on both vanilla Kubernetes and k3s.

- **Hardened image** — a Chainguard-Wolfi-based, distroless, nonroot (UID 65532), no-shell image at
  `ghcr.io/amitpatole/verel`, built multi-arch (amd64+arm64) with an SBOM + SLSA provenance, a
  **trivy + grype** gate (0 HIGH/CRITICAL), and a **cosign keyless** signature. One image, three roles:
  `verel serve`, `verel-mcp`, and `--operator`.
- **Secure-by-default Helm chart** (`deploy/chart`) — the `GatewayService` gate server. Fails closed
  (routable bind ⇒ bearer token **and** TLS, or an explicit insecure opt-out behind a TLS-terminating
  ingress). Pod hardening, probes, HPA, NetworkPolicy, PodDisruptionBudget, least-privilege SA.
- **Kopf operator + 4 CRDs** (`verel[operator]`) — **GateRun** (one-shot grade a repo/PR in a
  defense-in-depth-isolated Job → verdict in `.status`), **Brain**, **GatewayService**, **VerelFleet**.
  Least-privilege RBAC; the operator runs the same hardened image in `--operator` mode.
- **Security cadence (operator, rounds R4–R7, multi-agent red-team)** — closed a HIGH **verdict-forgery**
  (the verdict mirror now trusts only the Job whose server-assigned uid the operator recorded, never the
  author-settable label/ownerReference), a node-disk-exhaustion DoS, and a CGNAT (100.64/10) egress gap;
  trimmed RBAC to least-privilege; the operator emits per-workload NetworkPolicies. Two holistic rounds
  came back clean. Documented residuals: DNS-port egress, no pod PID cap (both bounded, cluster-layer).
- **Green on the config scanners** — every deployed workload passes **Polaris, kube-linter, and
  kube-score** (`deploy/policy/`, `bash deploy/policy/scan.sh`, CI `policy.yml`). All images pinned (no
  `:latest`), ephemeral-storage bounded, anti-affinity, NetworkPolicies everywhere.
- **Docs** — a new *Deploy on Kubernetes / k3s* guide (chart + operator quickstarts, a GateRun demo, the
  CRD reference, cosign-verify, and the cluster prerequisites).

**754 tests.**

## 0.51.1 — hosted brain: the unscoped full-dump needs the cluster credential (R-001)

Security hardening of the hosted `MemoryServer` (cross-backend, the shared-brain HTTP layer). In
**signed-writes mode**, an **unscoped `/all`** — which returns *every* record across all
scopes/principals (a full-brain dump) — now requires the **cluster credential** (`X-Cluster-Token`),
not just a client bearer token. A mere bearer holder could previously exfiltrate the entire shared
brain. A **scoped `/all`** (`scope=…`) stays a normal bearer read — the scope-lattice recall and
consolidation legitimately use it, and a client could already `/recall` that scope. Legacy
single-trust mode (no principals enrolled) is unchanged. Pinned by
`test_signed_mode_unscoped_all_requires_cluster_credential`. Closes residual **R-001**.

**728 tests.**

## 0.51.0 — Redis brain backend (networked, shared)

A **networked, multi-writer** brain store on plain Redis: many agents on different machines point at
one Redis and the trust layer stays correct under concurrent writers. `pip install verel[redis]`, set
`VEREL_MEMORY_BACKEND=redis` + `VEREL_REDIS_URL`, no code. Completes the external-DB backend set
(Postgres · LanceDB · Redis).

- **`verel.memory.redis_backend.RedisMemory`.** Each record is a Redis HASH at `{prefix}:mem:{id}`,
  enumerated via a SET index; proven by the shared `tests/memory_contract.py` harness (lexical **and**
  ANN). Recall scans the index and ranks in Python (cosine with an embedder, lexical otherwise).
- **Atomic under concurrent writers** via **optimistic concurrency** — `WATCH` the key, read, merge in
  Python, `MULTI`/`EXEC`, retry-with-backoff on a concurrent change (no global lock). Every mutator,
  and the per-key `decay` prune, is atomic. Pinned by concurrency proofs: 8×5 identical writes →
  `support_count==40`/one row; 8 distinct → one row + an N−1 correction chain; decay-vs-corroborate
  races lose nothing.
- **Security (full cadence):** Redis's RESP protocol is injection-safe (length-prefixed args — no
  string-interpolated query language), so there's no command-injection surface. A **routable host
  requires TLS *and* AUTH** — a non-loopback `VEREL_REDIS_URL` must be `rediss://` (validated cert)
  with a password, else refused (fail closed); loopback is zero-config. The URL/password is **scrubbed
  from every error**; the connection pool is bounded with timeouts. Multi-round adversarial red-team.
- Registered as the built-in `redis` backend + `verel.memory_backends` entry-point;
  `redis = ["redis>=5"]` extra. Env: `VEREL_REDIS_URL`, `VEREL_REDIS_PREFIX`, `VEREL_REDIS_CACERT`,
  `VEREL_EMBEDDER`. The full contract + concurrency proofs run in CI against a Redis service.

**727 tests.**

## 0.50.0 — LanceDB brain backend (embedded, vector-native)

A **zero-infrastructure** vector store for the brain: LanceDB is embedded (a directory on disk, no
server), so this is the drop-in way to get real ANN recall without standing anything up.
`pip install verel[lancedb]`, point `VEREL_LANCEDB_PATH` at a directory, set
`VEREL_MEMORY_BACKEND=lancedb` — no service, no code.

- **`verel.memory.lance_backend.LanceMemory`.** The full `MemoryView` over LanceDB + pyarrow, proven
  by the same `tests/memory_contract.py` harness (lexical **and** ANN). With an embedder, recall is
  approximate-nearest-neighbour over a Lance index; without one it falls back to the same lexical
  token-overlap as `LocalMemory`. The trust layer (interference rule, decay, documented `rank()`) is
  unchanged. Upserts via `merge_insert`; `close()` releases native handles cleanly.
- **Single-writer**, like `LocalMemory`: an instance serializes its own read-modify-write under a
  lock; concurrent multi-process writers to one dataset are not interference-rule-safe → front it with
  a `MemoryServer` (which already wraps any `MemoryView` behind its lock) for shared use.
- **Security (embedded — no network, no credentials):** LanceDB's `.where(...)` is a SQL-like filter
  string, so it's an injection sink. The surface is kept tiny — scope/kind/trust are filtered in
  **Python** (never in a predicate), and the only values reaching `.where()` are record ids, each
  escaped via `_lit` (doubled single-quotes, control chars rejected). The dataset path is
  operator-env only and path-normalized. Pinned by an injection regression test + a focused
  adversarial review. Because decay runs in Python (`apply_decay`), a malformed `detail_json` from a
  replica can't wedge it.
- Registered as the built-in `lancedb` backend + `verel.memory_backends` entry-point;
  `lancedb = ["lancedb>=0.5"]` extra. Env: `VEREL_LANCEDB_PATH`, `VEREL_LANCEDB_TABLE`,
  `VEREL_EMBEDDER`. The embedded contract runs in CI (no server needed).

**690 tests.**

## 0.49.0 — Postgres/pgvector brain backend (external, multi-machine)

The brain gets its first **external, networked** store: many agents on different machines write
directly to ONE Postgres. `pip install verel[postgres]`, set `VEREL_MEMORY_BACKEND=postgres` +
`VEREL_POSTGRES_URL`, no code — the registry resolves it like any built-in.

- **`verel.memory.pg_backend.PostgresMemory`.** The full `MemoryView` contract over psycopg3 +
  pgvector, proven by the same `tests/memory_contract.py` harness (lexical **and** ANN paths) the
  in-tree backends pass. Pushdown recall (scope/kind/trust filter in SQL, pgvector `<=>` ANN order,
  then Verel's documented `rank()` in Python); `apply_replica` verbatim/idempotent; decay prunes on
  the exact conjunction; confidence never moved by decay/recall.
- **Correct under concurrent writers** — the reason an external store exists. Every read-modify-write
  mutator runs under a per-key `pg_advisory_xact_lock`, so concurrent corroborate/supersede on the
  same `(subject,predicate,scope)` serialize. Pinned by two concurrency proofs: 8×5 concurrent
  identical writes → `support_count==40`, one row (no lost corroboration); 8 concurrent distinct
  writes → one row + an N−1 correction chain (no lost supersession).
- **Security cadence (networked store with credentials):** parameterized queries only (constant
  column lists, all values bound — B608 clean); the DSN/password is **scrubbed from every error**; a
  **routable host is refused without validating TLS** (`sslmode=verify-full`/`verify-ca`, fail closed);
  statement timeout bounds every query. An audit caught a **fail-open** hole — a URL DSN with no
  userinfo (`postgresql://host/db`) skipped the TLS guard — and a silently-dropped CA bundle on URL
  DSNs; both fixed and regression-pinned. Multi-round adversarial red-team across SQLi / secret-leak /
  TLS-bypass / DoS / concurrency / invariant lenses.
- Env: `VEREL_POSTGRES_URL` (or `VEREL_POSTGRES_DSN`), `VEREL_PG_SSLMODE`, `VEREL_PG_CACERT`,
  `VEREL_EMBEDDER`. Registered as the built-in `postgres` backend + the `verel.memory_backends`
  entry-point. Live smoke + concurrency + injection tests behind `VEREL_PG_SMOKE=1`.

**653 tests.**

## 0.48.0 — the action gateway: gate the boundary (Verified Review capstone, G)

Instead of trusting the agent to call the gate, put the gate **in front of its actions**. The gateway
classifies each tool call and enforces a verdict on the consequential ones — the agent needn't know
it's there. This completes the Verified-Review track.

- **`verel.gateway`.** `Gateway.handle(tool, args)` classifies the call (token-based, not substring):
  **SAFE** (read-only) forwards; **CONSEQUENTIAL** (writes) forwards **only on a gate PASS**, else
  blocked; **IRREVERSIBLE** (destructive/outward-facing) is **dry-run by default** and applied only on
  explicit **human approval**. `Policy` (allow/deny/overrides), `repo_gate` adapter.
- **Fail closed (the actel/immel non-negotiables), enforced + regression-pinned:** only a normalized
  `"pass"` forwards a consequential action — warn / error / missing / malformed / a gate that *raises*
  all **block**; an irreversible action is **never auto-applied**; an unclassifiable or un-gateable
  action is blocked. (A security round caught a HIGH fail-open — block-on-`fail` instead of
  forward-only-on-`pass` — now fixed and pinned; a confirmation round came back clean.)
- Built behind a clean **verdict / enforce / adapters** seam so it lifts into the boundary organ
  (`immel`) and act-then-verify organ (`actel`) later unchanged (adoption-first, segregate-later).

`examples/demo_gateway.py`. **637 tests.**

## 0.47.0 — over-engineering / scope-creep smell grader (Verified Review D)

Catches *"random abstractions for problems nobody was trying to solve."*

- **`verel.smell`.** Deterministic AST analysis — **no code execution, no new attack surface**. A
  changed function over a cyclomatic-complexity budget gates (`GraderKind.SMELL` is precise/gating);
  a public class/function added in the diff but referenced nowhere is flagged as **speculative
  generality** (advisory). `grade_smell` + the `verel_smell` MCP tool.
- This is the **smell organ `olfel`**'s future home — built in `verel` now as a self-contained module
  that emits standard verdict-bus Reports, so it lifts into `olfel` later unchanged (per the
  adoption-first / monolith-now-segregate-later strategy).

`examples/demo_smell_grader.py`. **621 tests.**

## 0.46.0 — business-rule / invariant grader (Verified Review C)

Catches *"business rules get ignored."* Declare cross-cutting invariants — *"an order total always
includes tax", "a refund never exceeds the charge"* — and Verel enforces them by execution.

- **`verel.ci.invariants`.** Declared invariants (a `verel_invariants.{yaml,yml,txt}` in the repo —
  one per line — or a passed list) are compiled by the LLM into property checks, **run**, and a
  falsified invariant **gates** (`verel_invariants` MCP tool; `load_invariants` / `grade_invariants`).
  Majority-voted like the spec grader; an ungroundable rule is advisory.
- **Reuses grader B's hardened, fail-closed execution** (`verel.ci.spec.run_check` — bwrap
  `--unshare-all` + seccomp + rlimits + memory cgroup) **unchanged**, so it inherits B's 4-round
  security audit. The new surface (a plain-text invariants file — no `yaml.load`, fixed filenames —
  and a validated rule list) was independently reviewed: **clean, no new attack surface.** Rules are
  human-declared (not from a hostile ticket), so the injection surface is smaller than B's.

`examples/demo_invariant_grader.py`. **614 tests.**

## 0.45.0 — agent-SDK shims: one gate hook for any framework (Reach R3)

Verel grades artifacts, so the integration is the same everywhere — give the agent a tool that gates
its own work before it declares "done". `verel.integrations.sdk` ships the framework-agnostic pieces,
**zero new dependencies**:

- **`gate(repo, criteria=…, files=…)`** — the universal callable. Runs the CI gate (tests + lint +
  types) and, with `criteria`, folds in the spec/intent grader; returns `{"verdict": pass|warn|fail,
  "issues": […]}` (combined = worst of the two). Any framework that takes a Python callable as a tool
  uses this directly: **LangChain/LangGraph** (`StructuredTool.from_function`), **CrewAI** (`@tool`),
  **AutoGen** (`register_function`).
- **`openai_tools()` / `anthropic_tools()`** — the gate as a function-calling / tool-use schema for
  the OpenAI and Anthropic (Claude Agent SDK) APIs; **`run_tool_call(name, arguments)`** executes the
  tool call your loop receives (accepts the model's JSON string or a dict).
- `langchain_tools()` lazily adapts to a `StructuredTool` when LangChain is installed.

`examples/demo_sdk_shims.py`; docs recipe in Get started. **608 tests.**

## 0.44.0 — spec/intent conformance grader + GitHub PR context (Verified Review B + Reach R2)

Catches the headline AI-PR failure mode — *"the ticket says A, the code does B."*

- **Spec/intent grader (`verel.ci.spec`).** The LLM extracts checkable acceptance criteria from the
  **ticket** (PR/issue text — never the agent's diff), compiles each into N independent pytest checks,
  **executes** them, and gates on a grounded `INTENT_MISMATCH` violation (`verel_spec` MCP tool;
  `grade_pr` pulls criteria + diff from a GitHub PR). The LLM only *proposes* checks; **majority vote**
  over independent checks decides, so one wrong generated test can't false-fail a merge; an
  unverifiable criterion is advisory; a non-empty ticket that yields no criteria reads as unverified
  (WARN), never a confident PASS.
- **GitHub PR context (`verel.integrations.github`).** Reads a PR's diff + changed files + linked-issue
  acceptance criteria (`VEREL_GITHUB_TOKEN`) — the "ticket" comes from the team's GitHub, not a new file.
- **Security cadence — 4 adversarial multi-agent rounds, final round empty.** Round 1 caught a CRITICAL
  RCE (a static allowlist can't sandbox a Turing-complete language: `getattr(__builtins__,'open')` etc.).
  Fixed *architecturally* — generated checks now execute under real OS isolation (bwrap `--unshare-all`
  no-net + read-only fs + seccomp denylist + rlimits + a memory cgroup), and **fail closed** (the
  criterion stays advisory, code is never run) when no isolation or memory bound is available. The MCP
  tool never exposes the weaker subprocess tier. Subsequent rounds fixed host-DoS (rlimits/seccomp/tmpfs
  memory-cgroup), criteria-suppression, and bounded the linked-issue fetch. **600 tests.**

## 0.43.0 — gate over HTTP: REST server + HMAC-verified GitHub PR webhook

Reach track (R1): gate from any stack — CI, a script, or a GitHub PR webhook — with no MCP host.

- **`verel serve --repo .`** runs an HTTP gate over one configured repo (`verel.integrations.rest`):
  `POST /gate` → `{verdict, issues}`; `POST /github` verifies GitHub's `X-Hub-Signature-256` HMAC
  over the raw body before gating; `GET /health`. The repo is fixed at startup — a caller can't
  redirect CI at another path. Built on the hardened `verel.transport`: loopback is zero-config, a
  routable bind **requires a token AND TLS** or refuses to start. Secrets from env
  (`VEREL_GATE_TOKEN`, `VEREL_GATE_WEBHOOK_SECRET`), never argv. `examples/demo_rest_gate.py`.
- **Security cadence — 3 adversarial rounds (multi-agent), all findings fixed + regression-pinned:**
  empty/blank token can no longer authenticate (`enforce_bind_policy` + both servers treat `""` as
  no-auth — also closed the same latent hole for the brain's `cluster_token`); concurrent gate runs
  are bounded by a semaphore (→ `503` when busy) so a request flood can't fork-bomb the host; HTTP
  request-smuggling closed (reject `Transfer-Encoding` / duplicate `Content-Length`, `Connection:
  close` on every error); webhook `repo`/`sha` are shape-validated (no URL-injection/SSRF into
  `post_commit_status`); a non-object webhook body skips cleanly instead of erroring; non-ASCII auth
  headers deny cleanly instead of 500.
- Docs: `verel serve` in cli.md + getting-started; **573 tests**.

## 0.42.0 — Verified Review: test-effectiveness grader + one-line agent adoption

First slice of "Verified Review" — catch the failure modes of AI-authored PRs — plus the
plug-and-play adoption surface so Verel inserts into a team's existing agent stack.

- **Test-effectiveness grader (mutation).** A green suite proves nothing if it asserts nothing.
  `verel.ci.mutation` injects small faults into the changed source (a zero-dependency `ast` mutator:
  comparison/arithmetic/boolean swaps, `True/False` flip, `return→None`) and re-runs the suite; a
  **surviving mutant** (one no test catches) is a deterministic FAIL. New `GraderKind.MUTATION` is
  **precise/gating** (not advisory) — an agent can't pad a PR with toothless tests. Diff-scoped +
  capped + total-wall-clock-budgeted so it stays under the CI ceiling and always restores files.
  Wire via `premerge_stage(..., mutation=["changed.py"])` or `mutation_spec`. Security: in-place
  writes are path-traversal-guarded and the run budget keeps it from being killed mid-mutation.
- **One-line adoption.** `verel mcp install` prints the `verel-mcp` server config + where each host
  expects it; `verel rules --target cursor|claude|agents|copilot|windsurf [--write]` emits a
  rules-file snippet that makes any agent call `verel_gate` before declaring "done" (idempotent,
  preserves existing content). Verel grades artifacts, so it plugs into whatever agent stack you run.
- New `verel.integrations` package (the "Reach" adapter seam) + `examples/demo_mutation.py`. **549 tests.**

## 0.41.0 — pluggable memory-backend registry (foundation for external DB stores)

Formalizes how Verel's shared brain selects its storage, so external databases can become
out-of-the-box options (`pip install verel[<db>]` + env vars, no code). This release is the
**foundation** — a registry + a portable contract — with **zero behavior change**; the Postgres,
LanceDB, and Redis backends land in the releases that follow.

- **Backend registry** (`verel.memory.registry`): `load_backend(name)` resolves a `MemoryView` by
  name, **built-ins first** (a static map — fast, deterministic, and a third-party package cannot
  hijack a built-in name), then the `verel.memory_backends` entry-point group so external packages
  can register their own backend. Listing names never imports a plugin.
- **`VEREL_MEMORY_BACKEND`** selects the backend (`local` default | `remote` | future external DBs).
  Back-compat is exact: unset behaves as before — `local`, or `remote` when `VEREL_BRAIN_URL` is set.
- **`from_env()`** factories on `LocalMemory` and `RemoteMemory` read operator env only and
  fail closed (a `remote` brain with no `VEREL_BRAIN_URL` raises rather than silently degrading).
- **Shared embedder factory** (`embedder_from_env`, via `VEREL_EMBEDDER=none|lexical|hash|openai`):
  one place configures the ANN-vs-lexical recall choice. Default is lexical (works with Ollama,
  which serves no embeddings endpoint).
- **Reusable contract harness** (`tests/memory_contract.py`): the trust-layer invariants (orthogonal
  confidence/strength, the interference rule, the exact prune conjunction, `apply_replica`
  idempotency, decay-never-moves-confidence) as backend-agnostic checks — every backend is proven by
  reusing it instead of copy-pasting assertions. Run over LocalMemory and the mem0 adapter here.
- `verel doctor` now reports the selected memory backend and the available ones. **521 tests.**

## 0.40.0 — remove the metrics dashboard from the package (not a Verel feature)

Reverts the v0.39.0 decision to ship the metrics dashboard inside `verel`. The dashboard is a
**maintainer tool** — it tracks the author's own projects' adoption and reads GitHub *traffic* data
(which needs push access via local `gh` auth), so it has no use for anyone who installs Verel. It does
not belong in the public package.

- Removed `verel.dashboard` and the `verel-dashboard` console script from the package.
- The dashboard lives under `tools/metrics_dashboard.py` again (not packaged); it keeps the
  fail-closed auth+TLS hardening and may be extracted into its own project later.
- No API a Verel user relied on is affected (the dashboard was only ever an extra command).

> **v0.39.0 is yanked** on PyPI/TestPyPI — install `verel>=0.40.0`. (Package versions are immutable;
> yank, not delete, is the correct supersede.)

## 0.39.0 — ship the metrics dashboard, hardened (auth + TLS)

The live metrics dashboard graduates from a `tools/` script (which bound `0.0.0.0` **unauthenticated**)
to a first-class shipped component, `verel.dashboard`, run via the **`verel-dashboard`** console script.
It reuses the same fail-closed transport hardening as the brain/lease/registry:

- **Loopback (`127.0.0.1`) default is zero-config** plain http, no token. A **routable bind** (anything
  else, incl. `0.0.0.0`) **requires both an auth token AND TLS** or it refuses to start — the
  GitHub-traffic data it shows is account-scoped, so it's never served to the open network
  unauthenticated. (Verified to bind no socket on refusal.)
- **Auth** is a constant-time bearer token (`Authorization: Bearer …`) or `?token=…` for a browser;
  401 before any data is served. TLS handshake runs off the accept loop; global + per-IP connection
  caps; slowloris timeout — all from the audited `verel.transport`.
- Config is operator env only: `VEREL_DASHBOARD_HOST` / `VEREL_DASHBOARD_TOKEN` /
  `VEREL_DASHBOARD_CERT` / `VEREL_DASHBOARD_KEY`. `tools/metrics_dashboard.py` stays as a thin
  back-compat shim.

A focused red-team (auth bypass / token leakage / SSRF / DoS / fail-closed) came back clean. The
dashboard passes the MEDIUM+ security gate (a real http(s) scheme guard on its data-fetch path).

> **Operational note:** a systemd unit running the dashboard now needs `VEREL_DASHBOARD_HOST` +
> `VEREL_DASHBOARD_TOKEN` + `VEREL_DASHBOARD_CERT`/`KEY` to serve on the LAN; otherwise it binds
> loopback only. (Will be refined further.)

## 0.38.0 — the security gate, fixed and stricter (dogfooding)

Dogfooding Verel's own pre-merge gate on Verel found that the `security` grader was broken — it
contradicted its own "HIGH/CRITICAL gate" docstring: it ran `bandit -r .` over the whole tree and
failed on *any* finding, so it flagged every test `assert` (B101) and all of `.venv`, and could never
pass on a normal project (and bandit wasn't even a declared dev dependency, so the gate failed closed
as "security grader absent").

- **bandit is now a `[dev]` dependency** — the pre-merge `security` grader is reproducible (an absent
  required grader is a red gate, not a silent pass).
- **The grader is fixed and made a real gate:** scans the shipped package (excludes `tests/`,
  `tools/`, `scripts/`, `.venv`, build dirs) and **gates on MEDIUM+ severity at MEDIUM+ confidence**
  (real SQL injection / weak crypto / command injection block a merge; LOW stays advisory).
- **Verified false-positives resolved at the source** so the gate is green *and* meaningful: a real
  scheme guard on the LLM/embedding clients (refuse to send the bearer key to a non-`http(s)`
  `base_url`), and justified `# nosec` on the constant-column SQL, the in-sandbox `--tmpfs` mount, and
  the restricted-`__builtins__` skill `exec`.
- Verel's own pre-merge gate now passes at MEDIUM+ with a publicly-verifiable ed25519 receipt
  (`graders_checked=4`) — the wedge, dogfooded end to end.

## 0.37.0 — mTLS, certificate pinning, per-IP fairness (closes the §15.4 transport residuals)

Closes the three code-closeable residuals named in v0.36.0 (§15.4), uniformly across the brain, lease
authority, and registry via `verel.transport`:

- **mTLS** — servers take `client_ca=` (require a client certificate signed by it, `CERT_REQUIRED`):
  transport-layer client authentication beneath the bearer/signature layers, so a stolen bearer token
  alone no longer connects. Clients present `client_cert=`/`client_key=`. `client_ca` without a server
  cert fails closed.
- **Certificate pinning** — clients take `pin_sha256=` (`transport.cert_sha256()` computes it): reject
  any server leaf cert outside the pinned set even if a trusted CA signed it (defeats a mis-issued or
  compromised-but-trusted CA). Additive to CA + hostname verification; pins are validated as 64-hex at
  build time (a malformed pin fails loud, never a silent never-match).
- **Per-source-IP fairness** — servers take `max_per_ip=` bounding how many of the global
  `max_connections` slots one source IP may hold (off by default; for routable/exposed binds).
- **MCP wiring** — `VEREL_BRAIN_CLIENT_CERT` / `VEREL_BRAIN_CLIENT_KEY` / `VEREL_BRAIN_PIN` (operator
  env only), via a shared `_remote_tls_kwargs()`.

**Honest residuals that stay operational/inherent** (§15.5): endpoint trust (closed at the application
layer by `verel_verify` on the ed25519 receipt — a malicious *configured* server's `trust`/`author`
claims), certificate issuance/rotation (operator-run; Verel is not a CA), per-IP is a concurrency
bound not a rate limiter, and the stdlib/OS/kernel/unknown-unknowns no audit removes.

Hardened through a **3-round adversarial red-team** (one LOW pin-validation footgun fixed; the last
round came back empty). 35 tests in `tests/test_brain_tls.py`. See `docs/SUBSTRATE_DESIGN.md` §15.5.

## 0.36.0 — TLS for routable brain/lease/registry binds

Roadmap item 3: transport confidentiality on any non-loopback bind, fail closed, with loopback staying
zero-config. The bind policy (§15.2) already refused an *anonymous* routable bind; a token-gated one
still crossed the wire in **cleartext** (bearer token, cluster credential, signed-write payloads all
sniffable). This closes that across all three HTTP services — the brain, the lease authority, and the
registry — via one shared `verel.transport` module.

- **Server TLS.** `MemoryServer`/`ControlPlaneServer`/`RegistryServer` take `certfile=`/`keyfile=` (or a
  built `ssl_context=`); `url` then reports `https://`. TLS 1.2+ floor.
- **Bind policy, tightened (fail closed).** A non-loopback bind now requires **both** an `auth_token`
  **and** TLS, else the server refuses to start. `host=""` is treated as routable (it's the `0.0.0.0`
  wildcard). Loopback stays plain-HTTP, zero-config.
- **Client TLS + cleartext-secret guard.** `RemoteMemory`/`ReplicaClient`/`RemoteLeaseStore`/
  `RemoteRegistry` take `cafile=`/`ssl_context=` (verify internal/pinned CAs) and **refuse to attach a
  bearer/cluster token to a non-loopback `http://` URL** (re-checked per request on the live token);
  `insecure=True` opts out for a TLS-terminating proxy.
- **DoS-resistant.** The TLS handshake runs in the per-connection worker thread (not the accept loop),
  and a `max_connections` semaphore (default 128, tunable) bounds concurrency — a stalled-connection
  flood can't starve `accept()` or exhaust threads. The client opener also ignores ambient
  `HTTP_PROXY`/`ALL_PROXY` (which would ship a token to a proxy in cleartext) and blocks token leaks
  across HTTP redirects.

Hardened through a **5-round adversarial red-team** (closed a wildcard-host bind bypass, an
HTTP-redirect token leak, a post-init guard bypass, a TLS-handshake accept-loop DoS, a proxy-env token
leak, and an unbounded-connection DoS; the last two rounds came back empty). 25 tests in
`tests/test_brain_tls.py`. See `docs/SUBSTRATE_DESIGN.md` §15.4.

## 0.35.0 — MCP `recall`/`remember` over a remote authenticated brain

Roadmap item 2: the MCP tools can now read from and write to a **hosted, multi-principal brain**, so a
fleet on different machines draws from ONE authenticated memory instead of per-install local stores.

- With `VEREL_BRAIN_URL` set, `verel_recall` reads the remote `MemoryServer` and `verel_remember`
  authors a **signed write as an authenticated principal** (`VEREL_PRINCIPAL_SEED`, a 32-byte ed25519
  seed) — the server enforces every guard (reserved-key, non-FACT backstop, cross-principal
  protection) and the cross-principal `verified` tier (fact-bound `evidence`). Optional
  `VEREL_BRAIN_TOKEN` (bearer) and `VEREL_CLUSTER_TOKEN` (replication) are threaded through.
- The local per-install brain stays the **zero-config default** — no behaviour change without the env.
- **Trust model (honest):** the remote `trust`/`author`/`reverified` reflect the *configured server's*
  claim (operator-trusted, same tier as a DB URL). An agent wanting integrity independent of the
  server calls `verel_verify` on the underlying ed25519 receipt — that survives a malicious peer.
- **Fails closed, never leaks:** missing/invalid seed → can read, can't author; an unenrolled
  principal is rejected (nothing written); a bad bearer surfaces as `HTTP 401`; an unreachable brain
  as a clean error — neither echoes the token or seed. Config is operator-env only (no agent tool arg
  can repoint the brain or forge a principal).

Shipped through a 3-round adversarial red-team (every round clean — only error-wording polish);
10 tests in `tests/test_mcp_remote_brain.py`. See `docs/SUBSTRATE_DESIGN.md` §15.2.

## 0.34.0 — cross-principal `verified` tier (fact-bound attestation)

Closes the last brain trust residual: a peer's belief can now earn the **`verified`** tier (not just
`candidate`) — but only via a **fact-bound attestation**, so trust still never travels by say-so.

- `verdict.fact_commitment(subject, predicate, text)` is a 256-bit commitment to a claim's content;
  `attest_fact()` mints a portable signed **GateReceipt** whose signed `subject` IS that commitment;
  `verify_fact_attestation()` accepts it iff it verifies, attests `verdict=PASS`, AND is bound to THIS
  exact claim — so an unrelated valid receipt can't launder a different fact.
- `memory.authenticated_remember(evidence=…)` earns the cross-principal `verified` tier only with a
  publicly-verifiable **ed25519** attestation (a peer verifies without the producer's secret);
  `RemoteMemory.remember_signed(evidence=…)` + `/write_signed` thread it (the response now returns
  `reverified`). The MCP `verel_remember` also promotes on a fact-bound attestation (local brain is
  single-principal, so hmac is accepted) and returns `fact_attested`.
- The reserved-key + non-FACT guards run BEFORE promotion, and the local and remote write paths now
  share one `memory.is_reserved_key` source of truth (so neither can touch the AuthorTrust ledger).

Shipped through a 4-round adversarial red-team (256-bit commitment; local non-FACT backstop; local
reserved-key guard; guard parity proven). 446-test suite; ruff + mypy clean.

## 0.33.0 — the hearing sense

An **Audel** hearing adapter (`senses/audio.py`) feeding the verdict bus as another grounded sense,
with cross-modal verdicts (Phase 5).

## 0.32.0 — the authenticated multi-principal brain

Turns the deferred multi-principal items from the 0.31.0 brain audit into real controls, so a **shared
remote brain** can be trusted across principals — not just one local operator.

- **Authenticated principals.** A principal is an **ed25519 keypair whose `key_id` IS its identity**
  (`verel.memory.Principal`). A write is signed; the server derives `author` from the **verified** key,
  never a caller-supplied string — so authoring as someone else requires their private key, and
  `AuthorTrust` can't be forged, inflated, or impersonated (closes the brain-audit **Finding 3**).
  Enrollment is pinning (operator publishes pubkeys), reusing the receipt key machinery.
- **Trust-weighted recall.** `rank()` now folds in the trust tier — at equal relevance a **verified**
  memory edges out a candidate, so a poisoned candidate can't outrank a verified fact (**Finding 4**).
- **Hosted wiring.** `MemoryServer(trusted_principals=…)` + a `/write_signed` endpoint
  (`RemoteMemory.remember_signed`); the replication channel (`/apply`, `/replicate`) now requires a
  **separate cluster credential** (`X-Cluster-Token`) distinct from the client bearer.
- **Hardened through a 7-round adversarial red-team** (the 7th came back clean): secure-by-default
  signed-writes mode (a bearer token can connect + read, but only signed writes author; the raw
  `/write` and all trust-mutation endpoints are refused); a **structural backstop** so a client `FACT`
  can never supersede a server-managed non-`FACT` record (failure ledger, skills, induced
  rules/schemas), plus a reserved-predicate/scope denylist for the one `FACT`-kind control record; a
  principal can't overwrite or reattribute another's verified belief; and `graduate()` stamps a
  collective author so a pre-empted key can't forge authorship of team knowledge. See
  `docs/SUBSTRATE_DESIGN` §15.

Residuals (honest): a cross-principal `verified` tier is still candidate-only (deferred, needs a
fact-bound attestation); no TLS on a routable bind (operator's responsibility; non-loopback refuses
without a token); the FACT-kind reserved-predicate denylist is a per-name maintenance obligation.

413-test suite; ruff + mypy clean.

## 0.31.0 — the shared verified brain: recall/remember over MCP

Completes the substrate's four hero verbs (`gate`, `sight`, `recall`/`remember`, `verify`): any agent
over MCP can now read and write a **shared verified brain** — and trust does not travel.

- **`verel_recall(query, scope, kind, k)`** reads via the scope lattice — resolves DOWN (self < team <
  org < global; most specific wins) and surfaces trust/confidence/support/provenance/fingerprint so a
  caller can weight what it gets.
- **`verel_remember(fact, scope, evidence, author)`** writes a CANDIDATE. The caller's self-asserted
  trust/confidence is **ignored**; a verifiable `evidence` receipt records **attested grounding**
  (provenance + tag) but does **not** auto-promote to verified — the receipt attests a run, not the
  fact, so promoting on the caller's unbound association would be trust *travelling*. A forged receipt
  cannot launder trust, and a VERIFIED belief is protected from silent overwrite.
- The brain is **one persistent store per server** (`VEREL_MEMORY_STORE` or `~/.config/verel/brain.db`),
  fixed and **not agent-controllable** (no arbitrary file read/write); inputs bounded; parameterized SQL.
- Shipped through audit → 3-round adversarial red-team: store/input/DoS clean; the trust hard-guarantee
  (no `verified` without a genuine runner-signed receipt) holds; two soft-trust paths fixed (no unbound
  auto-promote; verified-overwrite protection). The unauthenticated-author and trust-blind-ranking items
  are documented as the **deferred multi-principal remote-brain auth layer** (`docs/SUBSTRATE_DESIGN`
  §14.3) — acceptable under the local single-principal model.

390-test suite; ruff + mypy clean.

## 0.30.0 — the verification substrate: ed25519 public receipts + gate/sight/verify over MCP

Verel becomes a **verification substrate any agent can call over MCP** — a conscience, a pair of
eyes, and a receipt a *different* party can check. Three substrate slices, each shipped through the
full audit → 3-round adversarial red-team cadence (fix between rounds; not clean until a round comes
back empty).

- **Publicly-verifiable receipts (ed25519).** `RunReceipt` gains a second signing tier: HMAC-SHA256
  stays the default *within* a trust domain; **ed25519** adds public verifiability *across* domains —
  a second party verifies a receipt **offline with only the producer's public key**, no shared secret.
  Trust is **pinning, never TOFU**: a valid signature is necessary but not sufficient; the `key_id`
  must be in the verifier's trusted set (the runner's own key, or a published
  `~/.config/verel/trusted_keys/<key_id>.pub`). New `verify_receipt()` verb + `verel verify
  <receipt.json>` CLI. Optional extra `verel[attest]` (PyNaCl); absent → ed25519 **fails closed**,
  never silent green.
- **`gate` over MCP (the conscience).** `verel_gate` *runs the real graders* on a repo and returns the
  attested verdict + a signed, publicly-verifiable **gate-level receipt** that wraps the per-grader
  receipts. An agent can no longer self-declare "done", and "an agent cannot fake green" becomes
  checkable. New `verel_verify` MCP verb.
- **`sight` over MCP (the eyes).** `verel_sight` renders a URL through AgentVision and returns an
  **attested percept** — grounded observations with pixel bboxes, an `image_ref`, intent conformance,
  and a verifiable receipt bound to the screenshot bytes. SSRF-safe by default (private-network guard
  on; `allow_local` is an explicit opt-in); only `http(s)`.
- **Hardening from the red-team rounds (all regression-pinned):** injective (length-prefixed) signing
  payloads replacing non-injective `"|".join` across **every** signer (closed a real delimiter-injection
  on the receipt and on the toolsmith/registry HMAC signers); strict base64; ASCII-only `key_id`;
  cross-type domain separation (`runreceipt`/`gatereceipt`); the gate envelope signs the verdict +
  `ceiling_clamped` + a percept `subject` (image_ref/matches_intent) so no trust-implying field is
  unsigned; MCP host-boundary crash safety (no agent input can crash the connection; no `str(e)` leak).

378-test suite; ruff + mypy clean. CI now installs `verel[attest]` so the ed25519 tests run.

## 0.29.2 — CI fix for the v0.29.1 security release (no behavior change)

The v0.29.1 hardening made cross-tenant `import_skill` default to the **container** isolation tier,
which correctly **fails closed** when bubblewrap is absent. One test
(`test_trust_does_not_travel_import_reverifies`) re-verified a *trusted* artifact without opting out,
so it failed on bwrap-less CI runners. The test now passes `sandbox=False` (trusted test code runs
in-process), matching the other registry tests. **No product/source change** — the secure
container-default behavior is unchanged. 315 tests now green on CI (verified with bwrap masked).

## 0.29.1 — security: 3-round adversarial red-team (10 more findings closed)

A follow-up to 0.29.0: three independent adversarial red-team rounds on the hardened code, fixing
between rounds and not declaring clean until a full round came back empty. The rounds found **10
further issues** (2 verified-PoC), each fixed and pinned by a regression test. The final confirming
round could **not** forge an attested PASS or achieve code execution from untrusted input.

- **MCP/library RCE (the 0.29.0 container fix didn't reach the library default):** `eval_tool_cases`
  / `ToolSmith` still ran LLM/cross-tenant code **in-process** by default (a verified escape to real
  builtins). The default is now real isolation (`best`); cross-tenant **import** (`import_skill` /
  `measure_transfer`) and the MCP build path require the **container** tier (fail-closed without
  bwrap). In-process (`none`) must be opted into explicitly (trusted code only).
- **Receipt replay / input-binding:** `inputs_digest` was signed but never verified, and digested a
  *label* not content — and even once verified it was **vacuous** with empty `covers` (every shipped
  stage). Now the gate verifies it, it binds the **actual scanned bytes**, and it is **salted with a
  per-run nonce** so a PASS receipt is unique to its run and can't be replayed. `result_digest` also
  binds each issue's `fingerprint`.
- **DoS:** a negative `Content-Length` slipped past the body cap (`read(-1)` → EOF) on all three HTTP
  servers — now rejected.
- **Planted signing key:** the key file was read with no owner/mode/symlink check (a planted key
  forges signatures) — now `O_NOFOLLOW` + refuse foreign-owned / group-or-other-accessible → ephemeral
  fail-closed.
- **Fleet:** `FailureLedger.record`/`mark_fixed` read-modify-write is now lock-serialized (a
  concurrent worker can't mask a regression); registry publish writes atomically; the saga's
  forward-atomicity contract is documented.

315 offline-CI tests (`tests/test_security.py` now pins 13 hardening regressions). ruff + mypy clean.

## 0.29.0 — security hardening: a full attack-surface audit + red-team

A two-round security pass (a three-surface audit, then an adversarial red-team of the fixes) found
and closed **21 issues**, several with working proof-of-concept exploits. Every fix is verified
against the exploit and pinned by a regression test (`tests/test_security.py`). **Upgrading is
recommended.**

**Attestation integrity (the core guarantee).**
- No more **public default signing secrets** — keys resolve from an env var, else a persistent
  per-installation random key, else fail closed (`verel._secrets`). The old `verel-dev-*-secret`
  defaults let anyone forge an attested PASS. Tool signing moved to its own key domain.
- Run receipts now **bind the graded result** (verdict + every issue field the gate trusts:
  severity, confidence, source, plus `errored`) into the signature, so a valid receipt can't be
  paired with a tampered `Report` (stripping issues, or downgrading a CRITICAL via confidence).

**Untrusted / agent code.**
- The MCP `verel_build_tool` path now **requires the container tier** (bwrap netns + read-only fs +
  seccomp) and fails closed without it — no silent fallback to the rlimit-only subprocess tier
  (which had no network/seccomp isolation → RCE-with-network on bwrap-less hosts).
- The default seccomp denylist now blocks `clone`/`fork`/`vfork`; the subprocess tier sets
  `RLIMIT_NPROC`; seccomp no longer silently fails open when libseccomp is absent.

**Network services (memory / control-plane / registry).**
- Request-body **size caps** + handler timeouts (OOM / slowloris), **constant-time** bearer-token
  comparison, clean 400s for malformed/deeply-nested bodies, and a **refusal to bind a non-loopback
  interface without an auth token**.
- Registry lookup validates the content hash (path traversal); artifact `side_effect` is now signed
  and cross-origin overwrites are refused.

**Fleet.**
- Lease terminal writes (`complete`/`release`) are **owner-bound**, not token-only (a readable token
  could otherwise hijack another task's outcome). `task_id` is validated before it becomes a path /
  git ref; `git worktree add` is hardened against option injection.

**Behavior changes to know when upgrading:**
- Cross-machine receipt/tool verification now needs a **shared `VEREL_RUNNER_SECRET` / `VEREL_TOOL_SECRET` /
  `VEREL_REGISTRY_SECRET`** (no default to fall back on).
- A server bound to a non-loopback host **must** be given `auth_token=...` or it refuses to start.
- MCP tool-building **requires bubblewrap**; without it the build fails closed.

309 offline-CI tests (+ `tests/test_security.py`). ruff + mypy clean.

## 0.28.0 — quorum reads: a point read survives the leader being down

Strong reads (0.27) route to the leader — so a read **fails when the leader is unavailable**. Quorum
reads close that gap: a point read polls replicas and returns the freshest copy, tolerating leader
downtime as long as a quorum of replicas still hold the record.
- **Versioned records**: the leader stamps a monotonic version `token * STRIDE + seq` on every
  mutation. Versions increase within a leader *and* across failovers (a new leader has a higher
  fencing token), so any replica can tell which copy of a record is freshest. `version_of(record)`
  is exported.
- **`read_consistency="quorum"`** + **`read_quorum`** (default 1) on `ReplicatedMemory`: `get`
  polls up to `read_quorum` replicas (this node + its `sources`) and returns the **highest-version**
  copy. A read survives the leader being down — strong reads can't — and an unreachable replica
  simply doesn't count toward the quorum.
- **Reorder-/duplicate-safe replication**: `apply_replica_fenced` now drops an incoming record whose
  version is *older* than the copy already held, so a delayed or duplicated replicate never regresses
  a newer value.
- Verified live: versions are monotonic and jump across failover; a quorum read returns the record
  with the leader down; the freshest copy wins over a stale replica; an older replicate is ignored.
  300 offline-CI tests (+ `tests/test_quorum_reads.py`).

**HA brain — hardened end to end:** fault-tolerant replication (0.24) · self-healing anti-entropy
(0.25) · crash-safe write durability (0.26) · read-your-writes (0.27) · quorum reads (0.28). No
SPOF, no split-brain, no lost acked writes, reads that survive leader downtime.

## 0.27.0 — read-your-writes: opt-in strong reads from the leader

Completes the HA-hardening pass. Reads were always local (eventual) — a client reading a follower
right after writing the leader could miss its own write. Now strong reads are available when needed.
- **`read_consistency`** on `ReplicatedMemory` (default `"eventual"`): `"strong"` routes reads
  (`get` / `recall` / `all`) to the **current leader** — the single writer, so it holds every
  committed write — giving read-your-writes / linearizable-ish reads. Needs `sources` (owner →
  readable view, e.g. a `RemoteMemory`); falls back to local if no leader can be resolved.
- `leader_view()` exposes the resolved read target; the leader reads its own local store under
  strong mode (no needless hop).
- Verified live: an eventual follower may miss a recent write while a strong follower reads it from
  the leader; read-your-writes holds; strong reads route over HTTP. 280 offline-CI tests.

**HA brain — hardened end to end:** fault-tolerant replication (0.24) · self-healing anti-entropy
(0.25) · crash-safe write durability (0.26) · read-your-writes (0.27). No SPOF, no split-brain,
no lost acked writes, optional strong reads.

## 0.26.0 — write durability: an acked write survives a leader crash

Closes the small durability window in the HA brain — a write that returned could be lost if the
leader crashed before its sqlite commit reached disk.
- **Crash-safe by default**: an on-disk `LocalMemory` now opens `PRAGMA journal_mode=WAL` and
  `PRAGMA synchronous=FULL`, so every commit is **fsync'd before it returns**. A leader's write is
  durable *before* its replica is acked, and survives a process/leader crash. WAL also gives atomic,
  recoverable commits and better read/write concurrency.
- **`LocalMemory(durable=...)`** (default `True`): `durable=False` relaxes to `synchronous=NORMAL`
  (faster, weaker) where durability isn't required; `MemoryServer(durable=...)` threads it through.
  `:memory:` stores are unaffected.
- Verified live: a write survives reopening the db after an unclean close; a disk-backed
  `ReplicatedMemory` leader's acked write is on disk after a crash. 274 offline-CI tests.

## 0.25.0 — background anti-entropy: lagging followers self-heal

Catch-up was manual (`sync_from`) in 0.24.0; now a follower that fell behind — or just recovered —
reconciles itself automatically.
- **`AntiEntropy`**: a background reconciler that periodically resolves the *current* leader (via the
  lease store's new `holder`), maps it to a readable source, and `sync_from`s it. A no-op while this
  node is the leader or no leader holds the lease; best-effort (a failed cycle never crashes the
  loop). `start()`/`stop()` run it in a daemon thread; `tick()` runs one cycle (for tests/manual).
- **`LeaseStore.holder(key, *, now)`** — the current live owner of a lease — added to the Protocol,
  `InMemoryLeaseStore`, `SqliteLeaseStore`, and the control plane (`/holder` endpoint +
  `RemoteLeaseStore.holder`), so "who's the leader" is queryable across machines.
- Verified live: a lagging node syncs the leader's full state on a tick; the leader never syncs from
  itself; the background loop self-heals a node with state written *after* it started. 269 offline-CI
  tests.

## 0.24.0 — fault-tolerant replication: a dead follower can't break the brain

Hardens the HA memory from 0.23.0, where any unreachable follower failed every write.
- **Tolerates follower failure**: the leader commits locally, then replicates best-effort — an
  unreachable peer is counted as *lagging*, not fatal. A write is durable once `write_quorum` nodes
  (incl. the leader, default 1) hold it; below quorum raises `ReplicationError`.
- **State-based, idempotent replication**: the leader now replicates the *resulting record verbatim*
  (`apply_replica`) instead of the op, so re-delivery is idempotent and a follower mirrors the
  leader exactly — no confidence drift. New `apply_replica` on every backend (`LocalMemory`, mem0,
  `RemoteMemory`) and the `MemoryView` Protocol.
- **Catch-up** (`sync_from`): a lagging or recovered follower pulls the leader's full state and
  applies it verbatim.
- **Observability** (`replication_status`): acks / lagging / quorum from the last write.
- Verified live: a write succeeds despite a dead follower; quorum enforced; re-delivery is
  idempotent; `sync_from` catches a late node up. Wire: `MemoryServer` `/replicate` carries a record
  (fenced), `/apply` for sync; `ReplicaClient.apply_replica_fenced`. 262 offline-CI tests.

## 0.23.0 — replicated, HA shared memory (no SPOF, fenced between authorities)

Closes the one limitation flagged in 0.20.0: the hosted brain was a single writer / single point of
failure. Now it can run as a fault-tolerant cluster, reusing the fleet's fencing-token primitive.
- **`ReplicatedMemory`**: one node of a leader-fenced cluster. Exactly one node is leader (held by a
  fencing lease over a shared `LeaseStore`); the leader applies every mutation locally and
  **replicates** it to its peers; reads are served from any node's replica (eventual consistency).
- **No split-brain**: a non-leader's write is refused (`NotLeaderError`); when a leader's lease
  lapses a peer takes over with a **higher token**, and the deposed leader is fenced — its writes
  are rejected and any in-flight replicate it sends hits `FencingError` at the follower.
- **Cross-machine**: `MemoryServer` gains a `/replicate` endpoint and a `ReplicaClient` peer, so a
  cluster of `MemoryServer`s on different machines replicates over HTTP, with the hosted control
  plane (`RemoteLeaseStore`) as the shared fencing authority. Verified live end-to-end: write→leader
  replicates to follower, non-leader writes get 421, failover promotes a follower at a higher token.
- `decay` is per-node maintenance (each replica self-maintains; nodes converge). 257 offline-CI tests.

## 0.22.0 — the librarian: the brain compounds without rotting (shared-brain set complete)

The fourth and final shared-brain slice — the gated maintenance cycle ("sleep") that keeps a
growing brain from becoming a junk drawer. Pure orchestration of primitives that each earn their
own trust, over any `MemoryView` (incl. `RemoteMemory`, so it maintains the *shared* brain).
- **`librarian_pass`**: one upkeep cycle over a scope — (1) **consolidate** recurring failures into
  candidate rules, (2) **induce** the multi-hop schema hierarchy, (3) **graduate** beliefs verified
  across sibling scopes up the lattice, (4) **prune & decay** what §5 allows. Each step is
  toggleable; it returns a `LibrarianReport` (`rules_induced` / `schemas_induced` / `graduated` /
  `pruned`).
- **Nothing is decreed**: steps 1–3 write only `candidate`/`inferred` records (they still face the
  promotion gate); prune never drops a `verified` or `pinned` memory. The librarian *proposes and
  tidies* — it never mints trust. Verified live, including curating a shared store through
  `RemoteMemory`.
- `examples/demo_shared_brain.py` now walks the full arc: resolve-down → graduate-up → cross-agent
  trust → librarian → hosted. 250 offline-CI tests.

**Shared team brain — complete:** scope lattice (cognition) · hosted memory (cross-machine
substrate) · cross-agent trust (safety) · librarian (curation). Each agent thinks privately, shares
verified distillations, and the collective accepts only what re-verifies.

## 0.21.0 — cross-agent trust: sharing the brain *safely*

The third shared-brain slice — what makes opening the brain to *many* agents robust against one
sloppy or adversarial contributor. Pure logic over any `MemoryView` (incl. `RemoteMemory`).
- **`import_belief`**: the registry's "trust does not travel" rule, applied to beliefs. A peer's
  claim enters the importer as a `candidate` and becomes `verified` ONLY by passing the importer's
  own `verify` check in its own context — the claim's self-asserted trust/confidence are ignored.
- **`AuthorTrust`**: a per-author reputation, persisted *in the brain* so every agent shares the
  same view of who's reliable. `prior(author)` is a Laplace-smoothed re-verification rate (neutral
  0.5 when unknown). A fresh import's starting confidence is anchored to the author's prior (0.3 …
  0.7), not the peer's assertion — so a noisy author's claims need more corroboration before they
  surface, and a single bad actor can't move the collective. Verified live: a peer's "VERIFIED,
  conf 0.99" claim still enters as a candidate; reliable author → ~0.9 prior, noisy → ~0.3.
- `author_of()` reads the contributor (stored in detail, round-trips across backends);
  `BeliefImport` reports the outcome. `examples/demo_shared_brain.py` gains the cross-agent section.
- 244 offline-CI tests.

Next slice: the "librarian" — a gated, scheduled consolidation/curation pass so the shared brain
compounds without rotting.

## 0.20.0 — hosted shared memory: a fleet shares one brain over HTTP

The second shared-brain slice — agents on **different machines** read and write one store.
- **`MemoryServer`**: wraps a durable `MemoryView` (a `LocalMemory` from a `db_path`, opened
  cross-thread, or your own store) in a tiny stdlib HTTP service exposing the full Protocol —
  write / get / recall / all / corroborate / contradict / promote / demote / annotate / set_flags /
  pin / unpin / decay. Optional bearer token. The server is the **single writer**: every access is
  lock-serialized, so the interference rule (same `(subject,predicate,scope)` supersedes) stays
  correct under concurrent agents.
- **`RemoteMemory`**: a `MemoryView` over HTTP — a drop-in for `LocalMemory`/`mem0`, so
  `lattice_recall`, `graduate`, consolidation, and the promotion gate all work against the shared
  brain unchanged. Verified live: Alice writes, Bob recalls; corroboration is shared; 40 concurrent
  writes serialize cleanly; the interference rule holds over the wire; bad auth is rejected.
- `LocalMemory(check_same_thread=False)` so a server can serve it from its HTTP thread.
- `examples/demo_shared_brain.py` now ends with the hosted flow; 237 offline-CI tests.

Next slice: per-author trust + `import_belief` (re-verify on cross-agent import), then the
"librarian" curation pass.

## 0.19.0 — scope lattice: the foundation of a shared team brain

The first slice of the shared-brain work — the mechanic that turns individual memory into
collective memory, built on the existing trust layer (pure logic, no infra, any `MemoryView`).
- **`ScopeLattice`**: a child→parent map over scopes (`repo → team → org → global`); a scope with
  no explicit parent rolls up to `global`, so existing flat scopes behave exactly as before.
- **Resolve down** (`lattice_recall`): an agent recalls across its scope *and all ancestors* at
  once, ranked by the documented `rank()` plus a small specificity bonus so the most-specific scope
  wins ties (a repo override beats the team default, but the team's knowledge stays in view). A pure
  read — no recall-reinforcement side effect across scopes.
- **Graduate up** (`graduate`): a belief independently **verified** in `>= min_scopes` sibling child
  scopes is promoted to the parent as a **candidate** (records `detail['graduated_from']`) — it must
  re-earn `verified` at the higher level via the promotion gate. Single-scope quirks and unverified
  beliefs never graduate; trust is never decreed by height.
- `examples/demo_shared_brain.py`; 231 offline-CI tests.

Individual and collective cognition are the same verbs at different radii of the lattice — next
slices: a hosted shared `MemoryView` service, and per-author trust on cross-agent imports.

## 0.18.0 — schema-split propagation (close the one real consistency hole revision left)

0.15.0's revision could split a leaf rule but left the schemas above it derived from the old,
broader rule — a corrected leaf under an over-claiming principle.
- **`propagate_revision`**: after a split, every `SCHEMA` whose `subsumes` includes the revised
  rule is re-derived from its CURRENT members (the narrowed rule among them), superseding the stale
  principle and resetting to `candidate` so it must re-earn trust. It then recurses **up** the
  hierarchy (order-2 → order-3 → …), with a depth guard. A schema that can't be re-derived is
  `contradict`ed rather than left over-claiming; unrelated schemas are untouched.
- Wired into `revise_with_counterexample`: a split now returns the re-derived schemas
  (`Revision.propagated`). Verified live: splitting a rule re-derived both its order-2 principle
  and the order-3 meta-principle above it.
- 220 offline-CI tests.

## 0.17.0 — the hosted skill registry (the H2 sweep justified it; trust still doesn't travel)

The two-model H2 sweep measured ~88–89% cross-tenant transfer → BUILD, so the public registry is
now built as a service.
- **Hosted registry** (`registry/hosted.py`): `RegistryServer` serves a `PublicRegistry` over a
  tiny stdlib HTTP API — `POST /publish` (verifies the signature; refuses a tampered or unsigned
  artifact with 400), `GET /search`, `GET /fetch`, `GET /all`. Optional bearer token.
- **`RemoteRegistry`**: a `PublicRegistry`-shaped client over HTTP, so
  `import_skill(remote.get(hash), into=local, target_cases=...)` works unchanged across machines.
- **Trust does not travel — end to end**: the server stores and integrity-checks artifacts but
  confers no trust; a fetched skill enters as a `candidate` and only becomes `verified` by passing
  the importer's OWN held-out eval. Verified live over real HTTP: a universal skill (slugify)
  re-verifies for a second tenant; a tenant-specific one (tax_total@8%) stays a candidate for a
  10% tenant; a tampered publish is refused; bad auth is rejected.
- 216 offline-CI tests.

## 0.16.0 — hosted control plane: the fencing authority behind an HTTP API (cross-machine)

The lease stores needed a shared filesystem; this lets managers on different machines coordinate.
- **Control plane** (`fleet/control_plane.py`): `ControlPlaneServer` wraps a durable
  `SqliteLeaseStore` in a tiny, dependency-free (stdlib `http.server`) HTTP service —
  acquire/renew/release/complete + token/outcome. The **server is the clock authority** (it stamps
  `now` itself), so managers with skewed clocks can't disagree about lease expiry. An optional
  bearer token gates access.
- **`RemoteLeaseStore`**: a `LeaseStore` over HTTP that speaks the same Protocol, so
  `Scheduler(leases=RemoteLeaseStore(url), owner=host)` coordinates cross-machine with no other
  change. Fencing holds over the wire: a stale `complete` returns 409 and the client raises
  `FencingError`. **Verified live** — two schedulers pointed at one control plane run each task
  exactly once and converge; a stale leader's write is refused; bad auth is rejected.
- 211 offline-CI tests.

## 0.15.0 — contradiction-driven schema revision (consolidation that can be wrong, and recovers)

Consolidation only ever grew. Now it can contract when reality disagrees.
- **Revision** (`memory/revise.py`): a new failure in a rule's domain that the rule failed to
  prevent is a counterexample. `revise_with_counterexample` records it (`annotate`, no
  corroboration), `contradict`s the rule, and once `split_after` counterexamples accumulate asks
  the LLM to **split** the over-broad rule into a NARROWED general rule (which supersedes the
  original via the interference key) plus a specific EXCEPTION rule — both candidate + inferred. If
  belief collapses below the reject floor, the rule is `rejected`. `contradicts(rule, failure)` is
  the pure domain-match check. Revision only ever lowers trust or narrows scope; it never
  auto-verifies.
- **`MemoryView.annotate`**: a new backend method (LocalMemory + mem0) to update a record's audit
  detail (e.g. its counterexample list) WITHOUT the corroboration side effect of `write`.
- 210 offline-CI tests.

## 0.14.0 — H2 broadened + swept across models (the moat decision no longer rests on one run)

- **Model sweep** (`examples/run_h2_sweep.py`): the H2 corpus-transfer measurement now runs across
  multiple (provider, model) configs on a **broadened corpus** (8 universal + 4 tenant-specific
  skills × 4 tenants) and tabulates the transfer rate per model. Measured live:
  - Ollama `qwen3-coder:480b` — 12/12 built, **32/36 = 89% → BUILD**
  - OpenAI `gpt-4o-mini` — 11/12 built, **29/33 = 88% → BUILD**
  Per-skill rates are identical across the two models (universal 100%; tenant-specific only where
  the tenant's rule matches), so the BUILD decision holds across models, not just one run.
  `docs/H2_RESULTS.md` now records the cross-model comparison.
- No library code change — a measurement/experiment release.

## 0.13.0 — fleet: git fencing sink (durable) + cross-repo atomic sagas

Completes the distributed-safety story the fencing leases started.
- **Git fencing sink** (`fleet/fence_sink.py`): a `pre-receive` hook fences *pushes*, not just
  task-store writes. The pusher sends `(resource, token)` as git push options
  (`git push -o verel-resource=R -o verel-token=N`); the hook accepts only when the token **is**
  the current one for that resource (checked against the sqlite lease store) — a stale leader's
  push, an unknown resource, or a forged higher token are all refused. `write_pre_receive_hook`
  installs it and enables push options on the bare remote. **Verified end-to-end against a real
  bare repo**: a stale push is rejected by the hook, the current one accepted.
- **Cross-repo atomic sagas** (`fleet/saga.py`): a multi-repo change commits as a saga — each step
  has a forward action and a compensation; the first failure runs the compensations of the
  already-committed steps in **reverse** order and skips the rest, so the set is all-or-nothing.
  `git_revert_head` is the safe compensation (an inverse commit, never a reset). A compensation
  that itself fails is reported, not swallowed.
- 204 offline-CI tests (incl. real-git end-to-end checks, skipped where git is absent).

## 0.12.0 — consolidation: multi-hop schema hierarchy + cross-scope generalization

- **Multi-hop hierarchy** (`induce_hierarchy`): consolidation no longer stops at one schema level.
  It climbs — rules → order-2 principles → order-3 meta-principles → … — each level consolidating
  the one below, until the corpus stops supporting a higher level (returns `{order: [schemas]}`).
  Every node stays `candidate`; height never confers trust.
- **Cross-scope consolidation** (`consolidate_across_scopes`): a failure pattern that recurs across
  **several repos** is lifted into a `global` `DesignRule` — but only when its evidence spans
  `>= min_scopes` distinct scopes (it records `detail['spans']`); a single-repo quirk is refused.
- **Better clustering**: `cluster_records` now buckets by a record's natural category (a failure's
  `kind`, a rule's `covers_kind`, else the `MemoryKind`), so same-family rules group together —
  which is what lets a higher hierarchy level find more than one cluster.
- 198 offline-CI tests.

## 0.11.0 — H2 measured for real + a tool-smith reuse-safety fix it exposed

Ran the §8.7 corpus-transfer experiment on a **live-built** corpus to resolve the moat bet with
data instead of assumption.
- **Real H2 run** (`examples/run_h2.py`, Ollama `qwen3-coder:480b` → OpenAI fallback): the
  tool-smith builds a mixed corpus — universal skills (slugify, is_palindrome, word_count,
  initials) + tenant-specific ones (tax_total@8%, price_label, order_code) — then each verified
  skill is re-verified against 4 tenants' own held-out cases. Measured **17/21 = 81% transfer →
  BUILD** (well above the 20% kill-line): universal skills transfer 100%, tenant-specific ones
  only where the rule matches (tax_total 33%, the EUR/10% tenant rejects the USD/8% skills).
  Result recorded in `docs/H2_RESULTS.md`. One corpus, one model — honest, not the last word.
- **Tool-smith reuse must re-verify** (correctness fix the run exposed): `ToolSmith.build` reused
  a semantic capability match **without** re-running it against the new spec's held-out cases, so
  a close-but-different tool could be returned as "verified" (it collapsed two skills in the first
  H2 run). Reuse now re-evaluates the candidate against the new cases and only short-circuits on a
  pass; otherwise it rebuilds. +1 regression test.
- 193 offline-CI tests.

## 0.10.0 — distributed fleet: fencing leases for concurrent managers + multi-repo DAGs

The scheduler was single-writer by design (so split-brain couldn't happen). This lifts that limit
safely — the v3 fencing work the code had deferred.
- **Fencing leases** (`fleet/lease.py`): a `LeaseStore` where every lease carries a **monotonic
  token**. Taking over an expired lease bumps it; same-owner renewal keeps it. Every terminal
  write is **fenced** — a stale leader whose token isn't current is rejected (`FencingError`), so
  it can't corrupt shared state. `InMemoryLeaseStore` (one process) and `SqliteLeaseStore`
  (`BEGIN IMMEDIATE`, cross-process).
- **Concurrent managers**: `Scheduler(leases=store, owner=...)` runs only tasks it can lease,
  fences its terminal writes, and **adopts peers' recorded outcomes** — so N schedulers over one
  store run each task exactly once and converge. With no `leases`, behaviour is byte-for-byte the
  single-writer v1.
- **Multi-repo coordination** (`fleet/multirepo.py`): `plan_multi_repo` namespaces per-repo tasks
  (`repo::id`), rewrites intra-repo deps, adds `CrossDep` edges, and validates the combined DAG
  acyclic (a cross-repo cycle is rejected up front, never deadlocked). One fenced scheduler then
  enforces cross-repo ordering ("ship the client only after the API builds").
- `examples/demo_distributed_fleet.py`; 192 offline-CI tests.

## 0.9.0 — deepened consolidation: adaptive decay, semantic clustering, structured + 2nd-order rules

The Brain's "episodic → semantic" step gets richer and its decay gets smarter.
- **Adaptive decay** (`effective_half_life`): a memory's half-life now stretches with demonstrated
  usefulness — `support_count` (log) + `epistemic_confidence` above the prior — capped at 6×. A
  corroborated rule outlives a one-off. Reachability tuning only; truth still moves solely via
  corroborate/contradict. Wired into the shared `apply_decay`, so LocalMemory and mem0 match.
- **Semantic clustering** (`cluster_records`): consolidation buckets failures by kind first (a
  strong prior — distinct kinds never merge), then, with `semantic=True` and a real embedder,
  refines each bucket by MEANING (cosine single-link) into finer sub-patterns.
- **Structured induction**: an induced `DesignRule` now carries `condition` / `action` /
  `applies_to` slots (not just a one-liner), so its matcher and the held-out gate test something
  specific. Back-compatible with the old `{subject, rule}` form.
- **2nd-order schemas** (`induce_schemas`, new `MemoryKind.SCHEMA`): clusters the DesignRules
  themselves and induces a higher-level principle that subsumes a family of rules. Guards against
  re-consolidating schemas. Candidate + inferred — earns trust the same way.
- `examples/demo_consolidation.py`; 181 offline-CI tests. The LLM is Ollama Cloud (OpenAI
  fallback); the chat fn is injectable so the whole module is tested offline.

## 0.8.0 — broadened senses: Python · JS/TS · Go · perf · security on one bus

The verdict bus stops being Python-only. A `GraderSpec` now carries its own parser, so graders
that share a `GraderKind` but not an output format coexist:
- **JS/TS**: `jstest_spec` (TAP — node:test/tape/vitest), `eslint_spec` (JSON), `tsc_spec`.
- **Go**: `gotest_spec` (`go test -json`), `govet_spec`.
- **Perf** (`perf_spec`): a PRECISE grader — a benchmark metric past an **explicit budget** is a
  gating ERROR (so a perf regression can drive rollback); within budget is clean. Never inferred.
- **Security** (`bandit_spec`, `npm_audit_spec`): SAST/dependency audit — HIGH/CRITICAL map to
  gating ERROR, MEDIUM→WARNING, LOW→INFO, so a low finding advises without blocking.
- **Language toolchains** (`verel.ci.LANGS`): every stage takes `language="python"|"js"|"go"`;
  `premerge_stage(..., security=True, perf=spec)` adds the precise senses. Adding a runtime is one
  `LangToolchain` entry.
- All ride the existing contract: attested `RunReceipt`, stable fingerprints, one gate, one
  stuck/progress signal. Parsers are pure, so the matrix is tested offline (no node/go/bandit).
- `examples/demo_polyglot_ci.py`; 171 offline-CI tests.

## 0.7.0 — per-capability seccomp jail (a tool earns each syscall by verifying)

The tightest isolation tier, and the one that ties containment to Verel's verification discipline:
a tool may use only the syscalls it **exercised while passing its held-out eval**.
- **Policy learning** (`toolsmith/seccomp_learn.py`): `learn_syscall_profile()` runs the tool over
  its eval cases under `strace` and unions the syscalls observed — the tool's footprint. Needs
  strace at build time only; enforcement needs just libseccomp.
- **Capability profile** (`seccomp_profile="capability"`): default-deny, allowing the learned
  policy unioned with a `RUNTIME_FLOOR` (interpreter+libc essentials, so a thin trace can never
  crash CPython) and the bwrap supervisor syscalls. Strictly ⊆ the allow-list jail — a syscall the
  tool never earned is refused even if the allow-list would permit it.
- **Frozen onto the tool**: `ToolRecord.syscall_policy` (operator metadata, not in the code
  signature); `ToolSmith(learn_syscalls=True)` learns + stores it on a verified build.
- Verified live under bwrap: the verified math tool runs 10/10; `socket()`, `subprocess`,
  `os.fork()` are refused; and a benign `os.pipe()` that the allow-list jail permits (returns 5)
  is **refused** under the tool's math policy — per-tool tightening, proven, not asserted.
- New exports: `PROFILE_CAPABILITY`, `capability_allow`, `learn_syscall_profile`,
  `strace_available`; `build_bpf(profile=, allow=)`, `run_container(seccomp_profile=, seccomp_allow=)`.
- `examples/demo_capability_jail.py`; 156 offline-CI tests.

## 0.6.0 — the strict allow-list seccomp jail (default-deny for untrusted tool code)

The 0.5.0 denylist was defense-in-depth; this is the real minimal jail, the last roadmap item
on tool isolation.
- **Allow-list profile** (`seccomp_profile="allowlist"`): a default-**deny** filter (EPERM on
  anything not listed) that allows only the syscalls a single-threaded, pure-compute CPython
  payload needs — derived by tracing `python3 -I -S` over representative pure tools, plus a margin
  for libc/stdlib variation, and the handful bwrap's own pid-namespace init needs to reap the
  child. By omission it withholds **all** network syscalls, **all** process-spawn syscalls
  (`clone`/`fork`/`vfork` — so no subprocess and no threads), and every privileged family.
- Verified live under bwrap: pure tools (math/json/re/hashlib/decimal/datetime) run; a tool that
  opens a `socket()`, runs a `subprocess`, or calls `os.fork()` is refused with EPERM.
- EPERM (not SIGSYS-KILL) is the default action, matching the Docker/podman convention — a
  refusal surfaces as a Python `PermissionError` instead of crashing the interpreter.
- `run_container(..., seccomp_profile=...)`; `build_bpf(..., profile=...)`; new `ALLOWED_SYSCALLS`,
  `PROFILE_DENYLIST`, `PROFILE_ALLOWLIST` exports. Default stays `denylist` (safe for arbitrary
  tools); the allow-list jail is opt-in for untrusted code.

## 0.5.0 — seccomp on the §7.7 container runner (closing the last sandbox overclaim)

The container tool runner promised "seccomp containment" in its docstring but only did namespace
isolation. Now it's real:
- **seccomp-bpf syscall filter** (`toolsmith/seccomp.py`): a deny-list filter (default ALLOW,
  EPERM on a curated set — ptrace, mount, raw `socket`, unshare/setns/clone3, bpf, kexec, module
  loading, keyring, chroot/pivot_root, device-node creation, cross-process memory peek) compiled
  via libseccomp and handed to `bwrap --seccomp`. Optional defense-in-depth: needs the `seccomp`
  or `pyseccomp` binding (new `verel[container]` extra); without it the namespace sandbox still
  applies and `seccomp_available()` reports False.
- `run_container(..., seccomp=True)` is the default; `exec_child` gained `pass_fds` to hand the
  compiled BPF program to the sandboxed child.
- Verified live: under seccomp a tool calling `socket()` is denied with EPERM, while the SAME
  tool succeeds with `seccomp=False` — proving the network namespace blocks `connect()`, not
  `socket()`, and seccomp is the layer that does. Normal pure tools run unaffected.
- Fixed a committed version drift: `verel.__version__` was stuck at 0.4.2 while the package was
  0.4.5; both now track the real version.
- 153 offline-CI tests (+1 always-on; the live containment checks skip where bwrap/libseccomp
  are absent).

## 0.4.5 — developer adoption (CI gate Action + pre-commit), in sync with the eyes

Symmetric adoption polish so the brain drops into a workflow as easily as the eyes:
- **Reusable GitHub Action** (`action.yml`): installs Verel (+ your deps) and runs the verdict
  bus gate (`verel-ci check`) — tests + lint + types in one verdict; fails the build on FAIL.
- **pre-commit hook** (`.pre-commit-hooks.yaml`): `verel-precommit` gates commits on the bus.
- README "Drop it into your workflow & your agents" section (Action, pre-commit, native hook,
  `verel-mcp`, `verel[sight]` for visual gating + `watch`).
No library code change; cut so a pinned `@v0.4.5` action ref and `pip install` align.

## 0.4.4 — temporal perception: the eyes can now *watch* (AgentVision 0.6.0)

AgentVision 0.6.0 added temporal verification (`watch` — playback/loading/liveness over a
frame sequence). The brain now drives and records it:

- **`verel.senses.watch(source, …)`** — a temporal sense mirroring `perceive()`. Returns the
  same `SightResult`, so the verdict bus consumes it like any sense. A deterministic video
  **stall** (currentTime not advancing) is DOM-sourced → precise → **gates to FAIL**; the
  temporal *vision* findings are advisory/clamped — exactly the right trust split.
- **`Percept` gains `playing` / `live` / `stabilized`**, extracted from the watch signal and
  recorded by `PerceptLog`, so the brain can gate releases on *verified playback* and
  **compound** "the player plays (with captions)" across builds instead of re-checking it.
- +2 sight-adapter tests (152 passing). Keeps eyes and brain in sync.

## 0.4.3 — eyes intent conformance (AgentVision 0.3.0 compatibility)

- **Forward-compat with AgentVision 0.3.0**: `verdict.models.IssueKind` gains
  `intent_mismatch`. AgentVision 0.3.0 added intent-conformance grading, which emits
  `intent_mismatch` issues; without this the sight adapter raised
  `ValueError: 'intent_mismatch' is not a valid IssueKind` on any conformance run.
- **Intent conformance reaches the brain**: `Percept` gains `matches_intent`,
  `intent_satisfied`, `intent_total`, populated by `senses.sight.from_agentvision` from the
  AgentVision Report's `conformance`, and recorded by `PerceptLog` — so the brain can compound
  *"did the artifact match what we set out to build"* across iterations. A full brain still
  ingests the rich Report and runs its own gate/stuck detection; it does not consume
  AgentVision's distilled `next_action`. +3 sight-adapter tests.

## 0.4.2 — docs sync

- README, Hugging Face landing, and module guide updated for the 0.4.x memory lifecycle
  (pin / volatile / TTL / staleness / correction chains); test count refreshed (148);
  the HF "Design & plan" link now points to the public ARCHITECTURE.md (not the internal
  strategy doc).

## 0.4.1 — failure-ledger × lifecycle (self-cleaning, permanent-where-it-matters)

- The ci-medic's **transient (retry) and flaky** failures are now written `volatile` to
  failure-memory, so they self-clean unless they RECUR (a recurrence re-asserts and confirms
  them). Genuine regressions are never volatile. Wired through `run_stage`.
- A failure marked **fixed** is now `promote`d AND **pinned** — confirmed regression knowledge
  never decays or prunes, so the regression guard catches a reintroduction however long later.
- `MemoryView` protocol gains `set_flags`/`pin`/`unpin`. +5 tests.

## 0.4.0 — memory lifecycle (pin / volatile / TTL / staleness / correction chains)

Ideas validated by the r/aiagents memory thread, added to `verel.memory` (both LocalMemory
and the mem0 adapter, identical behaviour via a shared `apply_decay`):
- **Pinned** memories ignore decay entirely and are never pruned (`mem.pin(id)`).
- **Volatile-until-confirmed**: a `volatile` memory is dropped unless corroborated/verified
  within its window (`VOLATILE_TTL_S`); corroboration/promotion clears the flag.
- **Hard TTL** (`ttl_s`) for ephemeral environment facts (e.g. "current branch is X").
- **Context-triggered staleness**: records idle past `STALE_AFTER_S` are flagged `stale`.
- **Correction chains**: superseding a value keeps the full prior history (`correction_chain(r)`)
  instead of overwriting it.
New helpers: `is_pinned/is_volatile/is_expired/correction_chain`, `set_flags/pin/unpin`.

## 0.3.2 — brand & docs polish

- New README with a hero banner + architecture infographic (matches AgentVision's polish).
- Brand graphics generated with OpenAI **gpt-image-2** (hero, key-visual, eval-loop); the
  architecture **infographic is rendered & verified by AgentVision** (the eyes Verel ships).
- Hugging Face Space landing redesigned (`media/space_index.html`). Image URLs are absolute
  so the banner renders on GitHub and PyPI alike. Heavy media excluded from the sdist.

## 0.3.1 — polish pass (lint/types clean, typed, dogfooded)

- **ruff + mypy clean** across `src/` (config in pyproject); ruff passes on tests/examples too.
- **Ships type information** (`py.typed`, PEP 561) — downstream users get Verel's types.
- **Dogfooding invariant enforced in CI**: a step runs Verel's own pre-merge verdict bus
  (pytest + ruff + mypy graders, attested) over Verel and asserts `pass` — Verel gates Verel.
- Tests modernized (`pytest.raises` over `assert False`); `PublicRegistry.list()` → `all()`
  (consistency with `MemoryView.all()`, removes builtin shadowing). Dev status → Alpha.

## 0.3.0 — refinements: real mem0, container sandbox, semantic reuse, enriched medic

- **Real mem0 backend** (`memory/mem0_backend.py`): updated to the mem0 **2.x** API
  (`filters=` on get_all/search, `update(id, data, metadata=)`); `make_ollama_mem0()` now
  configures a local Chroma store; recall uses mem0's **semantic** ordering (no longer
  discarded by a lexical re-rank). Live smoke verified (write → promote → semantic recall)
  against real mem0 + OpenAI vectors. `mem0` extra → `mem0ai>=2.0, chromadb`.
- **Container tool runner** (`toolsmith/container.py`): `bwrap` namespace sandbox — no
  network, read-only system-only fs, ephemeral tmp, cleared env, + rlimits. `ToolSmith(
  isolation="container"|"best")`. Verified live: network blocked, /home unreadable.
- **Embeddings-backed tool reuse**: `ToolRegistry.find` ranks by cosine when the memory has
  an embedder, so a tool is reused by MEANING ("make a web-friendly identifier" → slugify).
- **LLM-enriched ci-medic**: `enrich_diagnoses()` adds a root-cause hint to FIX_BRANCH
  diagnoses only; the deterministic classification (retry-vs-fix) is never changed by the LLM.
  Wired into `self_heal(enrich_chat=...)` → hints flow to the code-fixer.
- 135 tests (+1 gated live mem0 smoke).

## 0.2.1 — post-merge canary + verdict-driven rollback (CI/CD table complete)

- **Post-merge canary stage** (`ci/postmerge_stage`) and **`canary_rollback()`**: run the
  smoke/E2E canary on merged code; on a PRECISE-evidence failure, auto-revert.
- **`RollbackExecutor`**: agent proposes → `RollbackPolicy` authorizes (precise gating
  evidence only) → a safe, non-destructive `git revert` (never a history rewrite). An
  advisory-only (vision/LLM) failure can never trigger a destructive revert.
- Completes §7.4's stage table: inner-loop → pre-commit → pre-merge → post-merge/canary.
- 130 tests; demo_canary_rollback.py (live, real git, no key): bad merge auto-reverted,
  advisory-only refused.

## 0.2.0 — public Skill Registry + the H2 corpus-transfer experiment (the moat gate)

- **Public Skill Registry** (`verel.registry`): content-addressed, signed, provenance-tagged
  `SkillArtifact`s in a `PublicRegistry`. Export a verified tool, publish it, search/fetch it.
- **Cross-tenant transfer with re-verification** (`registry/transfer.py`): trust does NOT
  travel — an imported skill enters as `candidate` and only becomes `verified` if it passes
  the importing tenant's OWN held-out eval.
- **H2 experiment** (`registry/h2.py`): `measure_transfer()` measures the cross-tenant
  re-verification rate and returns the design's gating decision (≥20% → build the registry;
  <20% → pivot to per-tenant lock-in). Honest: skills a target can't evaluate aren't counted.
- Fixed a tool-smith `detect()` bug: weak lexical capability overlap could reuse the wrong
  tool; reuse now requires a strong match (`min_relevance`).
- 125 tests; demo_h2_moat.py (live): builds skills on Ollama, measures real fungibility.

## 0.1.1 — semantic recall + real tool sandbox

- **Semantic memory recall** (`memory/embed.py`): pluggable `Embedder` (`HashEmbedder` offline,
  `OpenAIEmbedder` semantic); `LocalMemory(embedder=...)` ranks recall by cosine similarity, so
  a query with no shared words still finds the right memory. Vectors persist across reinforcement.
- **Subprocess sandbox for tools** (`toolsmith/sandbox.py`): runs agent-built tool code in an
  isolated interpreter (`python -I -S`) with CPU/memory/file-size rlimits and a wall-clock
  timeout — a genuine process boundary, not just a restricted namespace. `ToolSmith(sandbox=True)`
  evaluates candidates there. Honest about limits (no network/read isolation; that's the §7.7 runner).
- 116 tests; demo_semantic_recall.py.

## 0.1.0 — first end-to-end release

The five design organs all have working, tested slices, gated by Verel's own verdict bus.

### Verdict bus (`verel.verdict`)
- Unified `Report`/`Issue`/`Percept` contract across senses; `gate()` with an explicit
  advisory **ceiling clamp**, **grader-execution attestation** (signed `run_receipt`,
  dead/hollow-gate guards), scrubbed per-grader **fingerprints**, and strict-subset
  **stuck/progress** detection.

### Eyes (`verel.senses`)
- AgentVision **sight adapter** — grader identity keys off `Issue.source`; `CLASSIC_CAPABILITIES`
  imported from source (drift-proof); crash-safe percept log with Verel-owned progressed/stuck.

### Agents (`verel.agents`)
- Provider-agnostic LLM client (**Ollama Cloud** default, `qwen3-coder:480b`; OpenAI fallback).
- Coding agent `FixHook` (fixes UIs) and `fix_code` (patches source for failing graders).

### Brain (`verel.memory`)
- `MemoryView` trust layer with the two orthogonal quantities (epistemic confidence vs
  retrieval strength), interference rule, documented ranking, exact prune rule.
- Zero-dep `LocalMemory` (sqlite) and `Mem0Memory` (rented mem0) behind the same Protocol.
- Failure ledger + **regression guard**, cross-episode consolidation, and the **held-out,
  attested, agent-inaccessible promotion gate** (inferred → verified; leakage canary).

### Fleet (`verel.fleet`)
- Single-writer scheduler over a Task DAG: barriers (all/k_of_n/optional), concurrency,
  retry→quarantine, hard budget lease, WAL resume; every node gated by the bus.
- **LLM-driven manager** (plane validates/clamps/falls back) and **isolated git worktrees**.

### Tool-smith (`verel.toolsmith`)
- detect → scaffold → test → register → reuse; signed, versioned registry as SKILL records;
  sandboxed `load_callable`; read-only/idempotent auto-verified, destructive human-gated.

### Agent-run CI/CD (`verel.ci`)
- Tests/lint/type **graders** on the bus (attested); inner-loop / pre-commit / pre-merge
  stages with failure-memory; **self-healing** loop; deterministic **ci-medic** and
  **rollback policy engine** (destructive never depends on advisory evidence); git pre-commit
  hook + `verel-ci` CLI. Hardened pytest with `-B` (no stale-`.pyc` false verdicts).

### Surfaces
- `verel` CLI (`doctor`/`loop`/`fleet`/`heal`/`ci`), MCP server (`verel-mcp`), `verel-ci`.

### Meta
- 106 tests (offline/CI-safe), 9 runnable demos, dogfooded through Verel's own verdict bus.

## 0.0.1 — name reservation placeholder
