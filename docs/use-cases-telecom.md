# Use cases — Telecom RAN & 5G Core

> The throughline: **catch a dangerous RAN/Core change *before* it reaches the network** — whether a
> human or an agent authored it — gate it on one verdict bus, ground every finding in the exact source
> line, and emit a **signed receipt** of what actually ran. Nothing is "done" until a grader says so.

5G is now **software**: the Core is CNFs on Kubernetes (AMF, SMF, UPF, NSSF…), the RAN is O-RAN with a
RIC and xApps, and both are increasingly configured by GitOps and driven by AI agents. In that world an
agent that self-declares a config change "done" is how you get a `tracking area not allowed`
registration storm or a slice that no UE can reach. Verel gives you a **deterministic, offline,
attestable** gate over the *declared* config and the *reported* KPIs — one that a slice inconsistency, a
null SUCI scheme, an overlapping UE pool, or a TAC that no AMF serves **cannot** slip past.

## Who this is for

| Persona | Owns | The pain |
|---|---|---|
| **5G Core / SA engineering** | AMF/SMF/UPF/NSSF config, slices, DNNs, IP pools | a slice defined in SMF but missing from NSSF; overlapping UE pools; N3/N6 not separated; SUPI sent in clear — caught in review, or in production |
| **RAN / NetOps** | gNB/cell config, PCI plan, neighbors, TACs | PCI collision/confusion between declared neighbors; a gNB broadcasting a TAC no AMF serves; asymmetric Xn relations |
| **Automation / SRE** | the CI/CD for network config, the change gate, the SLOs | agent-authored changes you can't hand-review; a KPI regression after a change; postmortems that need *verifiable* evidence of what ran, not a screenshot |

## What Verel grades for telecom

Three deterministic graders on the one verdict bus (all offline, no network, no LLM — a telecom gate
that can hallucinate is worse than useless):

- **KPI / SLO vitals** ([`KPI`](graders.md)) — grade a metrics snapshot against **operator-declared**
  thresholds (never inferred), naming the exact 3GPP counter + clause. Inputs: a Prometheus/OpenMetrics
  scrape, CSV/JSON, or a **PM-XML (TS 32.435)** EMS export. `verel-ci telecom --kpi`.
- **Declared config invariants** ([`TELECOM_CFG`](graders.md)) — normalize a config artifact into one
  canonical network model and run declared invariants over it: **S-NSSAI consistency, UE-pool overlap,
  N3/N6 separation, redundancy floors, SUCI/null-scheme, SBI-TLS, MTU** (Core) and **PCI
  collision/confusion, neighbor symmetry, EIRP** (RAN), plus the flagship **`tac-plmn-consistency`**
  RAN↔Core cross-check. `verel-ci telecom-cfg --values`.
- **Receipt-visible waivers** — a waived violation becomes a non-gating INFO (never silently dropped);
  an expired waiver gates again + warns; a stale waiver warns. Every waiver is in the signed receipt.

### One machinery, cloud-native *and* classic

The config grader normalizes **both** an Open5GS-shaped **Helm-values** document (cloud-native) **and** a
**NETCONF / TS 28.541 NRM** export (classic/appliance) into the *same* model, so the **identical rule
body** grades both worlds. The flagship `tac-plmn-consistency` proves it: the same finding — a gNB
broadcasting a `(PLMN, TAC)` that no AMF serves → Registration Reject *'tracking area not allowed'*
(5GMM cause #12) — fires on the Helm form and the NETCONF form with the same `rule_id` and the same
`(PLMN, TAC)`; only the source `locator` differs. See `examples/demo_telecom_ran.py`.

## Quickstart (offline, no key, no network)

```bash
pip install "verel[telecom]"        # pyyaml + defusedxml (XXE-safe XML)

# Config invariants over an Open5GS Helm-values artifact (or a NETCONF/NRM XML export)
verel-ci telecom-cfg --repo . --values deploy/values.yaml --rules verel_telecom.yaml

# KPI vitals over a metrics snapshot (auto-detects json/csv/openmetrics/pmxml)
verel-ci telecom --repo . --kpi metrics.json --thresholds verel_kpi.yaml
```

Runnable demos (each prints real captured output — broken → grounded FAIL → fix → PASS):

- `examples/demo_telecom_kpi.py` — a synthetic Open5GS-shaped PM snapshot where AMF registration SR
  collapses → FAIL naming `RM.RegInitSucc / RM.RegInitReq` (TS 28.552 §5.2.1).
- `examples/demo_telecom_cfg.py` — a slice in SMF missing from NSSF → FAIL with a locator into the
  values path (TS 29.531 §5.2).
- `examples/demo_telecom_ran.py` — the RAN↔Core cross-check firing identically on Helm **and** NETCONF.

### Declaring rules and thresholds

`verel_telecom.yaml` enables/parameterizes the built-in invariants and declares waivers:

```yaml
version: 1
rules:
  - id: snssai-consistency
    params: {require_nssf: true}
  - id: redundancy-floor
    severity: error                 # promote from the default warning for a production values file
    params: {floors: {AMF: 2, SMF: 2, UPF: 2}}
  - id: suci-security-posture
    waivers:
      - {id: W-2026-014, match: {nf: amf}, expiry: 2026-09-30, reason: "Lab UEs lack NEA2; NIR-482"}
```

`verel_kpi.yaml` declares KPI gates (a ratio below `min_samples` clamps to a non-gating WARNING —
statistical insufficiency can't fail a build):

```yaml
RM.RegInitSuccRate: {min: 99.0, min_samples: 200}
RRU.PrbTotDl:       {max: 85.0, direction: lower_is_better, min_samples: 200}
MM.HoExeSuccRate:   {max_delta_vs_baseline: 0.5}   # gate a regression vs a supplied baseline window
```

## How it fits your pipeline

Telecom grading rides CI as a **step**, exactly like the [IaC / cloud-IAM track](use-cases-infra.md):
a pre-commit hook, a GitHub Action, or a Kubernetes Job runs `verel-ci telecom-cfg` / `verel-ci telecom`
over the changed artifacts and fails the build on a `FAIL` verdict. The receipt is signed (HMAC by
default; `--attest ed25519` for a receipt a second party verifies with only the public key). The gate is
offline and deterministic, so it runs anywhere — a laptop, a CI runner, or a `GateRun` in-cluster.

## Honest scope — what this does NOT do

Verel grades **declared config and reported KPIs**. It is not a service-assurance system, a protocol
tester, or an RF planner. Read this before you deploy it as a gate:

- **Correlation ≠ causation.** The KPI grader verifies thresholds over the windows you supply; it cannot
  attribute a regression to your change (traffic, weather, neighbor outages are invisible). A FAIL means
  *"X breached its declared threshold in this window,"* never *"your change degraded X."*
- **Config ≠ runtime.** The config grader grades the *declared* artifact. A passing Helm chart or NETCONF
  candidate says nothing about what the CNF actually negotiated at runtime. This is a merge gate, not an
  audit of the live network.
- **Vendor counter dialects.** No vendor emits TS 28.552 names verbatim (Ericsson `pmRrcConnEstabSucc`,
  Huawei numeric ids…). Mapping tables are maintained artifacts; an unmapped counter is kept verbatim
  (a threshold can still target it) and a threshold on an *absent* counter is WARNING "unmeasurable" —
  never a silent PASS.
- **Ratio statistics.** Small denominators, counter resets, and mean-over-cells aggregation produce false
  verdicts; `min_samples` + worst-cell disclosure are mitigations, not cures.
- **PCI / neighbor checks are topological, not RF planning.** Checking declared neighbor relations is not
  interference analysis or drive-test validation.
- **EIRP is operator-declared, not regulatory.** The grader compares against the licensed limit and
  antenna gains *you* declare; it does not know the regulator's database.
- **Standards-version drift.** The NRM/O-RAN modules and PM counters differ across Rel-16/17/18; the
  adapters target a pinned vocabulary (Rel-17) and read vendor-extension attributes where present.
- **Explicit non-goals:** no E2/A1/O1/N2/N4 **message-level** conformance, no vendor **interop** guarantee,
  no **drive-test** perception, no **slice-SLA delivery** verification (S-NSSAI *consistency* ≠ slice
  *performance*), and — for now — no PRACH-root/SSB-raster RF arithmetic (a documented follow-up).
- **Demo data is synthetic** or captured from open-source cores (Open5GS/free5GC), labeled as such in the
  demo output; nothing here implies vendor validation.

## Where it fits the organism

The KPI/vitals half is [`vitel`](https://github.com/amitpatole/verel)'s eventual domain (graded SLOs /
health); it is built inside `verel` behind a clean module boundary so it can lift into `vitel` later. The
config-invariant half is the [`verel` brain](index.md) deciding "done" over a declared change — the same
verdict bus, one more pair of eyes on the network.
