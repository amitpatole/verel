# Enterprise — identity, tenants, audit, telemetry and supply chain

What a security review of Verel's pilot service will ask for, and what exists today. Where something
does **not** exist yet, this page says so.

## Identity and roles

`verel serve-pilot` runs the pilot workflow over HTTP. Authentication is **always on**, even on loopback.
A routable bind additionally requires TLS (the same transport layer as the other services).

| Role | Can do |
|---|---|
| `viewer` | read evaluations, verify logs |
| `operator` | + record decisions (shadow or advisory), add labels |
| `admin` | + request `enforce`, archive logs, (phase 5) promote graders |

The role-to-permission table is fixed in code. Nothing in a config file or a token claim can create a
permission that the code does not define.

**Bearer tokens.** `verel auth add --file tokens.json --id alice --role operator --tenant acme` prints a
random 256-bit token once. Only its SHA-256 is stored. Comparison is constant-time across all entries.
Tokens can expire. `verel auth revoke` takes effect on the next request. A corrupt or group-writable token
file denies everyone (fail closed).

**SSO (OIDC).** `pip install "verel[sso]"`, then pass `--oidc-issuer/--oidc-audience` and a JWKS file or
https URL. Verel verifies signed JWTs with an asymmetric-only algorithm allowlist (`none` and HS* are never
accepted), requires `exp`, `iss`, `aud` and `sub`, and takes the role and tenant from claims
(`verel_role`, `verel_tenant`). A missing or unknown role or tenant **denies**; it never defaults. Group
mapping and refresh-token flows are out of scope: put your IdP in front and mint short-lived access tokens.

## Tenant isolation

The tenant comes **only** from the authenticated principal. No request field, header or path can name
another tenant. Each tenant's decision log, labels and archives live under `<data>/tenants/<id>/`, and tenant
ids are validated to a strict charset. This is logical isolation inside one process and one filesystem. If
you need isolation against a compromised process or host, run one service per tenant.

## Audit trail

Every **mutation and every denial** by an authenticated principal is appended to that tenant's keyed, hash-chained
audit log: who, tenant, action, outcome. Tokens and claims are never written. Reads are not audited, and
unauthenticated attempts are only counted in memory, so neither a read-only token nor anonymous traffic can fill the
log or slow other tenants. If an action cannot be audited it is refused. Any of the pilot, label or audit logs can be
archived (`POST /v1/pilot/archive` with `"log"`), which is what frees a full one. `verel auth verify-audit --log audit.jsonl`.

## Evidence integrity and retention

Decision logs, label ledgers and audit logs share one implementation: each record carries an HMAC under a
per-installation secret (`VEREL_LOG_KEY`, else a persisted key file), and a keyed head ledger pins the latest
head and count. Edits, deletions, reordering, forged records, rebuilt chains, truncation and deleting the
log are detected. Not protected: an attacker who holds the key, or who deletes the log **and** its ledger.
Keep an external copy of `head` for that case.

**Retention.** `verel pilot archive --log pilot.jsonl --keep-last N` moves older decisions into a verifiable
archive segment and re-anchors the live log. That is an *authorized deletion*: delete a segment when your
retention period ends and the live log still verifies. `verel pilot verify --segment` checks a segment.

## Telemetry

`pip install "verel[otel]"`. Verel emits one span and one counter per pilot decision through the
OpenTelemetry API. It never configures an exporter or endpoint: until **your** application installs an SDK,
the API is a no-op and nothing leaves the process. Artifact ids are exported as a short hash unless you opt in.

## Supply chain

- A CycloneDX **SBOM** of the resolved install is generated per release (`tools/release_sbom.sh`).
- The `release-assets` workflow attaches a Sigstore-signed **build-provenance attestation** for the wheel,
  sdist and SBOM. Verify with `gh attestation verify <file> --repo amitpatole/verel`. This workflow runs on
  version tags; it has not yet run on a published tag, so treat verification as available from the first
  tag that executes it.
- PyPI uploads currently use an API token, not Trusted Publishing, so PyPI itself does not yet show a
  publish attestation for Verel.
- Dependencies are tracked by Renovate; CodeQL runs weekly.

## Data flow and residency

Verel is self-hosted. The base install makes **no outbound network calls**. Pilot data stays on the host you
choose. The only features that reach the network are ones you turn on and point somewhere: an LLM backend, an
OIDC JWKS URL (https, SSRF-guarded), and OpenTelemetry export. Choose the region by choosing where to run it.

## Control mapping (supports, not certified)

Verel is **not** SOC 2, ISO 27001 or similar certified. This table shows which controls the product helps you
evidence. Your auditor decides what satisfies them.

| Control area | What Verel provides | What you still own |
|---|---|---|
| Logical access (SOC 2 CC6) | roles, hashed tokens, SSO, tenant scoping, revocation | IdP policy, MFA, joiner/mover/leaver process |
| Monitoring (CC7) | tamper-evident decision and audit logs, OpenTelemetry | alerting, retention policy, log shipping |
| Change management (CC8) | gated releases, signed receipts, SBOM, build attestation | approvals, deploy process |
| Availability (A1) | health endpoint, bounded concurrency | HA, backups, capacity |
| Confidentiality (C1) | TLS on routable binds, no default secrets, no egress by default | disk encryption, key management |

## Reading evidence

`verify` and `eval` take a short shared lock only to copy the log and its ledger, then verify the copy, so a slow verification of a big
log never blocks a writer. If the directory is read-only (an auditor, a WORM copy), they read without a lock and look twice before
calling a mismatch corruption. The ledger keeps at most 200 archive entries (older ones are folded into one), so it cannot outgrow
its read limit however often you archive. The archived-id index is keyed per line and counted against the archived total: forged
lines are ignored, a deleted or truncated index is reported.

## Resource limits

Denials are audited with a per-principal budget (20 a minute, and a separate 200 a minute for privileged actions such as archive
and promote, so cheap noise cannot hide an attempt on a sensitive route). Per tenant: at most 8 concurrent write requests (the rest get 429), 500 labels per request, 5,000 pending jobs. Waiting for a
log's lock is bounded (10 s, then 503 with `Retry-After`). A write that fails midway (a full disk) is rolled back, a multi-record write announces itself in the keyed ledger first (so a crash is recovered, and a
half-persisted batch after a power loss is fixed explicitly with `verel pilot repair`, never silently; add `--kind labels|policy|audit` for the tenant's other logs), and a
torn final line is dropped on the next write, so a log is never left unusable.

## Known gaps

- No built-in rate limiting of failed authentications beyond connection caps. Tokens are 256-bit, so guessing
  is infeasible, but put a WAF or gateway in front for abuse control.
- A single process serves all tenants of one service.
- No SCIM provisioning and no UI for token management (CLI only).
- Log verification is O(n) per append, which is fine for pilot volumes and not for millions of records.
