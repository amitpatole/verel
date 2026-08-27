# Python API

The verdict bus, senses, and CI stages are all importable. Example — gate any repo:

```python
from verel.ci import inner_loop_stage, run_stage
result = run_stage(inner_loop_stage(".", with_lint=True))
print(result.verdict)          # pass / warn / fail
```

## The verdict contract

::: verel.verdict.models

## The gate

::: verel.verdict.gate

## Issue fingerprints

Stable, content-addressed identity for an issue — so the same defect dedupes across runs and a fixed
issue can be recognised as gone. `assign` stamps fingerprints onto a report; `issue_signature`
reduces a report to its set of `(kind, fingerprint)` pairs; `canonicalize` normalises a message.

::: verel.verdict.fingerprint

## Senses (the eyes)

::: verel.senses.sight

## CI stages & self-healing

::: verel.ci.pipeline
::: verel.ci.heal

## Verified-Review graders

Test-effectiveness (mutation), spec/intent conformance, business-rule invariants, over-engineering
smell, and the action gateway — all importable, all on the verdict bus.

### Test-effectiveness (mutation)

::: verel.ci.mutation

### Spec / intent conformance

::: verel.ci.spec

### Business-rule / invariant

::: verel.ci.invariants

### Over-engineering smell

::: verel.smell

### Action gateway

::: verel.gateway

## Guard — document-ingress defense

Static hidden-content / prompt-injection scanning of untrusted documents before an LLM reads them
(see [Guard](guard.md)). `grade_docs` returns an attested `Report`; `check_propagation` catches a
known payload replicating into a generated file; `DocumentGuard` is the `Sense`-shaped surface the
`immel` organ re-exports.

::: verel.guard

## IaC / cloud-IAM graders & actuators

The offline IaC/IAM change sensor (Terraform plan + cloud IAM across AWS/GCP/Azure), the native
Kubernetes RBAC sensor, the plan-bound Terraform actuator, and the opt-in effective-access verifier.

### IaC / cloud-IAM sensor

::: verel.ci.iac

### Kubernetes RBAC sensor

::: verel.ci.k8s

### Terraform actuator (act-then-verify)

::: verel.actuators.terraform

### Effective-access verifier

::: verel.actuators.access_verify

### Cloud credential resolution

::: verel.actuators.cloudcreds

## Receipts & attestation

Sign and verify run-receipts; the two-tier (`hmac-sha256` / `ed25519`) signing and the trusted-key
resolution that makes a verdict publicly re-checkable.

::: verel.verdict.attest

::: verel.verdict.keys

### Receipt kind — two-tier model (`ReceiptKind`)

`GateReceipt` carries a `receipt_kind` field (bound into the signature — flipping it invalidates the HMAC):

| Value | Meaning |
|---|---|
| `COMMITTED` (default) | Irreversible actions. Synchronously blocking — nothing advances until the receipt is durably written. Non-revocable. |
| `OPTIMISTIC` | Advisory / read-only / idempotent actions. Signed asynchronously; revocable if a later grader contradicts it. |

```python
from verel.verdict import ReceiptKind
receipt = build_gate_receipt(verdict, reports)
assert receipt.receipt_kind == ReceiptKind.COMMITTED  # default — safe for destructive actions
```

### Crash-atomic receipt store (`ReceiptStore`)

`ReceiptStore` persists receipts to disk with two invariants:

- **WAL before grading (DC-01):** `begin(action_id)` writes a pending entry atomically before any grader runs. A crash between `begin()` and `commit()` leaves the WAL in place; `check_pending()` surfaces the gap.
- **Hash-chain (DC-02):** `commit()` writes via `os.replace()` (atomic rename) and chains each receipt to its predecessor with `prev_hash = SHA-256(prev_receipt)`. `verify_chain()` walks the store and detects any tampered or missing link.

```python
from verel.verdict import ReceiptStore

store = ReceiptStore()          # defaults to QUINE_RECEIPT_STORE or ~/.local/share/quine/receipts
store.begin("action-42")        # WAL written — grading starts
receipt = gate(reports)         # grader executes
h = store.commit(receipt, "action-42")   # atomic write, WAL cleared
ok, reason = store.verify_chain()        # confirm chain is intact
```

::: verel.verdict.store

## Fleet — agents managing agents

Fan a goal out into independent subtasks, run workers in isolated git worktrees under a single-writer
scheduler, fence stale leaders with leases, and commit cross-repo work as an atomic saga.

::: verel.fleet

## Tool-smith — agents build their own tools

Detect → scaffold → test → register a tool, admitted only on a passing held-out eval and then run
sandboxed under a learned capability jail.

::: verel.toolsmith

## Integrations & SDK

One `gate()` callable plus function-calling schemas in OpenAI and Anthropic shape (and a lazy
LangChain adapter) — the universal hook that lets any agent grade its own work before "done".

::: verel.integrations.sdk

### GitHub PR context

Fetch the acceptance text and changed files for a pull request, to feed the spec/intent graders.

::: verel.integrations.github

## Memory

The `MemoryView` Protocol and the lattice recall/graduation that compounds only verified work.

::: verel.memory.view

### Conversational memory — extract → grade → budgeted recall

Extract durable facts from a conversation, let only **graded** facts compound (corroborated or
attested — never a one-off say-so), and recall them token-budgeted and verified-first. See
[Memory backends → Conversational memory](memory-backends.md#conversational-memory).

Memory is **bi-temporal**: each value carries a valid-time interval (`valid_from`/`valid_to` — when it
was true in the world) distinct from its transaction-time (`created_ts` — when it was recorded).
Extraction captures a stated valid-time from content; `remember_conversation` / `write` accept an
explicit interval. Query history without flattening it:

- `recall_as_of(mem, query, as_of=…)` — point-in-time recall: what was believed about a subject **at
  a past instant** (reconstructed from the correction chain, read-only, ledger-aware).
- `members_as_of(mem, predicate=…, as_of=…, value=…)` — the set-valued query recall can't express:
  **every subject that held a predicate (optionally =value) at an instant** ("who was admin then").
- `remember_conversation(…, source_prior=…)` — seed the initial belief prior from the caller's trust
  in the source *type* (an audit log ≫ a chat message); a ranking prior only, never a trust grant.
- `parse_when(value)` — the fail-safe ISO-8601/epoch instant parser (rejects `+inf`/NaN/out-of-range
  bounds) shared by ingest and the `--as-of` surface.

::: verel.memory.extract

::: verel.memory.remember

::: verel.memory.recall

### Operator review — the human-in-the-loop path

List the CANDIDATE queue, approve to VERIFIED on human authority, or reject into a durable
tombstone — with laundering refused fail-closed and terminal-safe rendering. Surfaced as
[`verel memory`](cli.md#review-memory-as-a-human-verel-memory-resolve-the-candidate-queue).

::: verel.memory.review

### Mutation audit — who changed what, when

`AuditedMemory` wraps any backend and appends every trust-layer mutation
(`{actor, action, before, after}`) to a hash-chained, tamper-evident JSONL log.

::: verel.memory.audit

### Backends — local & hosted

The default zero-dependency SQLite store, plus the hosted brain: a `MemoryServer` over HTTP and a
`RemoteMemory` client that implements the **same** `MemoryView` Protocol (see
[Memory backends](memory-backends.md)).

::: verel.memory.local

::: verel.memory.hosted

### Failure ledger & regression report

Records gating failures so the fleet stops repeating mistakes; `regression_report` rolls the open
failures into a single verdict.

::: verel.memory.failure_ledger
