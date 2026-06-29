# Configuration

Verel is configured by environment variables — there is no config file.

## Environment variable reference

Every variable Verel reads, on one line each, grouped by area. Each name links down to the section
that explains it in full. Nothing here is required for the zero-config local path; the defaults run
out of the box.

**LLM & embeddings** — see [LLM keys](#llm-keys) · [Embeddings](#embeddings-semantic-recall)

| Variable | Controls | Default |
|---|---|---|
| [`VEREL_LLM_PROVIDER`](#llm-keys) | Agent LLM provider — `ollama` or `openai`. | `ollama` |
| [`VEREL_CODER_MODEL`](#llm-keys) | Override the code-fixer model. | provider default |
| [`OLLAMA_API_KEY`](#llm-keys) | Ollama Cloud key (env alternative to `~/.config/ollama/key`). | — |
| [`OPENAI_API_KEY`](#llm-keys) | OpenAI key — provider and `openai` embedder (env alt to `~/.config/OpenAI/key`). | — |
| [`VEREL_EMBEDDER`](#embeddings-semantic-recall) | Recall relevance signal — `none`/`lexical`, `hash`, or `openai`. | `lexical` |
| [`VEREL_EMBED_MODEL`](#embeddings-semantic-recall) | OpenAI embedding model id. | `text-embedding-3-small` |
| [`VEREL_EMBED_DIM`](#embeddings-semantic-recall) | Override the embedding vector dimension. | model-derived |

**Memory / brain** — see [Memory backend](#memory-backend)

| Variable | Controls | Default |
|---|---|---|
| [`VEREL_MEMORY_BACKEND`](#memory-backend) | Backend — `local`, `remote`, `postgres`, `lancedb`, `redis`, or any registered name. | `local` |
| [`VEREL_MEMORY_STORE`](#memory-backend) | SQLite path for the `local` backend. | `~/.config/verel/brain.db` |
| [`VEREL_BRAIN_URL`](#memory-backend) | `remote` backend: URL of a `MemoryServer`. | — |
| [`VEREL_BRAIN_TOKEN`](#memory-backend) | Bearer token for the remote brain. | — |
| [`VEREL_CLUSTER_TOKEN`](#memory-backend) | Replication-channel credential for the remote brain. | — |
| [`VEREL_BRAIN_CACERT`](#memory-backend) | CA bundle that signed the remote brain's TLS cert. | — |
| [`VEREL_BRAIN_CLIENT_CERT`](#memory-backend) / [`VEREL_BRAIN_CLIENT_KEY`](#memory-backend) | Client cert/key for mTLS to the remote brain. | — |
| [`VEREL_BRAIN_PIN`](#memory-backend) | Pin the remote brain's cert SHA-256 (comma-separated set). | — |
| [`VEREL_BRAIN_INSECURE`](#memory-backend) | Let a token ride a cleartext hop (behind a TLS proxy only). | `0` |
| [`VEREL_PRINCIPAL_SEED`](#memory-backend) | 64-hex identity that authors signed beliefs on a remote brain. | — |
| [`VEREL_POSTGRES_URL`](#postgres-pgvector-postgres) / [`VEREL_POSTGRES_DSN`](#postgres-pgvector-postgres) | Postgres connection string (URL or keyword DSN). | — |
| [`VEREL_PG_SSLMODE`](#postgres-pgvector-postgres) | Postgres TLS mode (`verify-full`/`verify-ca` for routable hosts). | from DSN |
| [`VEREL_PG_CACERT`](#postgres-pgvector-postgres) | CA bundle for the Postgres server cert (`sslrootcert`). | — |
| [`PGSSLMODE`](#postgres-pgvector-postgres) | libpq's own TLS mode — read only when `VEREL_PG_SSLMODE` and the DSN omit one. | — |
| [`VEREL_LANCEDB_PATH`](#lancedb-lancedb) | LanceDB dataset directory. | `~/.config/verel/lance` |
| [`VEREL_LANCEDB_TABLE`](#lancedb-lancedb) | Table name within the LanceDB dataset. | `memory` |
| [`VEREL_REDIS_URL`](#redis-redis) | Redis connection URL (`rediss://` + AUTH for routable hosts). | — |
| [`VEREL_REDIS_PREFIX`](#redis-redis) | Redis key namespace. | `verel` |
| [`VEREL_REDIS_CACERT`](#redis-redis) | CA bundle for the Redis server's TLS cert. | — |

**Gate server (`verel serve`)** — see [Gate server](#gate-server-verel-serve)

| Variable | Controls | Default |
|---|---|---|
| [`VEREL_GATE_TOKEN`](#gate-server-verel-serve) | Bearer token for `POST /gate` — required for a routable bind. | — |
| [`VEREL_GATE_WEBHOOK_SECRET`](#gate-server-verel-serve) | HMAC secret verifying GitHub's `X-Hub-Signature-256`. | — |
| [`VEREL_GATE_INSECURE`](#gate-server-verel-serve) | Waive in-process TLS for a routable bind (behind a TLS ingress only). | `0` |
| [`VEREL_GITHUB_TOKEN`](#gate-server-verel-serve) | Read a PR's diff + linked-issue criteria, post commit status. | — |

**Operator (Kubernetes)** — see [Operator](#operator-kubernetes)

| Variable | Controls | Default |
|---|---|---|
| [`VEREL_GATERUN_IMAGE`](#operator-kubernetes) | Gate image the operator runs for every GateRun. | `ghcr.io/amitpatole/verel:<release>` |
| [`VEREL_GATERUN_GIT_IMAGE`](#operator-kubernetes) | Clone-initContainer image (pinned Chainguard git by digest). | pinned `cgr.dev/chainguard/git@sha256:…` |

**Attestation, signing & secrets** — see [Receipts](#receipts-signing-trusted-keys) · [Secrets & key files](#secrets-key-files)

| Variable | Controls | Default |
|---|---|---|
| [`VEREL_RUNNER_SECRET`](#receipts-signing-trusted-keys) | Shared HMAC secret for run-receipts within one trust domain. | persisted per-install key |
| [`VEREL_RUNNER_ED25519_SEED`](#receipts-signing-trusted-keys) | 64-hex ed25519 seed for publicly-verifiable receipts. | persisted per-install key |
| [`VEREL_TRUSTED_KEYS`](#receipts-signing-trusted-keys) | Directory of trusted `<key_id>.pub` files `verel verify` accepts. | `~/.config/verel/trusted_keys` |
| [`VEREL_REGISTRY_SECRET`](#secrets-key-files) | Signing secret for skill-registry artifacts. | persisted per-install key |
| [`VEREL_TOOL_SECRET`](#secrets-key-files) | Signs tool-smith skill-registry artifacts (own trust domain). | persisted per-install key |
| [`XDG_CONFIG_HOME`](#secrets-key-files) | Relocates the whole config dir (keys, brain.db, lance). | `~/.config` |

## Memory backend

The shared **brain** (verified memory) is pluggable. Pick a backend by name; each reads its own
connection env. Built-in names are `local` (default), `remote`, `postgres`, `lancedb`, and `redis`;
third-party packages can register more under the `verel.memory_backends` entry-point and select them
the same way.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | `local` | Backend to use — `local`, `remote`, `postgres`, `lancedb`, `redis`, or any registered name. If unset but `VEREL_BRAIN_URL` is set, defaults to `remote` (back-compat). |
| `VEREL_MEMORY_STORE` | `~/.config/verel/brain.db` | SQLite path for the `local` backend (`:memory:` for ephemeral). |
| `VEREL_EMBEDDER` | `lexical` | Recall relevance signal — `none`/`lexical` (FTS5 BM25 term-weighted search, zero-config), `hash` (offline vectors), or `openai` (semantic; needs an OpenAI key). Shared by every backend. |
| `VEREL_BRAIN_URL` | — | `remote` backend: URL of a `MemoryServer` to share one brain across machines. |
| `VEREL_BRAIN_TOKEN` | — | Bearer token for the remote brain. |
| `VEREL_CLUSTER_TOKEN` | — | Replication-channel credential for the remote brain. |
| `VEREL_BRAIN_CACERT` | — | CA bundle that signed the remote brain's TLS cert. |
| `VEREL_BRAIN_CLIENT_CERT` / `VEREL_BRAIN_CLIENT_KEY` | — | Client cert/key for mTLS to the remote brain. |
| `VEREL_BRAIN_PIN` | — | Pin the remote brain's cert SHA-256 (comma-separated for a set). |
| `VEREL_BRAIN_INSECURE` | `0` | Explicit opt-out letting a token ride a cleartext hop (only behind a TLS-terminating proxy). |
| `VEREL_PRINCIPAL_SEED` | — | 64 hex chars: the identity that authors *signed* beliefs on a remote brain. |

`verel doctor` prints the selected backend and the available ones.

### Postgres / pgvector (`postgres`)

An **external, multi-machine** brain: many agents write directly to one Postgres, and the trust
layer (corroborate / supersede / decay) stays correct under concurrent writers (every mutation is
serialized per `(subject,predicate,scope)` key by a Postgres advisory lock). With an embedder set,
recall uses pgvector approximate-nearest-neighbour; without one it falls back to lexical overlap.

**Requires Postgres 16+** (the set-based librarian/decay pass uses the `IS JSON` predicate for a
total, abort-proof read of lifecycle flags) with the **pgvector** extension. The recommended image is
`pgvector/pgvector:pg16`.

```bash
pip install "verel[postgres]"
# enable the pgvector extension once: CREATE EXTENSION IF NOT EXISTS vector;
export VEREL_MEMORY_BACKEND=postgres
export VEREL_POSTGRES_URL="postgresql://user:pw@db.internal:5432/verel?sslmode=verify-full"
export VEREL_PG_CACERT=/etc/ssl/certs/db-ca.pem   # CA that signed the server cert
export VEREL_EMBEDDER=hash                          # optional: ANN recall (offline vectors)
```

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_POSTGRES_URL` / `VEREL_POSTGRES_DSN` | — | Connection string (URL or keyword DSN). Required for `postgres`. |
| `VEREL_PG_SSLMODE` | from DSN | TLS mode. A **routable host is refused** unless this is `verify-full` or `verify-ca` (fail closed); loopback is exempt. |
| `VEREL_PG_CACERT` | — | CA bundle that signed the server cert (`sslrootcert`), required for `verify-full`. |

!!! note "`PGSSLMODE` fallback"
    When neither `VEREL_PG_SSLMODE` nor an explicit `sslmode=` in the DSN is set, Verel falls back to
    libpq's own **`PGSSLMODE`** environment variable to determine the effective TLS mode. The same
    fail-closed rule applies to whatever value wins: a routable host is refused unless the effective
    mode is `verify-full` or `verify-ca`. (The live connection is also re-checked against the mode
    libpq actually used, so a `service` file or other `PG*` env can't quietly downgrade it.)

The credential is **never logged or echoed in an error**, all queries are parameterized, and a
statement timeout bounds each query. For *embedded* single-process use, `local` (SQLite) remains the
zero-dependency default; use `postgres` when several machines share one verified brain.

### LanceDB (`lancedb`)

An **embedded** vector store — a directory on disk, no server — so it's the zero-infrastructure way to
get real ANN recall (a vector-native upgrade over the SQLite default). With an embedder, recall is
approximate-nearest-neighbour over a Lance index; without one it falls back to the same lexical recall
as `local`.

```bash
pip install "verel[lancedb]"
export VEREL_MEMORY_BACKEND=lancedb
export VEREL_LANCEDB_PATH=~/.config/verel/lance   # a directory (created if absent)
export VEREL_EMBEDDER=hash                          # optional: ANN recall (offline vectors)
```

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_LANCEDB_PATH` | `~/.config/verel/lance` | Dataset directory (operator-set; path-normalized). |
| `VEREL_LANCEDB_TABLE` | `memory` | Table name within the dataset. |

**Single-writer**, like `local`: one dataset is owned by one process. For a brain shared across
machines/processes, front it with a hosted `MemoryServer` (set `VEREL_BRAIN_URL` on the clients) —
the server serializes every write, so the interference rule stays correct. LanceDB's `.where()` filter
is treated as untrusted SQL: scope/kind are filtered in Python and the only ids that reach a predicate
are escaped.

!!! note "The embedder is fixed per dataset"
    The vector dimension is baked into the dataset when it's first created, so `VEREL_EMBEDDER` (and
    the embedding model) **must stay the same** for a given `VEREL_LANCEDB_PATH`. Reopening a dataset
    with a different embedder (a dim change, or adding/removing one) **fails closed with a clear
    error** — point a fresh `VEREL_LANCEDB_PATH`/`VEREL_LANCEDB_TABLE` at the new configuration.

### Redis (`redis`)

A **networked, shared** brain on plain Redis — many agents/machines write to one Redis and the trust
layer stays correct under concurrent writers (each mutation is atomic via `WATCH`/`MULTI` optimistic
concurrency with retry). Recall scans the index and ranks in Python (cosine with an embedder, lexical
otherwise). Works on any Redis (no modules required).

```bash
pip install "verel[redis]"
export VEREL_MEMORY_BACKEND=redis
export VEREL_REDIS_URL="rediss://default:PASSWORD@redis.internal:6379/0"   # rediss:// + AUTH for routable hosts
export VEREL_REDIS_CACERT=/etc/ssl/certs/redis-ca.pem                       # CA that signed the server cert
```

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_REDIS_URL` | — | Connection URL. Required for `redis`. A **routable host must be `rediss://` (validated TLS) with a password** (fail closed); loopback is exempt. |
| `VEREL_REDIS_PREFIX` | `verel` | Key namespace (`{prefix}:mem:*` + `{prefix}:ids`) — lets several brains share one Redis. |
| `VEREL_REDIS_CACERT` | — | CA bundle that signed the server's TLS cert (for `rediss://`). |

The URL/password is **never logged or echoed in an error**, and Redis's RESP protocol is
injection-safe by design. For *embedded* single-process use prefer `local`/`lancedb`; use `redis` (or
`postgres`) when several machines share one verified brain.

## LLM keys

Each provider resolves its key from its **environment variable first, then a `~/.config` key file** —
so either form works, the env var wins.

- **Ollama Cloud** (default): `OLLAMA_API_KEY` or key file `~/.config/ollama/key`; model
  `qwen3-coder:480b`.
- **OpenAI**: set `VEREL_LLM_PROVIDER=openai` and `OPENAI_API_KEY` (or `~/.config/OpenAI/key`).

The **eyes** (AgentVision) read their own provider keys — see the
[AgentVision configuration](https://amitpatole.github.io/agent-vision/configuration/).

!!! warning "Production secrets"
    `VEREL_REGISTRY_SECRET` and `VEREL_RUNNER_SECRET` sign skill-registry artifacts and grader
    run-receipts. There is **no public default secret** — unset, each falls back to a per-installation
    random key (see [Secrets & key files](#secrets-key-files)). That keeps single-machine sign→verify
    working, but **set explicit values in any shared or production environment** so several machines
    share one trust domain.

## Embeddings (semantic recall)

`VEREL_EMBEDDER` picks the recall relevance signal, shared by **every** memory backend:
`none`/`lexical` (FTS5 BM25 search, zero-config, the default), `hash` (offline vectors — exercises the
ANN path with no API), or `openai` (real semantic vectors, needs an OpenAI key). With `openai`:

| Variable | Default | Purpose |
|---|---|---|
| `VEREL_EMBED_MODEL` | `text-embedding-3-small` | OpenAI embedding model id. |
| `VEREL_EMBED_DIM` | model-derived | Override the vector dimension for an unknown model / truncated dimensions. Set this if the LanceDB backend can't derive the dim from the model (the dim is baked into a Lance dataset at creation). |

The `openai` key resolves from `OPENAI_API_KEY` or `~/.config/OpenAI/key`. (Ollama Cloud serves no
embeddings endpoint, so `lexical` is the zero-key option and `openai` the semantic one.)

## Gate server (`verel serve`)

| Variable | Default | Purpose |
|---|---|---|
| `VEREL_GATE_TOKEN` | — | Bearer token for `POST /gate`. **Required** for any routable (non-loopback) bind. |
| `VEREL_GATE_WEBHOOK_SECRET` | — | HMAC secret verifying GitHub's `X-Hub-Signature-256` on `POST /github`. |
| `VEREL_GATE_INSECURE` | `0` | `=1`/`true`/`yes`/`on` waives in-process TLS for a routable bind — **behind a TLS-terminating ingress/proxy only**. Auth is still required. |

A routable `verel serve` bind **fails closed** unless it has BOTH a token and TLS (`--certfile`/
`--keyfile`); loopback is zero-config.

`VEREL_GATE_INSECURE` is the gate-server mirror of [`VEREL_BRAIN_INSECURE`](#memory-backend): it lets
the bearer token ride a cleartext (non-TLS) hop **only** when something else terminates TLS in front
of the pod. The token is still mandatory — this waives the in-process cert requirement, not auth. The
[operator](#operator-kubernetes) injects it on the behind-ingress path; never set it on a bind that is
directly reachable without a TLS proxy.

## Operator (Kubernetes)

The Verel [Kubernetes operator](kubernetes.md) runs every managed workload from an
**operator-controlled** image — never one named in a custom-resource spec (this closes the
confused-deputy: a CR author can't make the operator pull an attacker image). Two env vars on the
**operator Deployment** select those images.

| Variable | Default | Purpose |
|---|---|---|
| `VEREL_GATERUN_IMAGE` | `ghcr.io/amitpatole/verel:<release>` | The gate image the operator runs for every `GateRun`. The default tracks this package's `__version__` (the image is built per release), so it auto-follows the operator version. |
| `VEREL_GATERUN_GIT_IMAGE` | pinned `cgr.dev/chainguard/git@sha256:…` | The clone `initContainer` image — a Chainguard `git`, pinned **by digest** (immutable, minimal-CVE). |

!!! warning "Set `VEREL_GATERUN_GIT_IMAGE` for long-lived clusters"
    The default clone image is pinned to a digest on the **free `cgr.dev` tier, which can garbage-collect
    an old digest within weeks of a rebuild**. When that happens the clone `initContainer` fails with
    `ImagePullBackOff` and **every `GateRun` stops**. For any cluster expected to outlive a few weeks,
    mirror the git image into a registry you control and point `VEREL_GATERUN_GIT_IMAGE` at your own
    (renovate-bumped) digest pin. `VEREL_GATERUN_IMAGE` is similarly overridable if you mirror the gate
    image.

## Receipts, signing & trusted keys

A gate can emit a **run-receipt** (a signed attestation that a grader really ran); `verel verify`
checks it (see the [CLI reference](cli.md)).

| Variable | Default | Purpose |
|---|---|---|
| `VEREL_RUNNER_SECRET` | persisted per-install key | shared HMAC signing secret for receipts within one trust domain. |
| `VEREL_RUNNER_ED25519_SEED` | persisted per-install key | 64-hex ed25519 seed for **publicly-verifiable** receipts (a stranger verifies with only the public key). |
| `VEREL_TRUSTED_KEYS` | `~/.config/verel/trusted_keys` | directory of trusted `<key_id>.pub` files `verel verify` accepts for ed25519 receipts. |
| `VEREL_TOOL_SECRET` | persisted per-install key | signs tool-smith skill-registry artifacts. |

## Secrets & key files

Everything Verel persists lives under one config directory — `$XDG_CONFIG_HOME/verel` if
`XDG_CONFIG_HOME` is set, otherwise `~/.config/verel`. Setting **`XDG_CONFIG_HOME`** relocates the
whole tree (signing keys, `brain.db`, the LanceDB dataset) in one move.

**Provider key files** — the LLM clients read each provider's env var first, then a key file:

| Path | Used by |
|---|---|
| `~/.config/ollama/key` | Ollama Cloud (env alternative: `OLLAMA_API_KEY`). |
| `~/.config/OpenAI/key` | OpenAI provider **and** the `openai` embedder (env alternative: `OPENAI_API_KEY`). |

**Cloud read-credentials** — only for the opt-in [`verel verify-access`](cli.md) effective-access check;
**never used by the offline gate, never logged**. Resolved from `~/.config` per the house rule:

| Path | Cloud | Notes |
|---|---|---|
| `~/.config/AWS/rootkey.csv` | AWS | columns `Access key ID`,`Secret access key`; `chmod 600` (group/world-readable is warned; a symlink or foreign-owned file is refused). |
| `~/.config/gcp/<sa>.json` | GCP | service-account key; `~/.config/gcloud` is exported as `CLOUDSDK_CONFIG` if present. |
| `~/.azure/` | Azure | `az` CLI config dir (exported as `AZURE_CONFIG_DIR`); requires real token material, not just the directory. |

`verel verify-access` fails closed (exit 2) when the selected cloud's creds are absent.

**Per-installation signing keys** — every HMAC/ed25519 secret resolves as **env var > persisted
per-install key file > ephemeral**. When the env var is unset, Verel reads (or atomically creates) a
random key at `~/.config/verel/<name>.key`, mode `0600`, owner-only (a foreign-owned or
group/other-readable file is **refused**, falling back to an ephemeral key that fails *closed*). This
makes single-machine sign→verify zero-config and secret — no public default exists.

| Key file | Env override | Signs |
|---|---|---|
| `runner_secret.key` | `VEREL_RUNNER_SECRET` | grader run-receipts (shared-secret HMAC). |
| `ed25519_seed.key` | `VEREL_RUNNER_ED25519_SEED` | publicly-verifiable run-receipts (ed25519). |
| `registry_secret.key` | `VEREL_REGISTRY_SECRET` | skill-registry artifacts. |
| `tool_secret.key` | `VEREL_TOOL_SECRET` | tool-smith skill-registry artifacts (separate trust domain). |

!!! warning "Share a trust domain → set the env var explicitly"
    The per-install key file is **machine-local**. For several machines (or a CI fleet) to verify each
    other's receipts/artifacts, you **must** set the matching `VEREL_*_SECRET` /
    `VEREL_RUNNER_ED25519_SEED` to the same value on every machine. Relying on the auto-generated files
    gives each machine a *different* key, so cross-machine verification fails closed.

**Trusted public keys** — `verel verify` accepts ed25519 receipts whose `<key_id>.pub` lives in
`~/.config/verel/trusted_keys/` (override the directory with `VEREL_TRUSTED_KEYS`).

**Data stores** — the `local` brain is `~/.config/verel/brain.db` (`VEREL_MEMORY_STORE`) and the
LanceDB dataset defaults to `~/.config/verel/lance` (`VEREL_LANCEDB_PATH`); both move with
`XDG_CONFIG_HOME`.

## Verified-Review grader knobs

The Verified-Review graders (mutation, spec/intent, invariants, smell, gateway) take their knobs as
function arguments / MCP tool fields rather than env vars. The defaults below are the code defaults.

| Grader | Knob | Default | Meaning |
|---|---|---|---|
| mutation | `cap` / `cap_per_file` | `25` | max mutants generated per target file |
| mutation | `timeout` | `120` (CLI / `mutation_spec`) | per-suite-run wall-clock seconds |
| mutation | `total_budget_s` | `240.0` | whole-run budget; stays under the 300s outer grader timeout so files are always restored |
| spec | `checks_per_criterion` (MCP) / `n` (API) | `2` | independent generated checks majority-voted per criterion |
| spec / invariants | `timeout` | `30` | per generated-check wall-clock seconds |
| spec / invariants | `isolation` | `"container"` | `"container"` = bwrap no-net + seccomp + rlimits, **fails closed** if bwrap is absent. `"subprocess"` is a documented opt-out for a **trusted-local** repo only — never for external-contributor PR text. |
| smell | `complexity_budget` | `12` | cyclomatic-complexity ceiling; a function over it gates |
| smell | `flag_speculative` | `True` | flag a public def/class referenced nowhere (advisory) |
| gateway | `Policy.dry_run` | `True` | irreversible actions are planned, never applied without `approve` |

The only related environment variable is **`VEREL_GITHUB_TOKEN`** (above), which the spec grader's
`grade_pr` path and the REST webhook use to read a PR's diff + linked-issue criteria.

### Declaring invariants — `verel_invariants.{yaml,yml,txt}`

The invariant grader reads human-declared business rules from a `verel_invariants.yaml`,
`verel_invariants.yml`, or `verel_invariants.txt` at the repo root — **one rule per line**, blank
lines and `#` comments ignored, an optional leading `id:` prefix:

```text
# verel_invariants.txt — one business rule per line
tax: an order total always includes tax
refund: a refund never exceeds the original charge
shipping cost is never negative
```

The parser is plain text (no `yaml.load`, fixed filenames) — there is no new deserialization surface.
Each rule is compiled by the LLM into independent property checks, run under the same OS-isolation as
the spec grader, and a falsified rule gates.
