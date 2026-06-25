# Configuration

Verel is configured by a few environment variables — there is no config file.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_LLM_PROVIDER` | `ollama` | LLM provider for agents — `ollama` or `openai`. |
| `VEREL_CODER_MODEL` | provider default | Override the code-fixer model. |
| `OPENAI_API_KEY` | — | Required when `VEREL_LLM_PROVIDER=openai`. |
| `VEREL_REGISTRY_SECRET` | *dev value* | Signing secret for the skill registry — **set a real one in production**. |
| `VEREL_RUNNER_SECRET` | *dev value* | Grader-runner signing identity — **set a real one in production**. |
| `VEREL_GITHUB_TOKEN` | — | Token the REST webhook / spec grader use to read a PR's diff + linked-issue criteria and post commit status. |
| `VEREL_GATE_TOKEN` / `VEREL_GATE_WEBHOOK_SECRET` | — | Bearer token + GitHub webhook HMAC secret for `verel serve` (the REST gate). |

## Memory backend

The shared **brain** (verified memory) is pluggable. Pick a backend by name; each reads its own
connection env. Built-in names are `local` (default), `remote`, `postgres`, `lancedb`, and `redis`;
third-party packages can register more under the `verel.memory_backends` entry-point and select them
the same way.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | `local` | Backend to use — `local`, `remote`, `postgres`, `lancedb`, `redis`, or any registered name. If unset but `VEREL_BRAIN_URL` is set, defaults to `remote` (back-compat). |
| `VEREL_MEMORY_STORE` | `~/.config/verel/brain.db` | SQLite path for the `local` backend (`:memory:` for ephemeral). |
| `VEREL_EMBEDDER` | `lexical` | Recall relevance signal — `none`/`lexical` (token overlap, zero-config), `hash` (offline vectors), or `openai` (semantic; needs an OpenAI key). Shared by every backend. |
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

- **Ollama Cloud** (default): key at `~/.config/ollama/key`, model `qwen3-coder:480b`.
- **OpenAI**: set `VEREL_LLM_PROVIDER=openai` and `OPENAI_API_KEY`.

The **eyes** (AgentVision) read their own provider keys — see the
[AgentVision configuration](https://amitpatole.github.io/agent-vision/configuration/).

!!! warning "Production secrets"
    `VEREL_REGISTRY_SECRET` and `VEREL_RUNNER_SECRET` ship with **development defaults** so the
    examples run out of the box. Set real, secret values in any shared or production
    environment — they sign skill-registry artifacts and grader run-receipts.
