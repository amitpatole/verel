# Trust model

What Verel actually guarantees, how, and — just as important — what it does **not**. The verdict bus is a
*security* boundary (it decides what counts as "done"), so this page states only what's implemented and
names the residual risk plainly.

## The unit of trust: a signed receipt

Every grader run produces an `agentsensory.Report` carrying a **`RunReceipt`** that is cryptographically
signed. The receipt binds:

- **`inputs_digest`** — a hash of the exact artifact / diff the grader saw,
- **`coverage_assertion`** — proof the grader actually looked at the changed files (it must intersect the
  diff),
- **`result_digest`** — a hash of the graded *outcome* (verdict + issues),

into one signing payload (canonical, length-prefixed to prevent delimiter injection). Tamper with the
report — strip an issue, swap the verdict, point it at a different diff — and the signature no longer
verifies.

**Algorithms.** The default is **HMAC-SHA256** (a shared secret within one trust domain). Install
[`verel[attest]`](install-extras.md) for **ed25519** publicly-verifiable receipts a *second party* checks
with only your public key. Verification is always **constant-time** (`hmac.compare_digest`), and the
algorithm is bound into the signed payload so a signature can't be downgraded. An ed25519 verification
with PyNaCl absent **fails closed** — it returns `false`, never a silent pass.

**Keys are never a hardcoded default.** The HMAC secret resolves from `VEREL_RUNNER_SECRET`, else a
persisted per-installation random key under `~/.config/verel/`, else an ephemeral per-process key (which
makes cross-process verification fail closed rather than trust a guessable default). The key file is
created atomically at mode `0600` with symlink-race and foreign-owner protection; a world/group-readable
or foreign-owned key is rejected. ed25519 seeds resolve the same way, and public keys are **pinned, never
trust-on-first-use** — a valid signature is necessary but not sufficient; the verifier must already trust
the key (its own runner's key, zero-config, or one you place under `~/.config/verel/trusted_keys/`).

## No hollow pass

A verdict is not trusted just because it says `pass`:

- a **required grader that didn't run** → the gate fails,
- a grader result **with no signed receipt** → the gate fails (you can't claim success with no evidence
  the check ran),

so `verdict=pass, issues=[]` with no receipt behind it is a **fail**, not a pass. This "dead-gate /
hollow-gate" rejection is what makes the whole contract meaningful.

## Precise vs advisory: what can gate

| Class | Graders | Effect |
|---|---|---|
| **Precise** (deterministic evidence) | tests · types · lint · mutation · security · smell · IaC · IAM · policy · cost · **KPI · telecom-config** · DOM/OCR/CV · DSP/ASR | Can `fail` the build. |
| **Advisory** (open-ended judgment) | vision · LLM-as-judge · acoustic · audio-LLM | Clamped to `warn` — informs, never blocks. |

A **low-confidence** issue from any grader is also clamped to `warn`, so statistical insufficiency or a
hedged model call can never fail a build on its own.

## Isolation for untrusted / agent-generated code

Agent-authored or otherwise-untrusted code is run under **defence-in-depth**, not in-process `exec`:

- **Namespaces (bubblewrap `--unshare-all`)** — no network, no host PID/mount/IPC, a read-only view of
  only the system libraries the check needs, and an in-memory ephemeral `/tmp`.
- **Resource limits (`RLIMIT_*`)** — wall-clock CPU, address space (memory), max file size, process
  count. A `[0]*(10**12)` allocation hits `RLIMIT_AS` → `MemoryError` instead of eating the host.
- **Seccomp-bpf syscall filter** (with [`verel[container]`](install-extras.md)) — denies `clone`/`fork`,
  `ptrace`, `mount`, raw sockets, and similar.

**Honest limits.** The namespace + RLIMIT layer is mandatory for the container runner; the seccomp filter
is defence-in-depth on top. If bubblewrap is **absent**, a generated check that needs isolation is **not
run** (it stays unverified → fails closed), rather than silently dropping to an unsandboxed subprocess. If
seccomp is required but unavailable, the runner fails closed. This is real OS isolation for a single host —
it is not a substitute for a VM/microVM boundary against a kernel 0-day.

## Network surfaces authenticate

Any Verel service that can bind a socket (the REST gate, the shared brain, the fleet control plane)
follows one policy:

- **Loopback** (`127.0.0.1` / `::1` / `localhost`) → plain HTTP, no token: zero-config for local use.
- **Routable** (anything else) → requires **both** an `auth_token` **and** TLS, or the **server refuses to
  start**. An empty/whitespace token counts as no token. `insecure=True` is the explicit opt-out only for
  a TLS-terminating proxy that already encrypts the hop.

Bearer tokens and GitHub webhook HMAC signatures are compared in **constant time**, shape-validated before
comparison (so malformed input can't raise or short-circuit), and a client never attaches a secret to a
cleartext hop toward a routable host.

## Honest posture — what is NOT guaranteed

State only what's verified; name the rest.

- **Dependencies, kernel, and OS** are outside Verel's boundary — a compromised dependency or a kernel
  0-day defeats the sandbox.
- **DNS/egress** inside the container namespace and pod-level PID caps in Kubernetes have
  environment-dependent residuals (bounded by the NetworkPolicy and cgroup limits you deploy).
- **The IaC/IAM rule set is a denylist with a long tail** by design — pair it with the external scanners
  (`trivy`/`checkov`) it drives, not instead of them.
- **The telecom actuator** grades and classifies the *declared* config; it applies the operator's
  edit-config and binds the result to the graded intent via post-apply re-grade + confirmed-commit
  rollback — but the device/NETCONF backend behaviour is outside its control.

Verel never claims code is "unexploitable." It claims: every discovered vector is closed and
regression-pinned, isolation and receipts fail closed, and the residual risk is the set above — which no
audit eliminates. Open, unfixed attack-vector details are kept out of the public tree by policy; a fixed,
regression-pinned finding is safe to describe, an open one is not.
