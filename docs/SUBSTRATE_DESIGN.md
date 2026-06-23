# Verel as a verification substrate for agentic tools — design & build plan

> **Status:** proposal / pre-build. Internal design doc (excluded from the public docs site).
> **One line:** expose Verel's verdict bus, eyes, and brain through the protocol every agentic tool
> already speaks (MCP), so **any** agent — in any IDE, CI, or runtime — gains a *conscience*, a pair
> of *eyes*, and a *shared verified memory*. The VS Code extension becomes the friendly on-ramp and
> the human dashboard, not the product.

## 1. The reframe — substrate, not extension

Every agentic coding tool on the market is racing to **generate**. Almost none **verify with grounded
senses**, and none let a *different* party check that the verification was real. That gap is Verel.

> **Verel is the verification organ any agent plugs into.** "Nothing is done until a grader returns a
> verdict" stops being Verel's internal rule and becomes a service every agent can call. We give every
> blind, over-confident agent a **conscience** (the verdict bus) and **eyes** (AgentVision), and we let
> them compound into a **shared verified memory** — across tools, across machines.

The consumers are **agents**, and agents don't look at panels — they call tools over a protocol. So
the **primary surface is the MCP server** (`verel-mcp`, which already exists), and the VS Code
extension demotes to the **installer + dashboard**: it wires the MCP server into whatever tool the
developer uses, and visualizes what those agents gated / saw / remembered.

### Decisions locked (from the whiteboard)
| Question | Decision |
|---|---|
| Lead artifact | **MCP server is primary**; the extension is the on-ramp + dashboard over it. |
| v1 hero verbs | **`gate` + `sight`** (a conscience and eyes — the two things every coding agent lacks). |
| v1 contract | `gate`, `sight`, `recall`/`remember` first; **`heal`, `watch` second**. |
| Attestation | **Headline, first-class property** — the verifiable receipt is the wedge, not an internal detail. |
| DevOps reach | **IDE + CI at launch** (both surfaces mostly exist), **runtime (deploy/incident) as fast-follow**. |

## 2. Layering — core → adapters → consumers

```
                  ┌──────────────── Verel core (Python) ────────────────┐
                  │  verdict bus  ·  eyes (AgentVision)  ·  brain         │
                  │            + attestation / verifiable receipts        │
                  └───────────────────────┬──────────────────────────────┘
        ┌───────────────┬─────────────────┼──────────────────┬────────────────────┐
   MCP server       CLI / Action       LSP diagnostics    HTTP (HA brain)     VS Code ext.
  (verel-mcp)      (verel-ci)          (squiggles)        (RemoteMemory)      (installer+dash)
        │                │                  │                  │                    │
  Cursor · Claude Code · Cline · Windsurf · Zed          CI agents · deploy/incident bots   (human)
  Copilot (where MCP supported)                          ← the DevOps half
```

- **Core (already built):** `verel.verdict.gate()` → `GateResult`; `verel.senses.sight`/`watch`/
  `from_agentvision`; `verel.memory` (scope lattice, `import_belief` re-verification, HA
  `ReplicatedMemory` + quorum reads). The substrate work is *exposure + attestation*, not new senses.
- **Adapters:** thin surfaces over the core. MCP is the universal one; CLI/Action serve CI; LSP serves
  inline editor diagnostics; HTTP (`MemoryServer`/`RemoteMemory` + control plane) is the cross-machine
  shared brain; the extension is the human surface.
- **Consumers:** any MCP-capable agent tool, plus CI/deploy/incident agents.

## 3. The MCP contract — what every agent binds to

All tool results are **attested**: they carry a verifiable `receipt` (see §4). Reads return grounded
evidence; writes never trust the caller's assertion.

### `gate` — give an agent a conscience  *(hero verb)*
```jsonc
// input
{ "repo": "/abs/path", "stage": "inner_loop|pre_merge|canary",   // default inner_loop
  "language": "python|js|go", "diff_files": ["a.py"],            // optional: scope to a diff
  "options": { "lint": true, "types": false, "security": false, "perf": null } }
// output  (maps verel.verdict.GateResult)
{ "verdict": "pass|warn|fail",
  "reports": [ { "grader": "test|lint|typecheck|security|perf|vision",
                 "verdict": "pass|warn|fail",
                 "issues": [ { "message": "...", "file": "app.py", "line": 42,
                               "severity": "error|warning|info", "confidence": "...",
                               "source": "test|lint|...", "fingerprint": "..." } ] } ],
  "ceiling_clamped": false,            // advisory findings can warn, never gate destructive acts
  "stuck": false, "progress": true,    // strict-subset stuck/progress signal
  "receipt": { /* §4 */ } }
```
The agent can no longer self-declare "done" — it gets a real verdict with grounded `file:line` issues.

### `sight` — give an agent eyes  *(hero verb)*
```jsonc
// input
{ "url": "http://localhost:5173", "intent": "a centered login card, AA contrast",
  "viewport": "1280x800" }
// output  (maps verel.verdict.Percept via senses.sight)
{ "verdict": "pass|warn|fail", "summary": "...",
  "image_ref": "percept://<id>",       // the screenshot; fetched lazily by the dashboard
  "observations": [ { "message": "contrast 3.1:1 < 4.5:1", "bbox": {"x":..,"y":..,"w":..,"h":..},
                      "severity": "warning", "source": "dom|contrast|ocr",
                      "confidence": "...", "fingerprint": "..." } ],
  "matches_intent": true, "intent_satisfied": 7, "intent_total": 8,
  "receipt": { /* §4 */ } }
```
Most agents are blind. This answers "does it actually render / match what we set out to build?" — and
`observations[].bbox` + `image_ref` make it renderable with zero extra infra (the screenshot is on
disk as `Percept.image_path`).

### `recall` — read the shared verified memory
```jsonc
{ "query": "how do we page on call", "scope": "self|team|org|global", "kind": null, "k": 5 }
// → [ { "text": "...", "subject": "...", "scope": "team", "trust": "verified|candidate",
//       "confidence": 0.9, "provenance": "...", "fingerprint": "..." } ]
```
Recall resolves **down** the lattice (most specific wins). A Cursor session, a Claude Code session, and
a CI agent all draw from the same brain.

### `remember` — write to the shared memory (trust does not travel)
```jsonc
{ "fact": { "subject": "retry", "predicate": "rule", "text": "retry transient errors 3x" },
  "scope": "team", "evidence": "..." }
// → { "id": "...", "trust": "candidate|verified", "reverified": true }
```
A peer's claim enters as a **candidate** and only becomes `verified` by passing the importer's own
check (`import_belief`) — so one noisy agent can't poison the swarm (`AuthorTrust` weights repeat
contributors). The caller's self-asserted confidence is ignored.

### Phase 2
- **`heal(stage)`** — runs `self_heal`, returns a **proposed patch** (multi-file diff) + the re-gated
  verdict; never auto-applies. Human/agent approves.
- **`watch(url)`** — temporal eyes: streams percepts (`playing` / `live` / `stabilized`) for
  playback / loading / liveness on streaming UIs and dashboards.

## 4. The attested receipt — the headline wedge

Every result carries a **receipt any other party can verify** — a different tool, a human, or CI.
This is "trust does not travel" applied to *agent output*: an agent **cannot fake green**.

**The primitive already exists.** `verel.verdict.RunReceipt` is a per-grader execution attestation
signed over `(suite_sha, inputs_digest, coverage_assertion, runner_identity)` — the runner is already
a *separate trust domain*. The gate-level receipt below just wraps those, grounded in the real fields:

```jsonc
"receipt": {                                  // gate-level; wraps the per-grader RunReceipts
  "issued_by": "verel@0.28.0",
  "verdict": "fail",
  "fingerprint": "<Nirvana-computed, scrubbed per-grader issue fingerprints (§7.2)>",
  "graders": [
    { "kind": "test", "verdict": "pass", "precise": true,
      "run_receipt": {                        // == verel.verdict.RunReceipt, signed
        "suite_sha": "…",                     // which frozen suite ran
        "inputs_digest": "…",                 // digest of the artifact/diff the grader saw
        "coverage_assertion": "scanned: src/a.py,src/b.py",   // must intersect the diff
        "runner_identity": "ed25519:<key_id>",
        "alg": "ed25519",                     // NEW: hmac-sha256 | ed25519
        "signature": "<sig over signing_payload()>" } },
    { "kind": "vision", "verdict": "warn", "precise": false }   // advisory: informs, never gates
  ],
  "ceiling_clamped": false
}
```
- **Grader attestation** (already in `verel.verdict`): a precise grader must carry a signed
  `RunReceipt`; a hollow check can't mint green, and `coverage_assertion` must intersect the diff.
- **Advisory-vs-precise** split is explicit: advisory senses (vision/LLM) inform but never gate a
  destructive act; `ceiling_clamped` shows when an advisory finding was held back from gating.
- **Independently checkable:** the fingerprint recomputes from the artifact; the signature verifies the
  runner. This is what lets Verel be **the neutral referee** other agents are measured against.

> **Resolved — signing scheme.** Verel already signs `RunReceipt` with **HMAC-SHA256**
> (`gate.sign_receipt`/`verify_signature`, keyed by `VEREL_RUNNER_SECRET`). Keep it unchanged **inside
> a trust domain** (CI + orchestrator share the secret — fast, zero new work). For the substrate's
> headline — *any external tool verifies without being trusted with the secret* — add an **ed25519**
> mode: `runner_identity` becomes a published public key / `key_id`, a new `alg` field selects the
> scheme, and `verify(receipt)` checks the signature **offline with no shared secret**. Two-tier,
> backward compatible: HMAC for speed within the boundary, ed25519 for public verifiability across it
> (the whole point of a substrate other vendors' agents call).

## 5. The VS Code extension — installer + dashboard

The extension stops being the product and becomes the **on-ramp**:

- **One-click install:** writes the Verel MCP server config into whatever agent tool the dev uses —
  `.cursor/mcp.json`, Claude Code's `.mcp.json`, Cline/Windsurf/Zed settings — and verifies the
  handshake. "Add a conscience + eyes to your agent" in two clicks.
- **Dashboard (the human window):** the same surfaces we whiteboarded, now visualizing what *agents*
  did over the substrate —
  - **Verdict panel** + native **Problems-panel diagnostics** (`Issue.file/line` → squiggles),
  - **Eyes panel** (`WebviewView`): the percept screenshot with `bbox` overlays + intent/temporal
    strips; click a finding → source (see the DOM→source degradation ladder, §6),
  - **Memory tree:** the scope lattice + promotion candidates.
- **Status pill:** the ambient pass/warn/fail for the active repo.

The extension talks to the core over **stdio JSON-RPC** for the dashboard panels (single-client, local,
lifecycle-bound) and reuses the MCP server for agent-shaped actions. HTTP stays reserved for the
cross-machine HA brain.

## 6. The eyes — what's solved, resolved

From `senses/sight.py`: a finding's `locator` is already AgentVision's `bbox` serialized as JSON, and
`Percept.image_path` is the screenshot on disk. So the **degradation ladder** (never hard-fail):

```
L0  screenshot only ........................... always (image_path)
L1  + bbox overlays + findings + intent + temporal ... always (bbox pixels)     ◄── "eyes v1"
L2  + click box → reveal DOM node ............. needs a live page (elementFromPoint at box center)
L3  + click box → jump to source line ......... needs dev-build source locs (React __source / Vue
                                                 __file / a build-time data-verel-loc annotator)
```
The visually impressive 80% (what the eyes saw, boxed, with the intent + temporal strips) is **L1 —
zero extra infra**. The risky part (click-to-source) is **L3**, isolated and progressive.

> **Resolved — bbox schema.** AgentVision's `BBox` (`agentvision/models/geometry.py`) is **pixels
> only**: `x, y, width, height` floats, no selector/xpath — with a `bbox_precise` flag (`dom`/`ocr`/`cv`
> = precise, vision-model = advisory). Implications:
> - **L1 is unconditional** (pixels + screenshot).
> - **L2 needs a live page** — recover the node via `document.elementFromPoint(x+w/2, y+h/2)`. But
>   `sight` already navigates a live page *at capture time*, so the fix is to **enrich the Percept
>   then**: resolve each precise box to a selector during capture and stash it in `Issue.detail_json`.
>   That makes L2 free in the editor — no second round-trip. (`watch` media findings already carry a
>   `selector`.) This is a small `sight`-wrapper enhancement, not an editor problem.
> - **L3** still needs dev-build source locations or the annotator — the one genuine spike.
>
> **Bonus:** `bbox_precise` lines up exactly with the receipt's precise-vs-advisory split — a
> vision-model box (advisory) never gates; a `dom`/`cv` box (precise) can.

## 7. Build slices — substrate-first, each a verified, dogfooded, CI-green release

### Slice 0 — `gate` over MCP (the conscience)
Expose `verel.verdict.gate()` / `run_stage` as an MCP tool returning the attested verdict (§3, §4).
Wire into one host (Claude Code or Cursor). **Dogfood:** an external agent gates its own work against
Verel and can't self-declare done. **DoD:** the MCP tool returns a real verdict + receipt in a live
agent session.

### Slice 1 — `sight` over MCP (the eyes)
Expose `sight(url, intent)` → attested percept with `bbox` observations + `image_ref`. **DoD:** an
agent building a UI gets a grounded "does it render / match intent?" verdict.

### Slice 2 — `recall` / `remember` (the shared brain)
Expose memory reads/writes with re-verification on import. **DoD:** two different agent tools compound
into and recall from one verified brain; a bad claim stays a candidate.

### Slice 3 — the verifiable receipt
Make the receipt signed + independently verifiable; add a `verify(receipt)` verb. Document + market it.
**DoD:** a second party verifies a receipt without trusting the producer.

### Slice 4 — the extension (on-ramp + dashboard)
One-click MCP install into the major hosts + the dashboard panels (Verdict/Problems, Eyes L1, Memory).
**DoD:** install the `.vsix`, wire Verel into a tool in two clicks, watch agent verdicts/percepts live.

### Slice 5 — `heal` + `watch`, and runtime DevOps
`heal` (gated multi-file patch) and `watch` (temporal eyes); the **runtime adapter** — the same MCP
server hosted as a sidecar a deploy/incident agent calls (canary gate + deterministic rollback + HA
brain recall). **DoD:** a deploy agent gates a release and an incident agent recalls past incidents.

CI is covered throughout by the existing **Action + `verel-ci`** (the CI adapter already exists).

## 8. Risks & honest costs
- **MCP spec churn** — the protocol is young; pin a version and keep the adapter thin.
- **Receipt key management** — the ed25519 tier (public verifiability) adds a key lifecycle: generation,
  rotation, and *publishing the public key* so external verifiers trust it (§9.4). The HMAC tier has no
  new lifecycle (it already ships). Cost lands only when public verifiability is turned on.
- **Sight render target** — `sight`/`watch` need a live URL; assume the user's dev server, detect the
  port, allow override. Heaviest piece; keep it after `gate`.
- **Protocol/version drift** — the MCP + JSON-RPC contracts are the compatibility boundary; version
  them explicitly with a spawn handshake and a graceful "upgrade `verel`" path.
- **Third runtime** — the extension is TypeScript + Marketplace/OpenVSX, alongside two Python packages
  and a strict release cadence. Real cost; it's why the extension is an on-ramp, not the lead.
- **Cross-tool memory scoping** — a shared brain across tools needs auth + scope boundaries so the
  wrong project can't read another's `team` memory.

## 9. Open questions (decide before Slice 0)
*Resolved (see §4, §6): receipt signing → two-tier HMAC + ed25519; AgentVision bbox → pixels-only,
enrich at capture. Remaining:*
1. **MCP transport:** stdio (local hosts) vs SSE/HTTP (remote/runtime)? Likely both, host-dependent.
2. **Launch host coverage:** which agent tools are officially supported day one — Claude Code + Cursor
   first, then Cline/Windsurf/Zed?
3. **Memory auth model:** how scope + access control work when many tools share one brain — and how it
   reuses the existing control-plane bearer-token / lease auth.
4. **ed25519 key distribution:** where the runner's public key is published so an external verifier
   trusts it (registry endpoint? a `.well-known` key? the receipt carries a key URL?).

## 10. Recommended first step
Build **Slice 0 (`gate` over MCP) + the attested receipt skeleton (Slice 3's core)** together — the
conscience *and* the verifiable-receipt wedge in one increment, wired into one host and dogfooded. It's
brain-only (no render target), proves the substrate thesis, and lands the differentiator immediately.
`sight` (Slice 1) and the extension on-ramp (Slice 4) follow as their own gated releases.

## 11. Slice 3 build plan — the ed25519 verifiable receipt (locked, in progress)

> **Status:** decisions locked 2026-06-22; build started this session. Ships as its own gated,
> CI-green release per the standing cadence. Security cadence (audit → 3-round red-team) is mandatory
> here — this is crypto/attestation surface.

### 11.1 Decisions locked
| Question | Decision |
|---|---|
| Crypto library | **PyNaCl** (`nacl.signing` — libsodium, constant-time Ed25519). |
| Packaging | **Optional extra `verel[attest]`**; lazy-imported. Default install stays HMAC-only and light. |
| Missing-lib behavior | **Fail closed** — an ed25519 receipt with no `pynacl` present never verifies; clear "install verel[attest]" surfaced by the `verify` verb. |
| Key distribution (v1) | **Local trusted-keys dir** (`~/.config/verel/trusted_keys/<key_id>.pub`) **+ inline-pinning**. The runner's *own* key is auto-trusted (zero-config local roundtrip). Registry / `.well-known` deferred to fast-follow. |
| Trust model | **Pinning, never TOFU.** A valid ed25519 signature is necessary but **not** sufficient: `key_id` MUST resolve in the verifier's trusted set (dir or own key). An attacker-minted receipt self-certifies cryptographically but is rejected because its `key_id` is untrusted. |
| `runner_identity` | For ed25519 it becomes `ed25519:<key_id>`, `key_id = urlsafe_b64(sha256(pubkey))[:16]`. |

### 11.2 Two-tier model
- **HMAC-SHA256** (existing) — fast, zero new lifecycle, *within* a trust domain (CI runner + gate share `VEREL_RUNNER_SECRET`). Unchanged, remains the default for all three minting sites.
- **ed25519** (new) — public verifiability *across* trust domains. A second party verifies offline with only the producer's **public** key. This is the substrate wedge.

### 11.3 Build steps (file by file)
1. `pyproject.toml` — add `attest = ["pynacl>=1.5"]` optional extra.
2. `verdict/models.py` — `RunReceipt` gains `alg: str = "hmac-sha256"` and `public_key: str = ""`
   (inline pubkey, cross-checked, never trust-granting). **`signing_payload()` binds `alg` first**
   (anti-downgrade/confusion). Receipts are ephemeral (minted + verified inside one `gate()` call),
   so the payload-format change needs no migration.
3. `_secrets.py` — extract the hardened keyfile I/O (`O_NOFOLLOW`/`O_EXCL`/`0600`/owner-check/
   fail-closed-ephemeral) into a shared helper reused by both the HMAC secret and the ed25519 seed.
4. `verdict/keys.py` (new) — persisted ed25519 seed (reusing 11.3.3), `key_id` derivation, the
   trusted-key resolver (dir + own-key), `ed25519_sign` / `ed25519_verify`, and a `MissingAttestationDep`
   raised when `pynacl` is absent.
5. `verdict/gate.py` — `sign_receipt`/`verify_signature` dispatch on `alg`; **ed25519 verify enforces
   `key_id ∈ trusted` and the inline-pubkey pin**; unknown alg / missing lib → fail closed. New
   `verify_receipt(receipt) -> ReceiptVerification` (the public verb) and an `allowed_algs` policy knob
   on `gate()` (default accepts both; ed25519 still gated by trust).
6. `cli.py` — `verel verify <receipt.json>` prints valid/invalid, alg, runner, and whether it was
   **publicly** verifiable (ed25519 + trusted key) vs shared-secret (HMAC).

### 11.4 Attack vectors to eliminate (each regression-pinned)
| Vector | Defense |
|---|---|
| **Untrusted-key acceptance (TOFU trap)** | valid ed25519 sig but `key_id` not in trusted set → **FAIL**. The single most important property. |
| **Algorithm downgrade / confusion** | `alg` bound into the signed payload; verifier dispatches on `alg`; a sig made under one scheme never validates under another; unknown alg → fail closed. |
| **Inline-pubkey swap** | inline `public_key` must hash to `key_id` **and** equal the authoritative trusted key; mismatch → FAIL. Inline pubkey is display/defense-in-depth, never a trust grant. |
| **Missing `pynacl`** | ed25519 verify fails closed (gate FAILs); `verify` verb surfaces an explicit install hint, never silent green. |
| **Result / input / replay tampering** | inherited unchanged from the existing receipt (result-binding, per-run-nonce input-binding, suite_sha, coverage) — re-pinned under ed25519. |
| **Planted / foreign-owned seed file** | the ed25519 seed reuses `_secrets` hardening; a foreign-owned or group/other-readable seed → ephemeral key (verify fails closed), never trusted. |
| **Empty / malformed signature** | fail closed (extends the existing HMAC test). |

### 11.5 Definition of done
A second party verifies a producer's receipt **offline with only the public key** (`verel verify`),
the full attack table above is regression-pinned in `tests/`, an exploit script is run against the
fixed code and shown blocked, **≥3 adversarial red-team rounds come back clean**, and lint + types +
the full suite are green. Residual design risk named honestly (key distribution/registry deferred;
rotation lifecycle; dependency/kernel trust).

### 11.6 Red-team log (what the adversarial rounds actually found)
- **Round 1 (manual):** `_b64d` claimed strict validation but used lax base64 (silent char-discard) →
  switched to `validate=True`. Robustness, not a forge vector.
- **Round 2 (independent crypto + impl agents):** **non-injective signing payload** — a bare `"|".join`
  let a `"|"` inside any field shift the binding partition, so one signature covered multiple distinct
  field tuples (proven on both tiers). Fixed with a length-prefixed (netstring) canonical encoding.
  Also tightened the `key_id` charset to strict ASCII (was Unicode-aware `isalnum()`).
- **Round 3 (independent encoding-attack + holistic agents):** the new encoding proven injective
  (300k random adversarial tuples, zero collisions). Surfaced the **same `|`-injection class on the
  adjacent HMAC signers** (`toolsmith.ToolRecord`, `registry.SkillArtifact`) — the ToolRecord one was
  empirically exploitable (a signature over `(name="a", code="b|2|c")` validated `(name="a|1|b",
  code="c")`). Fixed by routing all three signers through the shared `verel._sign.canonical_payload`.
- **Round 4:** target — a clean round (no new findings) before declaring done.

**Named residual (deferred defense-in-depth):** the per-run replay `inputs_digests` binding is wired
only at the CI pipeline site; `memory.promotion` and `toolsmith.smith` gate a self-minted receipt in
the same call (so there is no external receipt to replay), and cross-rule/cross-tool replay is already
blocked by the coverage-assertion check. Wiring an *independently computed* expected input digest at
those two sites is deferred — passing the receipt's own digest there would be a no-op (self-comparison).

## 12. Slice 0 build — `gate` over MCP (the conscience, shipping the attested receipt)

> **Status:** built this session, on top of Slice 3. The MCP `gate` tool now RUNS the real graders and
> hands back the §3/§4 attested verdict + a verifiable **gate-level receipt** — so an external agent
> gets a conscience it cannot fake, and a *different* party can confirm the verdict.

### 12.1 What shipped
- **`verel_gate(repo, stage, language, options, diff_files, attest)`** (`mcp_server.py`) — runs
  `ci.run_stage` on the agent's repo and returns `{verdict, stage, reports[file:line issues],
  ceiling_clamped, attest, receipt, receipt_public_verifiable}`. The agent can no longer self-declare
  "done": the verdict is grounded in real graders and the receipt commits to what ran.
- **Gate-level receipt (§4)** — new `verdict.GateReceipt` / `GraderAttestation` + `build_gate_receipt`
  / `verify_gate_receipt` (`verdict/attest.py`). It wraps the per-grader `RunReceipt`s; integrity comes
  from (a) a `fingerprint` that recomputes from the verdict + each grader's outcome **and signature**
  (tamper-evident), and (b) each precise grader's signature. `ceiling_clamped` records when an advisory
  finding was held back from gating.
- **ed25519 by default when available** — `run_stage`/`run_grader`/`graders._receipt` thread an
  `attest` mode; the MCP tool's `attest="auto"` mints ed25519 receipts when `verel[attest]` is
  installed (publicly verifiable), else HMAC. `attest="ed25519"` **fails closed** if PyNaCl is absent —
  never a silent downgrade.
- **`verel_verify(receipt, require_public)`** — exposes Slice 3's verb over MCP; accepts a gate receipt
  (`graders`) or a single `RunReceipt` (`suite_sha`). `require_public` rejects HMAC.
- Real JSON `inputSchema` on every tool (agents see typed args); receipts serialized `mode="json"` so
  the stdio transport never chokes on raw enums.

### 12.2 Wiring (one host: Claude Code)
`examples/mcp.json` → drop into a project as `.mcp.json` (or merge into Claude Code's MCP settings):
```json
{ "mcpServers": { "verel": { "command": "verel-mcp" } } }
```
`verel-mcp` is the existing console script (`verel[mcp]` extra for the server binding). Loopback stdio,
single-host, lifecycle-bound. For cross-machine public verifiability, set a stable
`VEREL_RUNNER_ED25519_SEED` (or rely on the persisted per-install key) and publish the runner's pubkey
to the verifier's `~/.config/verel/trusted_keys/`.

### 12.3 DoD — met
Dogfooded: `verel_gate` on a real repo returns a PASS verdict with an ed25519 receipt; `verel_verify`
(and `verel verify` CLI) confirm it **with no producer trust**; flipping the verdict trips the
fingerprint. Input handling fails closed (missing/again-non-dir repo, unknown stage/language/attest,
PyNaCl-absent). Covered by `tests/test_mcp_gate.py` (14 tests). Security cadence (MCP input surface)
applied below.

## 13. Slice 1 build — `sight` over MCP (the eyes, attested)

> **Status:** built this session. The eyes are now an MCP verb that returns an attested percept —
> grounded observations with pixel bboxes + an image_ref + a verifiable receipt.

### 13.1 What shipped
- **`verel_sight(url, intent, viewport, backend, allow_local, attest)`** (`mcp_server.py`) — renders a
  URL through AgentVision (`senses.sight.perceive`) and returns `{verdict, summary, image_ref,
  image_path, observations[{message, bbox, severity, source, confidence, precise, fingerprint}],
  matches_intent, intent_satisfied, intent_total, ceiling_clamped, attest, receipt,
  receipt_public_verifiable}`. `bbox` is AgentVision's pixel BBox (`{x,y,w,h}`); `image_ref` is
  `percept://<blake2s of the screenshot>`.
- **Attested percept** — `verdict.mint_report_receipt` signs each per-source-grader Report
  (DOM/OCR/CV precise, VISION advisory), binding `inputs_digest` to the **screenshot bytes** (a percept
  receipt can't be replayed onto a different render). `build_gate_receipt` wraps them into the same
  signed, publicly-verifiable envelope as `gate`. So an agent's "it renders / matches intent" claim is
  checkable by a second party — `verel_verify` confirms it.
- **SSRF-safe by default** — the URL is agent-controlled, so AgentVision's `block_private_networks`
  guard stays ON; `allow_local=true` is an explicit opt-in (an agent verifying its own dev server).
  Only `http(s)` is accepted (file/gopher refused at our layer too). ed25519 auto when `verel[attest]`,
  else hmac; `attest="ed25519"` fails closed without PyNaCl. `verel[sight]` absent → clear install hint.
- Sync↔async bridge (`_run_async`) so `dispatch` can drive the async `perceive` under the server's loop
  or in tests.

### 13.2 DoD — met (dogfooded LIVE)
`verel_sight https://example.com` rendered, returned a PASS with an **ed25519** receipt, and
`verel_verify` confirmed it publicly (1 precise grader attested). Hermetic coverage in
`tests/test_mcp_sight.py` (9 tests, `perceive` monkeypatched): attestation + image-binding + tamper,
SSRF/scheme rejection, `allow_local` default-off, viewport parse, AgentVision-absent + PyNaCl-absent
fail-closed, bbox parsing. Security cadence (SSRF + the new input surface) applied next.

## 14. Slice 2 build — `recall` / `remember` over MCP (the shared verified brain)

> **Status:** built this session. Two MCP verbs over ONE persistent shared brain so a Cursor session,
> a Claude Code session, and a CI agent compound into and draw from the same verified memory.

### 14.1 What shipped
- **`verel_recall(query, scope, kind, k)`** — reads via `memory.lattice_recall`: resolves DOWN the scope
  lattice (self < team < org < global; most specific wins) and surfaces
  trust/confidence/support/provenance/fingerprint so a caller can weight what it gets. `k` bounded.
- **`verel_remember(fact, scope, evidence, author)`** — writes a CANDIDATE; **trust does not travel**
  (the caller's self-asserted trust/confidence is ignored). A verifiable `evidence` receipt records
  **attested grounding** (provenance + grounding tag) but does NOT promote to verified.
- **Brain store is fixed per-server** (`VEREL_MEMORY_STORE` env or `~/.config/verel/brain.db`),
  **not agent-controllable** — a tool arg can't repoint it (no arbitrary file read/write). Inputs
  bounded (`_MAX_TEXT`/`_MAX_QUERY`/`_MAX_FIELD`); parameterized SQL (no injection).

### 14.2 DoD — met
A fact remembered without evidence is a candidate; recall resolves it across the lattice with trust
surfaced; a fact remembered with a genuine gate receipt records attested grounding; a **forged receipt
cannot launder trust** (stays candidate). 12 tests in `tests/test_mcp_brain.py`.

### 14.3 Red-team log + the local/remote trust boundary (honest)
Two independent round-2 agents. Store/input/DoS: **CLEAN** (no arbitrary path, no SQL injection,
bounds enforced, no fail-open, concurrency sound). Trust model: the **hard guarantee holds** — no
`verified` without a genuine runner-signed receipt; caller-asserted trust ignored; REJECTED filtered.
It surfaced four soft-trust paths, all *harmless under one local principal, blocking once the brain is
shared across principals*:

| # | Finding | Status |
|---|---|---|
| 1 | A valid-but-UNRELATED receipt could promote a false fact (trust laundering). | **FIXED** — attested evidence records grounding only; no auto-promote (a real `verified` needs a fact-bound attestation). |
| 2 | An unattested CANDIDATE could silently supersede a VERIFIED fact (interference rule). | **FIXED** — `remember` refuses to overwrite a verified belief (returns `conflict`; a real change goes through a revision/contradict flow). |
| 3 | `author` is an unauthenticated free string → AuthorTrust forgery/inflation. | **DEFERRED** — needs an authenticated principal (derive `author` from a signing key). AuthorTrust is therefore NOT used by the local `remember`; it's the **remote-brain** mechanism. (§9.3) |
| 4 | `rank()` ignores the trust tier → a candidate can outrank a verified fact. | **DEFERRED** — recall surfaces `trust` per record so a caller can weight it; folding trust into core `rank()` (used by promotion/consolidation) is a remote-brain ranking item. (§9.3) |

**Residual named:** the local brain is single-principal (one operator's agents on one machine), which is
exactly why #3/#4 are acceptable here; they (plus a receipt↔fact binding for a true cross-principal
`verified`) are the **deferred multi-principal auth layer** the `hosted.py`/`RemoteMemory` direction
already anticipates — that layer does not yet exist to audit.

## 15. Slice 3 (brain, cont.) — the authenticated multi-principal brain (closes Findings 3 & 4)

> **Status:** built this session. Turns the deferred items above into real controls so the **shared
> remote brain** can be trusted across principals, not just one local operator.

### 15.1 What shipped
- **Finding 4 — trust-weighted ranking (`memory/view.py`).** `rank()` gains a small `W_TRUST` term
  (`_TRUST_RANK`: verified 1.0 / candidate 0.0 / rejected −1.0), so at equal relevance a **verified**
  memory edges out a poisoned **candidate** — while a much-more-relevant candidate still wins (relevance
  dominates). Applies everywhere recall ranks (local, lattice, mem0).
- **Finding 3 — authenticated principals (`memory/principal.py`).** A **principal is an ed25519
  keypair** whose `key_id` *is* its identity (reuses `verdict.keys`). `Principal.sign_write` signs the
  exact claim (`canonical_payload("memwrite", key_id, subject, predicate, scope, text)` — domain-tagged,
  injective, so a signature can't be lifted onto a different fact). `verify_write` checks it against an
  **enrolled** pubkey (pinning, never TOFU; the stored pubkey must hash to its key_id).
  `authenticated_remember` writes on behalf of the verified principal: **`author` is the verified
  key_id, never a caller string** — so `AuthorTrust` can no longer be forged, inflated, or
  impersonated. A principal may **not** silently supersede *another* principal's VERIFIED belief.
- **Wiring (`memory/hosted.py`).** `MemoryServer(trusted_principals=…)` + `enroll()`; a `/write_signed`
  endpoint runs `authenticated_remember` (the bearer token = "can connect"; the signature = "who
  wrote"). `RemoteMemory.remember_signed(principal, …)` signs and posts; an unauthenticated write is a
  403 surfaced as a structured result.

### 15.2 DoD — met
Across the in-process HTTP server: an enrolled principal's signed write authenticates with `author ==
key_id`; **signing with your own key while claiming another's key_id fails** (no impersonation); an
unenrolled principal is rejected; a signature is bound to its claim (can't be lifted); a peer cannot
overwrite another principal's verified belief; `AuthorTrust` keys on the verified id. 23 tests in
`tests/test_principal_brain.py`. Security cadence applied next.

**Cross-principal `verified` tier — DONE.** A peer's belief now earns `verified` (not just
`candidate`) via a **fact-bound attestation**: `verdict.fact_commitment(subject,predicate,text)` is a
256-bit commitment to the claim content; `attest_fact()` mints a portable signed `GateReceipt` whose
`subject` IS that commitment; `verify_fact_attestation()` accepts it iff it verifies, attests
`verdict=PASS`, and is bound to THIS exact claim. `authenticated_remember(evidence=…)` requires
**ed25519** (a peer verifies without the producer's secret); the local MCP `verel_remember` accepts
hmac too (single-principal). Trust still never travels by say-so — only a trusted grader's signature
over the specific fact. The reserved-key + non-FACT guards run BEFORE promotion, and the local tool
now shares the same `is_reserved_key` guard as the remote path (so neither can touch the AuthorTrust
ledger). Hardened through a 3-round red-team (256-bit commitment; local non-FACT backstop; local
reserved-key guard).

**MCP `remember`/`recall` → remote principal — DONE.** With `VEREL_BRAIN_URL` set, `verel_recall`
reads the hosted brain and `verel_remember` authors a **signed write as an authenticated principal**
(`VEREL_PRINCIPAL_SEED`, 32-byte ed25519 seed) — the server enforces every guard above and the
verified tier; the local brain stays the zero-config default. Config is operator env, never an agent
tool arg (an agent can't repoint the brain). The returned `trust`/`author`/`reverified` reflect the
*configured server's* claim (operator-trusted, same tier as a DB URL); an agent wanting integrity
independent of the server `verel_verify`s the underlying receipt (ed25519, no producer trust). Missing
seed → fail closed (can read, can't author); bad bearer surfaces as `HTTP 401`, unreachable as a clean
error — neither leaks the token. 8 tests in `tests/test_mcp_remote_brain.py`; 3-round red-team (clean).

**Still deferred (honest):** transport confidentiality (TLS) for a routable bind. Key
distribution/enrollment is operator-driven (publish pubkeys), same as receipt keys.

### 15.3 Security cadence — the controls the red-team rounds added
Seven adversarial rounds hardened this surface; each of the first six found a real issue (fixed
between rounds), and the seventh came back empty — clean. The controls:
- **AUTHZ (signed-writes mode).** Enrolling principals turns on signed-writes mode (secure-by-default,
  read live so a later `enroll()` flips it on). A bearer token then means "can connect", not "can
  author/mutate": the allow-list is `{/write_signed, /recall, /all}`; the raw `/write` and all ten
  trust/confidence mutators (`/promote`, `/corroborate`, `/contradict`, `/demote`, `/pin`, `/unpin`,
  `/annotate`, `/set_flags`, `/decay`) return 403. Bearer is checked first (401 before anything).
- **Replication = cluster channel.** `/apply` and `/replicate` are verbatim upserts (trust + author
  as-is), so they require a **separate cluster credential** (`X-Cluster-Token`, constant-time),
  distinct from the client bearer; without it a signed-mode server refuses them. (`MemoryServer(
  cluster_token=…)`, threaded by `RemoteMemory`/`ReplicaClient`.)
- **No control-record forgery (root-cause fix).** A signed client write may only AUTHOR a plain
  `FACT`; `make_id` ignores `kind`, so a client FACT shares an id with any server-managed record at
  the same `subject|predicate|scope`. Two layers: (a) a **structural backstop** — a client FACT may
  never supersede an existing **non-FACT** record (failure ledger, SKILL, induced rule/schema),
  predicate-independent, so a future server-managed kind can't reopen the class; (b) a **reserved
  predicate/scope denylist** (`author_trust`, `fails`, `design_rule`, `schema`, `tool` / `meta:authors`)
  for the one FACT-kind control record (the AuthorTrust ledger), normalized exactly as `make_key`.
- **Verified-belief integrity.** A principal can't overwrite **or** corroborate-and-reattribute
  another principal's verified belief (the author check fires regardless of text equivalence); signed
  fields are length-bounded; cross-protocol signature reuse is blocked by the `memwrite` domain tag.
  A client signed write carries no `detail` at all (only subject/predicate/scope/text/kind), so the
  pinned/ttl/tool detail-injection vectors are structurally absent.

**Maintenance obligation (named residual).** The non-FACT structural backstop is predicate-independent,
but the FACT-kind reserved-predicate list (`author_trust`, `fails`, `design_rule`, `schema`, `tool`) is
per-name. Any **future** server pipeline that writes a FACT-kind control record on a client-reachable
key MUST either add its predicate to that denylist or, like `graduate()`, stamp its control fields
(notably `author`) explicitly. This is a design-discipline obligation, not a current exploitable gap.

### 15.4 Transport confidentiality (TLS) — roadmap item 3

The bind policy (§15.2) refuses an *anonymous* routable bind, but a token-gated one still crossed the
wire in **cleartext** — the bearer token, the cluster credential, and every signed-write payload were
sniffable on a routable network. Item 3 closes that: confidentiality on any non-loopback path, fail
closed, with loopback staying zero-config.

- **Server TLS.** `MemoryServer(certfile=, keyfile=, ssl_context=)` wraps the listening socket with an
  `ssl.SSLContext` (`server_side=True`); `url` then reports `https://`. Pass a cert/key pair or a
  fully-built context (e.g. with mTLS / a custom cipher policy).
- **Bind policy, tightened (fail closed).** A **non-loopback bind now requires BOTH an `auth_token`
  AND TLS.** Without a cert the server *refuses to start* on a routable host — it will not silently
  serve a bearer-authenticated brain in cleartext. Loopback (`127.0.0.1`, `::1`, `localhost`) is
  unchanged: plain HTTP, no token, zero-config for the local-dev roundtrip.
- **Client TLS + cleartext-secret guard.** `RemoteMemory`/`ReplicaClient` take `cafile=`/`ssl_context=`
  so an internal CA or a pinned cert verifies (not only system roots), threaded into `urlopen`. And
  the client **refuses to attach a bearer or cluster token to a non-loopback `http://` URL** — a
  secret must never leave the process toward a routable host in cleartext. An explicit `insecure=True`
  (client) opts out for a TLS-terminating proxy / service mesh that already encrypts the hop.
- **MCP wiring.** `_brain()`/`_remote_principal()` read `VEREL_BRAIN_CACERT` (CA bundle for the brain's
  cert) and `VEREL_BRAIN_INSECURE` (the same explicit cleartext opt-out), operator env only.

**Threat addressed:** a passive on-path attacker on the brain's network. **Residual (named):** TLS
protects the hop, not the endpoints — a malicious *configured* server still returns whatever
`trust`/`author` it likes (the §15.2 operator-trust caveat; `verel_verify` the ed25519 receipt for
endpoint-independent integrity). Certificate *issuance/rotation* is operator-driven (same posture as
key distribution). Client cert *pinning* beyond CA verification is available via a custom `ssl_context`
but not a first-class field yet.
