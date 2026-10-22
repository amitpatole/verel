# Media & communications — delivery specs and content credentials

For a broadcaster, publisher or agency, "done" means the asset meets a **delivery spec** and its
**provenance** is acceptable. `verel.media` grades both deterministically and offline, on the same
verdict bus, gate and signed receipts as every other organ.

| Grader | Grades | Gates | Command |
|---|---|---|---|
| `MEDIA` | declared rules over supplied **measurement facts** (loudness, true peak, A/V sync, track durations, caption languages…) | yes | `verel-ci media` |
| `PROVENANCE` | **C2PA content credentials** against a declared policy | yes | `verel-ci provenance` |

## Who measures what

Verel does not measure media. The senses do, and hand Verel a facts file:

- **Audel** (ears): integrated loudness, true peak, loudness range, silence, clipping, speech.
- **AgentVision** (eyes): frame, caption and on-screen state.
- **ffprobe** or any tool: container, duration, channel and language facts.

Facts are one JSON object (`MediaFacts v1`). Keys are dotted paths. Pass several files and they merge;
the same key with two different values is an **error**, so a stale measurement can't quietly win.

```json
{"audio": {"integrated_lufs": -23.1, "true_peak_dbtp": -1.6, "duration_s": 1800.0},
 "video": {"duration_s": 1800.0},
 "av": {"offset_ms": 12.0},
 "captions": {"languages": ["en", "es"]}}
```

`av.offset_ms` is **positive when audio is late**.

## The delivery spec

```yaml
version: 1
profiles: [ebu_r128, ebu_r37_av_sync]     # built-ins, listed below
rules:
  - id: tracks_match
    path: audio.duration_s
    op: approx            # gte gt lte lt eq ne between approx in not_in present superset subset
    ref: video.duration_s # compare to another fact instead of a constant
    tol: 0.1
    severity: error       # info | warning | error | critical
  - id: captions
    path: captions.languages
    op: superset
    value: [en, es]
disable: [ebu_r128.true_peak]            # opt out of one profile rule, by id
waivers:
  - rule: ebu_r128.integrated_loudness
    reason: "remaster ticket MED-123"
    expires: 2026-12-31                  # required; an expired waiver stops waiving
```

Behavior worth knowing:

- **Unmeasured is not passed.** A missing or non-numeric fact is an ERROR by default (`on_missing:
  warning|skip` per rule to change it). Booleans, strings and NaN are never numbers.
- **Typos fail loudly.** An unknown op, field, profile or duplicate id raises. A rule is never silently dropped.
- **Waivers are visible.** A waived finding becomes a non-gating INFO in the report and receipt. Expired
  waivers gate again and warn; a waiver for a rule that doesn't exist warns as stale.
- **Empty specs warn.** A spec with no active rules cannot grade a clean PASS.
- **Numbers compare as numbers.** `48000` and `48000.0` are equal for `eq`, `ne`, `in` and `not_in`. `true` is never `1`.
- **Null is not measured.** A `null` fact counts as missing. Booleans are never numbers, and `true` is not `1`.
- **Bind the facts to the file.** `verel-ci media --asset masters/ep.mxf` hashes the asset into the receipt, and if your
  facts carry `asset.sha256` it must match, otherwise the finding is CRITICAL. Without `--asset`, nothing ties a
  facts file to a particular asset.
- **Specs are data, not programs.** YAML anchors and aliases are rejected, and `eq`/`in` values must be scalars.

### Built-in profiles

| Profile | Rules | Source |
|---|---|---|
| `ebu_r128` | -23.0 LUFS +/-0.5 LU; true peak <= -1 dBTP | EBU R 128 (standard) |
| `atsc_a85` | -24 LKFS +/-2 dB; true peak <= -2 dBTP | ATSC A/85 (standard) |
| `ebu_r37_av_sync` | audio <= 40 ms early, <= 60 ms late | EBU R 37 (standard) |
| `streaming_14`, `podcast_16` | -14 / -16 LUFS +/-1; true peak <= -1 dBTP | platform **conventions**, not standards |

Profiles are a starting point, not a certification. Individual broadcasters and platforms publish their
own delivery specs. Declare yours.

## Content credentials (C2PA)

```bash
verel-ci provenance --repo . --asset masters/ep-2041.mp4 --policy provenance.yaml
verel-ci provenance --repo . --manifest-json ep-2041.c2pa.json      # fully offline, from a saved report
```

```yaml
version: 1
require_manifest: true
trusted_issuers: ["Example News Org"]   # empty = don't restrict by issuer name
require_trusted_credential: false       # true = the library must report a TRUSTED state (merely "valid" fails)
ai_generated: flag                      # allow | flag (WARN, human review) | deny (FAIL)
```

Informational codes (`ocsp.skipped`, `ocsp.inaccessible`: revocation could not be checked) produce a WARNING, and success codes
(`...validated`, `...match`, `...trusted`, `ocsp.notRevoked`) never count against an asset. Every other code is a failure.

A C2PA implementation (the `c2patool` binary, or `pip install "verel[provenance]"`) validates the
manifest, signature and hashes. Verel grades the **result**: no manifest, validation failure (tamper,
CRITICAL), untrusted credential, issuer not allowed, AI-generated per `digitalSourceType`. If no backend
is available the grader **fails closed**. Failure codes always win over a declared state, so a report that
lists a tamper code is invalid even if it also says "Valid". `--manifest-json` is trusted input (anyone can
hand-write one); add `--asset` to bind the saved report to the exact file bytes in the receipt.

## Real output

`python examples/demo_media.py` (= `verel media demo`; synthetic facts, no key):

```text
1. delivery as submitted: FAIL
    error    ebu_r128.integrated_loudness: -17.4 violates between [-23.5, -22.5]: integrated loudness must be -23.0 +/- 0.5 LU
    error    ebu_r128.true_peak: 0.8 violates lte -1.0: true peak must be <= -1.0 dBTP
    error    ebu_r37_av_sync.av_offset: 95.0 violates between [-40.0, 60.0]: audio must be no more than 40 ms early nor 60 ms late 
    error    tracks_match: 1800.0 violates approx 1802.5: audio.duration_s approx 1802.5
    error    captions: ["en"] violates superset ["en", "es"]: captions.languages superset ["en", "es"]
2. after remix, re-sync, Spanish captions: PASS
3. credentials, untouched: PASS
    info     manifest report is unverified input: it is not tied to any asset
4. credentials, bytes changed after signing: FAIL
    critical content credentials FAILED validation (tampered or corrupt): assertion.datahash.mismatch
    info     manifest report is unverified input: it is not tied to any asset
```

## Honest limits

- Verel grades supplied facts. If a sensor measures wrongly, Verel faithfully grades the wrong number.
- Receipts bind the facts, the spec and the verdict. They do not prove the measurement was honest.
- No manifest does not mean fake: most real media carries none. A valid manifest proves who signed and
  that bytes are unchanged since, **not** that the content is true. Verel does not detect deepfakes.
- C2PA reader adapters were tested against fixtures in the `c2patool` JSON shape, not yet against a
  corpus of live signed assets from each vendor. Pilot on your real files before relying on it.
