# Connectors — hot folders, job queue, signed webhooks

Media pipelines already move files through watched folders and talk to each other with webhooks. These
connectors let Verel sit in that flow without changing it.

## Hot folder

```bash
verel hotfolder --root /srv/qc --data-dir /var/lib/verel --tenant acme --spec spec.yaml
```

```text
/srv/qc/
  incoming/            watched.  ep-2041.mxf  +  ep-2041.mxf.facts.json   (measurements from Audel / ffprobe)
  spec.yaml            the delivery spec ([Media](media.md))
  passed/  review/  quarantine/        used only outside shadow mode
```

For each file that has stopped changing, Verel grades the sidecar facts against the spec, records the
decision in the tenant's pilot log, and writes `ep-2041.mxf.verel.json` next to the asset (the full Report,
the would-be and enforced verdicts, and the signed receipt, bound to the asset's bytes).

| Mode | What happens to the file |
|---|---|
| `shadow` (default) | nothing moves. Verdict sidecar and log entry only. |
| `advisory` | PASS to `passed/`; anything else to `review/`. Never `quarantine/`. |
| `enforce` | PASS to `passed/`, WARN to `review/`, FAIL to `quarantine/`. |

Guardrails, because this tool touches business files:

- Files are only **renamed** inside the root. Nothing is copied-then-deleted, overwritten or deleted. A name
  collision gets a `-1` suffix.
- Symlinks, non-regular files, hidden files and `.part`/`.tmp`/`~` names are ignored.
- A file is graded only after it has stopped changing (`--settle-s`, default 5 s). `--once` trusts the file's
  modification time; the long-running watcher also requires an unchanged size and mtime across scans.
- **Facts must name the file.** The measurements sidecar has to carry `asset.sha256`, and it must match the dropped
  file. Anyone who can write into `incoming/` could otherwise pair a bad file with a good file's facts. (`--no-require-binding`
  relaxes this for a pilot whose sensors don't emit the hash yet; it is weaker, and the docs say so on purpose.)
- **Verdict sidecars are signed.** `<file>.verel.json` carries a MAC under the installation key over the file's size,
  modification time and change time (a writer can restore the first but not the last). A hand-written or copied sidecar is
  ignored and the file is graded; it cannot suppress grading or carry a forged PASS.
- **Crash-safe.** A version that was recorded but not finished (a crash, or a metadata-only change) is decided again under the
  CURRENT mode and policy, without a new record, and then moved. A decision made in shadow mode is never reused to release a
  file under enforce. Each file name may have at most 50 recorded versions per 24 hours, so touching a file cannot flood the evidence log or block the name
for good. An artifact id is the name, the version (size, modification time) and the file's hash, so swapped bytes under a restored
modification time are a new, recorded version. "Waiting for facts" is measured from when the file was first seen, not from its modification time,
  which the sender controls. A hostile entry where a sidecar belongs skips that one file and the scan continues.
- **Checked again before the move.** If the file changed while it was being graded, it is left where it is and graded again.
- **Progress is guaranteed.** Hidden and temp names are filtered before the per-scan limit, and the rotating start is saved
  between runs, so neither a pile of such files nor repeated `--once` runs can starve a real asset.
- **No sidecar, no pass.** If nobody supplies measurements within `--facts-timeout-s` (default 1 h) the asset
  is graded FAIL with an explicit finding. An unmeasured asset is never passed.
- A re-dropped or modified file (different size or mtime) is graded again. An unchanged graded file is not.

Limits: one host, one filesystem (`rename` must be atomic). It is a poller, not an inotify listener.

## Job queue and workers

For volume, put the grading behind a durable queue and run several workers.

```bash
verel jobs enqueue --db jobs.sqlite --tenant acme --kind media_grade --payload job.json --dedupe-key ep-2041
verel worker --db jobs.sqlite --data-dir /var/lib/verel --concurrency 8 \
  --root acme/masters=/srv/acme/masters --pin acme/masters:spec=delivery.yaml
verel jobs stats --db jobs.sqlite
```

```json
{"root": "masters", "facts": ["ep-2041.facts.json"], "spec": "delivery.yaml",
 "asset": "ep-2041.mxf", "artifact_id": "ep-2041", "mode": "shadow", "notify": "qc"}
```

Properties:

- **Durable**: SQLite in WAL mode; jobs survive a crash or restart.
- **At-least-once with fencing**: a worker that stalls past its lease cannot overwrite the result of the worker
  that took over. Handlers are idempotent, and `--dedupe-key` makes enqueue idempotent per tenant.
- **Retries**: capped exponential backoff up to `max_attempts` (default 3), then `dead`, kept for inspection.
  A crashed worker's job is re-queued and counts as an attempt.
- **A payload never names a path or a URL.** It names a **root bound to its own tenant** (`--root TENANT/NAME=/path`; a
  tenant cannot use another tenant's root) and repo-relative paths that the graders confine themselves. A webhook
  destination is a **sink id** that the operator configured for that tenant.
- **The operator pins the spec.** `--pin TENANT/NAME:spec=delivery.yaml` fixes the delivery spec for a root, so a requester
  cannot swap in a lenient one. Policy and enforce modes **require** a pin and an `asset` (so the facts can be bound to
  the file's bytes). Provenance jobs need an `asset`. A job that names an artifact id that already has a decision is
  refused, except for a retry of the same job. At most 8 distinct facts files per job.
- **No mode confusion.** A tenant with a promotion policy always runs in `policy` mode; a job (or HTTP request) that asks
  for another mode is refused.
- **Quota and retention.** A tenant may have at most 5,000 pending jobs and 20,000 stored rows (`VEREL_JOBS_MAX_PENDING`, `VEREL_JOBS_MAX_ROWS`; the rest get HTTP 429),
  claiming is fair across tenants, and finished jobs are purged after 7 days (`VEREL_JOBS_RETENTION_DAYS`,
  `verel jobs purge`). Error text shown to a tenant never contains server paths.
- A bad payload dies immediately (no retry storm) and has **no side effects**: validation runs before grading
  or recording.

Job kinds: `media_grade`, `provenance_grade`, `webhook`. Over HTTP, `verel serve-pilot` exposes
`POST /v1/jobs`, `GET /v1/jobs/<id>` and `GET /v1/jobs`, scoped to the caller's tenant.

## Signed webhooks

Define sinks per tenant; the secret comes from an environment variable, never from the file:

```json
{"acme": {"qc": {"url": "https://qc.example.com/hooks/verel", "secret_env": "VEREL_SINK_ACME_QC"}}}
```

`verel worker --sinks sinks.json`. Each delivery is signed:

```text
X-Verel-Timestamp: 1767225600
X-Verel-Signature: v1=<hex hmac-sha256 of "<timestamp>.<raw body>">
X-Verel-Event-Id:  <uuid>
```

Receivers should verify the signature in constant time and reject timestamps older than a few minutes
(`verel.connectors.webhook.verify_signature` does both). Events carry a hash of the artifact id, the verdicts and
the tenant, not the media or its name.

Safety: `https` only (plain `http` needs `allow_http` per sink), no redirects, the cloud-metadata and link-local
SSRF guard applies, internal addresses are allowed because internal receivers are the normal case, responses are
size-capped, and unsigned sinks are refused. 5xx and timeouts are retried; 4xx (other than 408/425/429) is final.

**Residual:** the SSRF guard resolves the host once and the HTTP client resolves again, so a malicious DNS server
could rebind between the two. Sinks are operator configuration, not user input, which keeps this a low risk; use
IP-pinned egress rules if your threat model includes a hostile receiver.
