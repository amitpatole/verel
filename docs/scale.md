# Scale — measured throughput and where the limits are

Numbers below were measured with `python tools/bench_scale.py` on one development machine (Linux VM, Python 3.12,
network-attached disk). They are **not promises**. Run the script on your hardware before you size anything.

## Results

| Measurement | Default (`all`) | `VEREL_LOG_FSYNC=record` | `VEREL_LOG_FSYNC=none` |
|---|---|---|---|
| Grade one asset against a delivery spec (`grade_media`, signed receipt), 1 thread | about 1,900 per second | | about 1,900 per second |
| Append a decision to the pilot log, 100 existing records | about 18 per second | about 53 per second | about 1,100 per second |
| Same, 1,000 existing records | about 20 per second | about 59 per second | about 900 per second |
| Same, 5,000 existing records | about 14 per second | about 55 per second | about 1,300 per second |
| Queue: enqueue | about 1,600 per second | about 1,800 per second | about 2,500 per second |
| Queue: claim and complete | about 1,200 per second | about 600 per second | about 1,200 per second |
| End to end through the worker (grade and record), 1 thread | about 18 per second | about 40 per second | about 140 per second |
| End to end through the worker, 8 threads | about 18 per second | about 31 per second | about 224 per second |

What these say:

- **Grading is cheap.** A delivery-spec check is around half a millisecond. It is not the bottleneck.
- **The durable evidence log is disk-sync bound.** Each decision is protected by a keyed ledger that announces the write, the record,
  and the final ledger: three syncs by default (about 18 ms each here), which caps one tenant's log near 15 to 20 decisions per
  second no matter how many worker threads you add. The cost does **not** grow with log size while one process does the appending: it verifies the whole log once, then carries
  the verified set of decided ids forward from its own writes. If another process (or anything else) changed the files in
  between, the next unique append re-verifies the whole log, O(n). That is deliberate: a decided id is refused from verified
  records, never from a quick scan of the file. Use one collector process per tenant for volume: with several processes writing one tenant log, each hand-over costs a full verify (about 4 seconds per 100,000 live records here), so keep the live log small with `verel pilot archive`. A repeated id is answered from one line, not a re-verify.
- **Your options, in order of safety:** keep the default; set `VEREL_LOG_FSYNC=record` (sync only the record, about three times
  faster; after a power loss the ledger or its pending marker may lag, and verification reports it, failing closed, and
  `verel pilot repair` resolves it); or `none` for throwaway pilots. A process crash loses nothing in any mode; only a power loss can
  lose recent records in `record` and `none`.
- **Tenants should scale independently.** Each tenant has its own log and lock, so throughput ought to grow with the
  number of active tenants until the disk saturates. That was not measured.
- **The queue is not the limit.** Single-threaded, SQLite in WAL mode handled over a thousand operations per second.

## What this does not tell you

- **Large media.** These benchmarks grade small facts files. Measuring a 4K master is the sensors' job (Audel,
  AgentVision, ffprobe), and that cost belongs to them, not to Verel. The only per-asset work Verel does on the file is a
  streaming SHA-256 when you pass `--asset`, which runs at disk read speed.
- **A fleet of machines.** Everything here is one host. The queue and the evidence logs are local files, so multi-host
  scaling needs a shared filesystem with working `flock` (for the logs) and is **not tested**. For several hosts, run one
  service per tenant group.
- **Millions of decisions.** The log has a hard cap of one million live records per file; archive with
  `verel pilot archive` before then. Evaluation reads the whole log, so very large logs make `pilot eval` slower
  (linear in records).
- **Sustained load over days.** No soak test has been run.

## Reproduce

```bash
python tools/bench_scale.py --n 500                       # durable defaults
VEREL_LOG_FSYNC=none python tools/bench_scale.py --n 500  # evidence log without disk sync
```
