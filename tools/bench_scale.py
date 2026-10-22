"""Measure Verel's grading throughput on THIS machine. Prints a markdown table; nothing here is a promise.

  python tools/bench_scale.py [--n 2000]

Measures: media-grade (facts+spec -> signed Report) per second, pilot-log append cost as the log grows,
job-queue enqueue/claim/complete throughput, and end-to-end worker throughput with N threads.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import tempfile
import threading
import time
from pathlib import Path

from verel.jobs import JobQueue, WorkerContext, run_pool
from verel.media import grade_media
from verel.pilot import ShadowLog, run_pilot
from verel.verdict.models import GraderKind, Report, Verdict


def timed(fn, n):
    t = time.perf_counter()
    for i in range(n):
        fn(i)
    dt = time.perf_counter() - t
    return n / dt, dt / n * 1000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    n = ap.parse_args().n
    rows = []
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "m"
        root.mkdir()
        spec = {"version": 1, "profiles": ["ebu_r128", "ebu_r37_av_sync"]}
        (root / "spec.json").write_text(json.dumps(spec))
        facts = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}, "av": {"offset_ms": 10.0}}
        (root / "f.json").write_text(json.dumps(facts))
        rate, ms = timed(lambda i: grade_media(str(root), facts=["f.json"], spec="spec.json"), min(n, 500))
        rows.append(("grade_media (facts+spec -> signed Report), 1 thread", rate, f"{ms:.2f} ms each"))

        rep = Report(verdict=Verdict.PASS, summary="s", grader=GraderKind.DSP)
        for size in (100, 1000, 5000):
            log = ShadowLog(Path(d) / f"l{size}.jsonl")
            saved = os.environ.get("VEREL_LOG_FSYNC")
            os.environ["VEREL_LOG_FSYNC"] = "none"  # seed quickly; the timed appends use the mode under test
            for i in range(size):
                run_pilot([rep], artifact_id=f"a{i}", log=log)
            if saved is None:
                os.environ.pop("VEREL_LOG_FSYNC")
            else:
                os.environ["VEREL_LOG_FSYNC"] = saved
            t = time.perf_counter()
            for i in range(20):
                run_pilot([rep], artifact_id=f"x{i}", log=log)
            ms = (time.perf_counter() - t) / 20 * 1000
            mode = os.environ.get("VEREL_LOG_FSYNC", "all")
            rows.append((f"pilot log append at {size} records (VEREL_LOG_FSYNC={mode})", 1000 / ms,
                         f"{ms:.1f} ms each"))

        q = JobQueue(Path(d) / "jobs.sqlite")
        rate, ms = timed(lambda i: q.enqueue("t", "k", {"i": i}), 500)
        rows.append(("queue enqueue", rate, f"{ms:.2f} ms each"))
        t = time.perf_counter()
        c = 0
        while (j := q.claim("w", ["k"])) is not None:
            q.complete(j, {})
            c += 1
        rows.append(("queue claim+complete", c / (time.perf_counter() - t), ""))

        for threads in (1, 4, 8):
            jq = JobQueue(Path(d) / f"w{threads}.sqlite")
            for i in range(300):
                jq.enqueue("acme", "media_grade", {"root": "m", "facts": ["f.json"], "spec": "spec.json",
                                                   "artifact_id": f"ep-{i}"})
            ctx = WorkerContext(data_dir=Path(d) / f"data{threads}", roots={"acme": {"m": root}})
            stop = threading.Event()
            t0 = time.perf_counter()
            run_pool(jq, ctx, concurrency=threads, stop=stop, poll_s=0.01)
            while jq.stats("acme")["done"] < 300:
                time.sleep(0.05)
            el = time.perf_counter() - t0
            stop.set()
            rows.append((f"end-to-end worker (grade + record), {threads} thread(s)", 300 / el, ""))

    print(f"Machine: {platform.platform()} | Python {platform.python_version()}\n")
    print("| Measurement | Rate per second | Note |\n|---|---|---|")
    for name, rate, note in rows:
        print(f"| {name} | {rate:,.0f} | {note} |")


if __name__ == "__main__":
    main()
