"""Phase-0 walking-skeleton DoD demo.

> Verel fixes a real UI overflow on a real page, and the loop terminates on a `pass`
> verdict it computed ITSELF — not a self-asserted "done".

Run:  python examples/demo_overflow_loop.py     (needs `pip install -e ".[sight]"`)

The "fix" here is a deterministic function standing in for a coding subagent — the Phase-0
seam. Everything else is real: AgentVision renders + perceives, Verel's verdict bus gates,
and Verel's OWN scrubbed-fingerprint progressed/stuck decides termination.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from verel.loop import ultracode_loop
from verel.verdict import Verdict

BROKEN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>overflow demo</title>
<style>
  body { margin: 0; font-family: system-ui, sans-serif; color: #111; background: #fff; }
  .panel { box-sizing: border-box; width: 2400px; height: 90px; padding: 16px; }
</style></head>
<body>
  <div class="panel">This panel is 2400px wide and overflows the viewport horizontally.</div>
</body></html>
"""


async def fix_hook(artifact: str, gate_result, reports) -> bool:
    """Stand-in for a coding subagent: resolve the overflow once, then give up."""
    src = Path(artifact).read_text()
    if "width: 2400px" in src:
        Path(artifact).write_text(src.replace("width: 2400px", "width: 100%; max-width: 100%"))
        print("  fix_hook: narrowed .panel to 100% width")
        return True
    return False  # nothing left we know how to fix -> loop reports fix_gave_up


async def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        artifact = str(Path(d) / "page.html")
        Path(artifact).write_text(BROKEN)

        outcome = await ultracode_loop(
            artifact, fix_hook, backend="local", log_dir=str(Path(d) / "percepts"), max_iter=5
        )

        print(f"\nterminated_on={outcome.terminated_on}  final_verdict={outcome.final_verdict.value}")
        for it in outcome.iterations:
            print(f"  iter {it.n}: verdict={it.verdict.value:4}  "
                  f"progressed={it.progressed}  stuck={it.stuck}  gating={len(it.gating)}")

        ok = outcome.passed and outcome.final_verdict == Verdict.PASS
        print("\nDoD:", "PASS — loop terminated on a self-computed `pass`" if ok else "NOT MET")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
