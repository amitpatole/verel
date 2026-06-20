"""Render media/heal-demo.gif — an animated terminal of a REAL `verel heal` run.

The frames replay the actual output captured from `python examples/demo_selfheal.py` (round 1
fails → the agent patches the source → round 2 passes). No mockup: the lines are verbatim. We
reveal the output line-by-line as HTML states, screenshot each with Playwright, and assemble a
looping GIF with PIL.
"""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

W, H = 900, 470
OUT = Path(__file__).parent / "heal-demo.gif"

# Verbatim from a real run of examples/demo_selfheal.py (Ollama qwen3-coder:480b).
PROMPT = '<span class="c">$</span> <span class="cmd">python examples/demo_selfheal.py</span>'
LINES = [
    '<span class="dim">── Self-healing CI (real pytest grader + Ollama code-fixer) ──</span>',
    '  round 1: verdict=<span class="red">fail</span>  medic=[\'fix_branch\']  patched=[\'mathx.py\', \'strx.py\']',
    '  round 2: verdict=<span class="grn">pass</span>  medic=[]  patched=[]',
    '',
    'healed=<span class="grn">True</span>  terminated_on=<span class="grn">passed</span>',
    '',
    '<span class="ok">Result: PASS — agent healed failing CI to green; graders decided done</span>',
]

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{width:%dpx;height:%dpx;background:#0b0b12;font-family:ui-monospace,'SF Mono',Menlo,monospace}
.win{height:100%%;display:flex;flex-direction:column}
.bar{height:34px;background:#15151f;display:flex;align-items:center;padding:0 14px;gap:8px;border-bottom:1px solid #23233a}
.dot{width:12px;height:12px;border-radius:50%%}
.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}
.title{margin-left:10px;color:#6b6b85;font-size:13px;letter-spacing:.3px}
.body{flex:1;padding:18px 20px;font-size:15.5px;line-height:1.6;color:#d6d4ee;white-space:pre-wrap}
.c{color:#8b7cff;font-weight:700}.cmd{color:#e2ddff}
.dim{color:#7b87a8}.red{color:#ff6b6b;font-weight:700}.grn{color:#46d39a;font-weight:700}
.ok{color:#46d39a;font-weight:800}
.cur{display:inline-block;width:9px;height:18px;background:#8b7cff;vertical-align:-3px;margin-left:2px}
""" % (W, H)


def _html(body_lines: list[str], cursor: bool) -> str:
    rows = "<br>".join(body_lines)
    cur = '<span class="cur"></span>' if cursor else ""
    return (f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>"
            f"<div class='win'><div class='bar'><span class='dot r'></span><span class='dot y'></span>"
            f"<span class='dot g'></span><span class='title'>verel — self-healing CI</span></div>"
            f"<div class='body'>{rows}{cur}</div></div></body></html>")


def main() -> None:
    # Frame states: type the command, then reveal output lines one at a time, then hold.
    states: list[tuple[list[str], bool, int]] = [  # (lines, show_cursor, duration_ms)
        ([PROMPT], True, 700),
    ]
    shown = [PROMPT]
    for i, line in enumerate(LINES):
        shown = [*shown, line]
        last = i == len(LINES) - 1
        states.append((list(shown), not last, 1900 if last else 650))
    states.append((list(shown), False, 2200))  # final hold

    frames, durations = [], []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=2)
        for lines, cursor, dur in states:
            page.set_content(_html(lines, cursor))
            png = page.screenshot()
            frames.append(Image.open(io.BytesIO(png)).convert("RGB").resize((W, H), Image.LANCZOS))
            durations.append(dur)
        browser.close()

    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True)
    print(f"wrote {OUT}  ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
