"""Render the Verel infographic to PNG and verify it with AgentVision (the eyes Verel ships).

Dogfood: the marketing infographic is graded by the product's own perception organ before we
publish it. Screenshots at 2x for a crisp asset.
"""

import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

HERE = Path(__file__).parent
SRC = HERE / "infographic.html"
OUT = HERE / "infographic.png"


async def shoot():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1200, "height": 1400}, device_scale_factor=2)
        await pg.goto(SRC.as_uri())
        await pg.wait_for_timeout(300)
        await pg.screenshot(path=str(OUT), full_page=True)
        await b.close()
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


async def verify():
    try:
        from agentvision import analyze, load_settings
    except ImportError:
        print("agentvision not available — skipping verification"); return
    rep = await analyze(str(SRC), settings=load_settings(vision_backend="local"), full_page=True)
    real = [i for i in rep.issues if i.kind.value != "other"]
    print(f"AgentVision verdict: {rep.verdict.value}  ({len(real)} grounded issue(s))")
    for i in real[:6]:
        print(f"  - {i.kind.value}/{i.severity.value}: {i.message[:80]}")


async def main():
    await shoot()
    await verify()


if __name__ == "__main__":
    asyncio.run(main())
