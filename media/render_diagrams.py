"""Render the architecture & flow SVGs to crisp PNGs and verify them with AgentVision."""

import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
JOBS = [(ROOT / "docs/architecture.svg", ROOT / "media/architecture.png", 1200, 940),
        (ROOT / "docs/flow.svg", ROOT / "media/flow_diagram.png", 1120, 720)]


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        for svg, png, w, h in JOBS:
            pg = await b.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
            html = f'<body style="margin:0">{svg.read_text()}</body>'
            await pg.set_content(html)
            await pg.wait_for_timeout(200)
            await pg.locator("svg").screenshot(path=str(png))
            await pg.close()
            print(f"wrote {png.name} ({png.stat().st_size // 1024} KB)")
        await b.close()
    try:
        from agentvision import analyze, load_settings
        for _svg, png, _w, _h in JOBS:
            rep = await analyze(str(png), settings=load_settings(vision_backend="local"))
            real = [i for i in rep.issues if i.kind.value != "other"]
            print(f"AgentVision {png.name}: {rep.verdict.value} ({len(real)} grounded issue(s))")
            for i in real[:4]:
                print(f"   - {i.kind.value}/{i.severity.value}: {i.message[:70]}")
    except ImportError:
        print("agentvision not available — skipping verification")


if __name__ == "__main__":
    asyncio.run(main())
