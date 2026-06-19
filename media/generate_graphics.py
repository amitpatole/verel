"""Generate Verel's brand graphics with OpenAI's best image model (gpt-image-2)."""

import base64
import sys
from pathlib import Path

from openai import OpenAI

MEDIA = Path(__file__).parent
client = OpenAI(api_key=Path.home().joinpath(".config/OpenAI/key").read_text().strip())
MODEL = "gpt-image-2"

STYLE = ("Premium, modern, minimal abstract tech aesthetic. Deep navy-black background "
         "(#0b0b12). Violet and indigo (#8b7cff) volumetric glow, soft luminous gradients, "
         "subtle fine grid, lots of clean negative space, high detail, crisp, 8k, "
         "professional product marketing art. No gibberish text, no UI mockups.")

JOBS = [
    ("hero.png", "1536x1024",
     "A wide cinematic hero banner for an AI developer framework called VEREL. Centerpiece: "
     "a glowing brain made of light and circuitry that morphs into a single calm stylized eye, "
     "with verified work flowing through a luminous gate marked by an elegant checkmark — the "
     "'verdict gate'. Convey verification, perception (an eye), and a thinking brain. Keep the "
     "left third as clean dark negative space for a title overlay. " + STYLE),
    ("keyvisual.png", "1024x1024",
     "A luminous emblem for VEREL: a minimalist eye whose iris is a glowing neural/circuit "
     "brain, encircled by a thin ring that reads as a verification checkmark, floating over "
     "dark space with violet glow. Iconic, balanced, logo-like, centered. " + STYLE),
    ("flow.png", "1536x1024",
     "An abstract horizontal flow of five connected glowing nodes/orbs left to right on a dark "
     "background, joined by a flowing luminous line that loops back on itself, suggesting an "
     "eval-driven loop: perceive, judge, act, remember, repeat. Each orb a soft different hue "
     "within an indigo/violet/cyan palette. Minimal, premium, no text. " + STYLE),
]


def main() -> int:
    for name, size, prompt in JOBS:
        print(f"generating {name} ({size}) ...", flush=True)
        r = client.images.generate(model=MODEL, prompt=prompt, size=size, quality="high", n=1)
        (MEDIA / name).write_bytes(base64.b64decode(r.data[0].b64_json))
        print(f"  wrote {name} ({(MEDIA / name).stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
