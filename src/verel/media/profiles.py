"""Built-in delivery profiles. Each is a plain list of rules the operator can see, override or disable.

Provenance of the numbers (be precise about what is a standard and what is a convention):
- `ebu_r128`: EBU R 128 — programme loudness -23.0 LUFS, permitted deviation +/-0.5 LU, max true peak -1 dBTP.
- `atsc_a85`: ATSC A/85 — -24 LKFS +/-2 dB, true peak <= -2 dBTP.
- `ebu_r37_av_sync`: EBU R 37 — audio no more than 40 ms ahead of, nor 60 ms behind, the video.
  `av.offset_ms` convention here: positive = audio LATE.
- `streaming_14` / `podcast_16`: platform CONVENTIONS (not standards); tolerance is declared, adjust to
  the platform you deliver to.
A profile is a starting point, not a certification: broadcasters' delivery specs differ — declare your own.
"""

from __future__ import annotations

from typing import Any

Rule = dict[str, Any]


def _loud(target: float, tol: float, tp: float) -> list[Rule]:
    return [
        {"id": "integrated_loudness", "path": "audio.integrated_lufs", "op": "between",
         "value": [target - tol, target + tol], "severity": "error",
         "message": f"integrated loudness must be {target} +/- {tol} LU"},
        {"id": "true_peak", "path": "audio.true_peak_dbtp", "op": "lte", "value": tp,
         "severity": "error", "message": f"true peak must be <= {tp} dBTP"},
    ]


PROFILES: dict[str, list[Rule]] = {
    "ebu_r128": _loud(-23.0, 0.5, -1.0),
    "atsc_a85": _loud(-24.0, 2.0, -2.0),
    "streaming_14": _loud(-14.0, 1.0, -1.0),
    "podcast_16": _loud(-16.0, 1.0, -1.0),
    "ebu_r37_av_sync": [
        {"id": "av_offset", "path": "av.offset_ms", "op": "between", "value": [-40.0, 60.0],
         "severity": "error",
         "message": "audio must be no more than 40 ms early nor 60 ms late (positive = audio late)"},
    ],
}
