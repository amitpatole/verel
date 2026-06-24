"""Named constants for the Verdict bus (§7.1). No magic numbers in the reducer."""

from __future__ import annotations

from .models import GraderKind, Severity

# Severity rank: index = rank. The clamp/gate logic depends on this exact ordering.
SEV_ORDER = [Severity.INFO, Severity.WARNING, Severity.ERROR, Severity.CRITICAL]

GATING_SEVERITY = Severity.ERROR  # issues at/above this gate (progressed/gating_failures)
ADVISORY_CEIL = Severity.WARNING  # advisory graders cannot exceed this

# Per-issue grounding is keyed off Issue.source (§8.3), so these are GraderKind sets.
PRECISE_GRADERS = {
    GraderKind.TEST,
    GraderKind.TYPECHECK,
    GraderKind.LINT,
    GraderKind.MUTATION,  # deterministic: a surviving injected fault is hard evidence, not a hunch
    GraderKind.SMELL,  # deterministic complexity metrics gate; the LLM "needless abstraction" stays advisory
    GraderKind.DOM,
    GraderKind.OCR,
    GraderKind.CV,
    GraderKind.SECURITY,
    # Hearing: DSP signal analysis and ASR transcription are deterministic grounding.
    GraderKind.DSP,
    GraderKind.ASR,
}
# Advisory graders are clamped to ADVISORY_CEIL: open-ended model judgement (VISION/LLM_JUDGE) and
# the hearing analogues — zero-shot acoustic (CLAP) and transcript/audio-native LLM critique.
ADVISORY_GRADERS = {GraderKind.VISION, GraderKind.LLM_JUDGE,
                    GraderKind.ACOUSTIC, GraderKind.AUDIO_LLM}

# Progress is required non-increasing across a window of this length (§7.2).
W = 4
