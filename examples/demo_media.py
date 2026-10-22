"""Grade a media delivery against a declared spec, and catch tampered content credentials (no key).

Loudness, A/V sync, track duration and caption languages are graded from *supplied measurements*
(`MediaFacts v1`, produced by Audel / AgentVision / ffprobe). Verel never measures or infers: a rule
whose fact is missing FAILS rather than passing unmeasured. Content credentials (C2PA) are graded from
a validated manifest; Verel grades the validation result against policy, it does not do the crypto.

Run:  python examples/demo_media.py
"""

from verel.media.demo import run_demo

raise SystemExit(run_demo())
