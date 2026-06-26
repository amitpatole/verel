"""Actuators — act-then-verify (the future `actel` organ), built inbuilt behind a clean seam.

An actuator performs a real-world change and then has the senses confirm the world actually changed.
Built here now (like the gateway) behind a layered seam so it lifts out into `actel` later as a
package move, not a rewrite. See IAC-KICKOFF.md Phase 4.
"""

from __future__ import annotations

from .access_verify import (
    EffectiveAccessVerifier,
    parse_aws_simulate,
    parse_aws_validate_policy,
    parse_az_role_assignments,
    parse_gcp_analyze_iam,
)
from .cloudcreds import CloudCreds, resolve, resolve_aws, resolve_azure, resolve_gcp
from .terraform import (
    ActResult,
    PlanResult,
    TerraformActuator,
    escalate,
    escalation_override,
    iam_action_class,
    iam_tool_overrides,
    plan_digest,
)

__all__ = [
    "TerraformActuator", "PlanResult", "ActResult",
    "escalate", "escalation_override", "plan_digest",
    "iam_action_class", "iam_tool_overrides",
    "CloudCreds", "resolve", "resolve_aws", "resolve_gcp", "resolve_azure",
    "EffectiveAccessVerifier", "parse_aws_validate_policy", "parse_aws_simulate",
    "parse_gcp_analyze_iam", "parse_az_role_assignments",
]
