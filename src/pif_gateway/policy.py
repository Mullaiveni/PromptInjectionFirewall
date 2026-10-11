from __future__ import annotations

from .config import Settings
from .models import (
    Capabilities,
    DecisionAction,
    Finding,
    PolicyDecision,
    Segment,
    ThreatCategory,
)


CRITICAL_CATEGORIES = {
    ThreatCategory.CREDENTIAL_THEFT,
}


def evaluate_policy(
    segments: list[Segment],
    findings: list[Finding],
    settings: Settings,
    requested_tools: list[str] | None = None,
) -> PolicyDecision:
    operational = [finding for finding in findings if finding.operational]
    maximum = max((finding.confidence for finding in operational), default=0.0)
    categories = {finding.category for finding in operational}
    has_secret_and_exfiltration = (
        ThreatCategory.SECRET_EXTRACTION in categories
        and ThreatCategory.DATA_EXFILTRATION in categories
    )
    critical = bool(categories & CRITICAL_CATEGORIES) or has_secret_and_exfiltration

    has_external_content = any(
        segment.trust == "external_untrusted" for segment in segments
    )
    if critical or maximum >= settings.block_threshold:
        action = DecisionAction.BLOCK
    elif maximum >= settings.constrain_threshold:
        action = DecisionAction.QUARANTINE
    elif findings or has_external_content:
        action = DecisionAction.ALLOW_AS_UNTRUSTED
    else:
        action = DecisionAction.ALLOW

    quarantined = sorted(
        {
            finding.segment_id
            for finding in operational
            if finding.confidence >= settings.constrain_threshold
        }
    )
    allowed_requested_tools = [
        tool
        for tool in (requested_tools or [])
        if tool in settings.allowed_tools
    ]
    can_use_tools = action in {
        DecisionAction.ALLOW,
        DecisionAction.ALLOW_AS_UNTRUSTED,
    }
    capabilities = Capabilities(
        tools=allowed_requested_tools if can_use_tools else [],
        network=bool(allowed_requested_tools) and can_use_tools,
        memory_write=False,
        secret_access=False,
    )
    return PolicyDecision(
        action=action,
        risk_score=maximum,
        reason_codes=sorted(category.value.upper() for category in categories),
        quarantined_segment_ids=quarantined,
        capabilities=capabilities,
    )


def sanitize_segments(
    segments: list[Segment],
    decision: PolicyDecision,
) -> str:
    quarantined = set(decision.quarantined_segment_ids)
    output: list[str] = []
    for segment in segments:
        if segment.id in quarantined:
            output.append(
                f"[QUARANTINED UNTRUSTED CONTENT: segment={segment.id}]"
            )
        else:
            output.append(segment.text)
    return "\n".join(output)
