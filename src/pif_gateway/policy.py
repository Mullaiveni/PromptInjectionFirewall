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
    network_requested: bool = False,
    memory_write_requested: bool = False,
    secret_access_requested: bool = False,
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
        network=network_requested and settings.allow_network and can_use_tools,
        memory_write=(
            memory_write_requested
            and settings.allow_memory_write
            and can_use_tools
        ),
        secret_access=(
            secret_access_requested
            and settings.allow_secret_access
            and can_use_tools
        ),
        requested_tools=requested_tools or [],
        network_requested=network_requested,
        memory_write_requested=memory_write_requested,
        secret_access_requested=secret_access_requested,
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
