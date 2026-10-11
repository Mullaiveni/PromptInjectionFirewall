from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ThreatCategory(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTION = "encoded_instruction"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    ALLOW_AS_UNTRUSTED = "allow_as_untrusted"
    ALLOW_CONSTRAINED = "allow_constrained"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class Segment(BaseModel):
    id: str
    text: str
    source: str
    trust: str = "external_untrusted"
    location: dict[str, Any] = Field(default_factory=dict)
    derived_from: str | None = None


class Finding(BaseModel):
    category: ThreatCategory
    segment_id: str
    confidence: float = Field(ge=0, le=1)
    evidence: str
    start: int = 0
    end: int = 0
    operational: bool = True
    representation: str = "original"


class Capabilities(BaseModel):
    tools: list[str] = Field(default_factory=list)
    network: bool = False
    memory_write: bool = False
    secret_access: bool = False
    requested_tools: list[str] = Field(default_factory=list)
    network_requested: bool = False
    memory_write_requested: bool = False
    secret_access_requested: bool = False


class PolicyDecision(BaseModel):
    action: DecisionAction
    risk_score: float = Field(ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list)
    quarantined_segment_ids: list[str] = Field(default_factory=list)
    capabilities: Capabilities = Field(default_factory=Capabilities)


class InspectionResult(BaseModel):
    request_id: str
    decision: PolicyDecision
    findings: list[Finding]
    sanitized_text: str


class ToolAuthorizationRequest(BaseModel):
    request_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source_trust: str = "model_generated"
    session_risk: float = Field(default=0, ge=0, le=1)


class ToolAuthorizationResult(BaseModel):
    allowed: bool
    reason_code: str
    requires_approval: bool = False
