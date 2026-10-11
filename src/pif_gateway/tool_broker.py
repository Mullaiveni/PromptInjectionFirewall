from __future__ import annotations

import json
import re

from .config import Settings
from .models import ToolAuthorizationRequest, ToolAuthorizationResult
from .output_filter import SECRET_PATTERNS


EXTERNAL_URL = re.compile(r"https?://", re.IGNORECASE)


def authorize_tool(
    request: ToolAuthorizationRequest,
    settings: Settings,
) -> ToolAuthorizationResult:
    if request.tool_name not in settings.allowed_tools:
        return ToolAuthorizationResult(
            allowed=False,
            reason_code="TOOL_NOT_ALLOWLISTED",
        )
    if request.session_risk >= settings.constrain_threshold:
        return ToolAuthorizationResult(
            allowed=False,
            reason_code="SESSION_RISK_TOO_HIGH",
        )
    serialized = json.dumps(request.arguments, ensure_ascii=False)
    if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
        return ToolAuthorizationResult(
            allowed=False,
            reason_code="SECRET_IN_TOOL_ARGUMENTS",
        )
    if request.source_trust == "external_untrusted":
        return ToolAuthorizationResult(
            allowed=False,
            reason_code="UNTRUSTED_ARGUMENT_PROVENANCE",
        )
    if EXTERNAL_URL.search(serialized):
        return ToolAuthorizationResult(
            allowed=False,
            reason_code="EXTERNAL_DESTINATION_REQUIRES_APPROVAL",
            requires_approval=True,
        )
    return ToolAuthorizationResult(allowed=True, reason_code="ALLOWED")

