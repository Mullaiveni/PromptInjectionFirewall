from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .config import Settings


SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_ -]?key|password|secret|access[_ -]?token)\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9+/_.=-]{12,}"
    ),
)


@dataclass(frozen=True)
class OutputInspection:
    value: Any
    redacted: bool
    reason_codes: list[str]


def _redact_text(text: str, settings: Settings) -> tuple[str, list[str]]:
    reasons: list[str] = []
    result = text
    for pattern in SECRET_PATTERNS:
        result, count = pattern.subn("[REDACTED SECRET]", result)
        if count:
            reasons.append("SECRET_PATTERN")
    if settings.system_prompt_canary and settings.system_prompt_canary in result:
        result = result.replace(settings.system_prompt_canary, "[REDACTED CANARY]")
        reasons.append("SYSTEM_PROMPT_CANARY")
    return result, sorted(set(reasons))


def inspect_output(value: Any, settings: Settings) -> OutputInspection:
    reasons: list[str] = []

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            sanitized, found = _redact_text(item, settings)
            reasons.extend(found)
            return sanitized
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {key: walk(child) for key, child in item.items()}
        return item

    sanitized_value = walk(value)
    unique_reasons = sorted(set(reasons))
    return OutputInspection(
        value=sanitized_value,
        redacted=bool(unique_reasons),
        reason_codes=unique_reasons,
    )

