from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from .config import Settings
from .models import Finding, Segment, ThreatCategory


@dataclass(frozen=True)
class Rule:
    category: ThreatCategory
    pattern: re.Pattern[str]
    confidence: float
    evidence: str


RULES = (
    Rule(
        ThreatCategory.INSTRUCTION_OVERRIDE,
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,50}"
            r"\b(?:previous|prior|above|system|developer)\b.{0,30}\b(?:instructions?|rules?|prompt)\b",
            re.IGNORECASE,
        ),
        0.91,
        "Attempts to override existing instructions.",
    ),
    Rule(
        ThreatCategory.ROLE_CHANGE,
        re.compile(
            r"\b(?:you are now|act as|assume the role|switch roles?|new persona)\b",
            re.IGNORECASE,
        ),
        0.72,
        "Attempts to redefine the model's role.",
    ),
    Rule(
        ThreatCategory.SECRET_EXTRACTION,
        re.compile(
            r"\b(?:reveal|show|print|return|repeat|expose|dump)\b.{0,60}"
            r"\b(?:system prompt|developer message|api key|secret|token|environment variables?|credentials?)\b",
            re.IGNORECASE,
        ),
        0.96,
        "Requests disclosure of protected instructions or secrets.",
    ),
    Rule(
        ThreatCategory.CREDENTIAL_THEFT,
        re.compile(
            r"\b(?:passwords?|api[_ -]?keys?|access[_ -]?tokens?|private[_ -]?keys?|credentials?)\b"
            r".{0,70}\b(?:send|upload|post|email|transmit|exfiltrate)\b"
            r"|\b(?:send|upload|post|email|transmit|exfiltrate)\b.{0,70}"
            r"\b(?:passwords?|api[_ -]?keys?|access[_ -]?tokens?|private[_ -]?keys?|credentials?)\b",
            re.IGNORECASE,
        ),
        0.99,
        "Attempts to transmit credentials.",
    ),
    Rule(
        ThreatCategory.TOOL_ABUSE,
        re.compile(
            r"\b(?:call|invoke|execute|run|use)\b.{0,50}"
            r"\b(?:tool|shell|terminal|powershell|bash|function|command)\b",
            re.IGNORECASE,
        ),
        0.82,
        "Attempts to direct tool execution.",
    ),
    Rule(
        ThreatCategory.DATA_EXFILTRATION,
        re.compile(
            r"\b(?:send|upload|post|transmit|forward)\b.{0,100}"
            r"(?:https?://|webhook|external|attacker|remote server)",
            re.IGNORECASE,
        ),
        0.94,
        "Attempts to transmit data to an external destination.",
    ),
    Rule(
        ThreatCategory.CONTEXT_POISONING,
        re.compile(
            r"\b(?:the (?:new|actual|updated) (?:policy|rule)|"
            r"(?:administrator|developer|system) (?:approved|authorized)|"
            r"remember (?:that|this) for (?:all|future) conversations?)\b",
            re.IGNORECASE,
        ),
        0.78,
        "Attempts to introduce unverified policy or durable context.",
    ),
    Rule(
        ThreatCategory.MULTI_STEP_JAILBREAK,
        re.compile(
            r"\b(?:do not (?:execute|answer) yet|store this for later|"
            r"in the next (?:message|step)|combine (?:these|the) parts)\b",
            re.IGNORECASE,
        ),
        0.69,
        "May be staging a multi-step instruction.",
    ),
)

EDUCATIONAL_MARKERS = re.compile(
    r"\b(?:example|article|documentation|detect|detection|classifier|"
    r"quoted|phrase|security research|prompt injection|test case)\b",
    re.IGNORECASE,
)
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")


def _representations(
    text: str, settings: Settings
) -> list[tuple[str, str]]:
    normalized = unicodedata.normalize("NFKC", text)
    representations: list[tuple[str, str]] = [("original", text)]
    candidates = {
        "unicode_normalized": normalized,
        "zero_width_removed": ZERO_WIDTH.sub("", normalized),
        "html_decoded": html.unescape(normalized),
        "url_decoded": unquote(normalized),
    }
    for name, value in candidates.items():
        if value != text and all(existing != value for _, existing in representations):
            representations.append((name, value))

    frontier = [(normalized, 0)]
    seen = {value for _, value in representations}
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= settings.max_decode_depth:
            continue
        for match in BASE64_TOKEN.finditer(current):
            token = match.group(0)
            try:
                decoded_bytes = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(decoded_bytes) > settings.max_decoded_bytes:
                continue
            try:
                decoded = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            printable_ratio = sum(character.isprintable() for character in decoded) / max(
                len(decoded), 1
            )
            if printable_ratio < 0.9 or decoded in seen:
                continue
            seen.add(decoded)
            representations.append((f"base64_decoded_depth_{depth + 1}", decoded))
            frontier.append((decoded, depth + 1))
    return representations


def inspect_segments(
    segments: list[Segment],
    settings: Settings,
) -> list[Finding]:
    findings: list[Finding] = []
    for segment in segments:
        educational = bool(EDUCATIONAL_MARKERS.search(segment.text))
        representations = _representations(segment.text, settings)
        for representation_name, representation in representations:
            is_derived = representation_name != "original"
            for rule in RULES:
                for match in rule.pattern.finditer(representation):
                    confidence = rule.confidence
                    operational = True
                    if educational:
                        confidence = max(0.2, confidence - 0.42)
                        operational = False
                    if is_derived:
                        confidence = min(1.0, confidence + 0.04)
                    findings.append(
                        Finding(
                            category=rule.category,
                            segment_id=segment.id,
                            confidence=confidence,
                            evidence=rule.evidence,
                            start=match.start(),
                            end=match.end(),
                            operational=operational,
                            representation=representation_name,
                        )
                    )
            if is_derived and representation != segment.text:
                if any(rule.pattern.search(representation) for rule in RULES):
                    findings.append(
                        Finding(
                            category=ThreatCategory.ENCODED_INSTRUCTION,
                            segment_id=segment.id,
                            confidence=0.93,
                            evidence="An encoded representation contains an instruction-like attack.",
                            end=len(segment.text),
                            representation=representation_name,
                        )
                    )
        if segment.trust == "external_untrusted":
            for finding in list(findings):
                if finding.segment_id == segment.id and finding.operational:
                    findings.append(
                        Finding(
                            category=ThreatCategory.INDIRECT_PROMPT_INJECTION,
                            segment_id=segment.id,
                            confidence=min(1.0, finding.confidence + 0.02),
                            evidence="Operational instructions were found in untrusted content.",
                            end=len(segment.text),
                            representation=finding.representation,
                        )
                    )
                    break
    return _deduplicate(findings)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple[ThreatCategory, str, str], Finding] = {}
    for finding in findings:
        key = (finding.category, finding.segment_id, finding.representation)
        current = by_key.get(key)
        if current is None or finding.confidence > current.confidence:
            by_key[key] = finding
    return list(by_key.values())

