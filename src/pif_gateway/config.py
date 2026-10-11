from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    upstream_base_url: str | None
    upstream_api_key: str | None
    request_timeout_seconds: float
    max_document_bytes: int
    max_decoded_bytes: int
    max_decode_depth: int
    allowed_tools: frozenset[str]
    allow_network: bool
    allow_memory_write: bool
    allow_secret_access: bool
    block_threshold: float
    constrain_threshold: float
    system_prompt_canary: str | None

    @staticmethod
    def _env_flag(name: str, default: bool = False) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def from_env(cls) -> "Settings":
        tools = {
            tool.strip()
            for tool in os.getenv("PIF_ALLOWED_TOOLS", "").split(",")
            if tool.strip()
        }
        return cls(
            upstream_base_url=os.getenv("PIF_UPSTREAM_BASE_URL"),
            upstream_api_key=os.getenv("PIF_UPSTREAM_API_KEY"),
            request_timeout_seconds=float(os.getenv("PIF_REQUEST_TIMEOUT_SECONDS", "60")),
            max_document_bytes=int(os.getenv("PIF_MAX_DOCUMENT_BYTES", str(10 * 1024 * 1024))),
            max_decoded_bytes=int(os.getenv("PIF_MAX_DECODED_BYTES", str(256 * 1024))),
            max_decode_depth=int(os.getenv("PIF_MAX_DECODE_DEPTH", "2")),
            allowed_tools=frozenset(tools),
            allow_network=cls._env_flag("PIF_ALLOW_NETWORK"),
            allow_memory_write=cls._env_flag("PIF_ALLOW_MEMORY_WRITE"),
            allow_secret_access=cls._env_flag("PIF_ALLOW_SECRET_ACCESS"),
            block_threshold=float(os.getenv("PIF_BLOCK_THRESHOLD", "0.9")),
            constrain_threshold=float(os.getenv("PIF_CONSTRAIN_THRESHOLD", "0.55")),
            system_prompt_canary=os.getenv("PIF_SYSTEM_PROMPT_CANARY"),
        )
