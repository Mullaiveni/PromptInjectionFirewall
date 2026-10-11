from __future__ import annotations

from typing import Any, Protocol

import httpx

from .config import Settings


class ProviderConfigurationError(RuntimeError):
    pass


class ModelProvider(Protocol):
    async def chat_completions(self, request: dict[str, Any]) -> dict[str, Any]:
        ...


class OpenAICompatibleProvider:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def chat_completions(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self._settings.upstream_base_url or not self._settings.upstream_api_key:
            raise ProviderConfigurationError(
                "Set PIF_UPSTREAM_BASE_URL and PIF_UPSTREAM_API_KEY."
            )
        url = (
            self._settings.upstream_base_url.rstrip("/")
            + "/v1/chat/completions"
        )
        headers = {
            "Authorization": f"Bearer {self._settings.upstream_api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            timeout=self._settings.request_timeout_seconds
        ) as client:
            response = await client.post(url, headers=headers, json=request)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("The upstream model returned a non-object response.")
        return payload

