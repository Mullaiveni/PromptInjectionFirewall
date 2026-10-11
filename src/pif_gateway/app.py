from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .detector import inspect_segments
from .extractors import ExtractionError, extract_segments
from .models import (
    DecisionAction,
    InspectionResult,
    ToolAuthorizationRequest,
    ToolAuthorizationResult,
)
from .output_filter import inspect_output
from .policy import evaluate_policy, sanitize_segments
from .provider import (
    ModelProvider,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
)
from .service import inspect_text, prepare_chat_request
from .tool_broker import authorize_tool


def create_app(
    settings: Settings | None = None,
    provider: ModelProvider | None = None,
) -> FastAPI:
    effective_settings = settings or Settings.from_env()
    effective_provider = provider or OpenAICompatibleProvider(effective_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        yield

    app = FastAPI(
        title="Prompt Injection Firewall Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = effective_settings
    app.state.provider = effective_provider
    static_directory = Path(__file__).parent / "static"
    app.mount(
        "/static",
        StaticFiles(directory=static_directory),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    async def demo() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/content/inspect", response_model=InspectionResult)
    async def inspect_content(
        file: UploadFile = File(...),
        source_trust: str = Form("external_untrusted"),
        requested_tools: str = Form(""),
        network_requested: bool = Form(False),
        memory_write_requested: bool = Form(False),
        secret_access_requested: bool = Form(False),
    ) -> InspectionResult:
        data = await file.read(effective_settings.max_document_bytes + 1)
        if len(data) > effective_settings.max_document_bytes:
            raise HTTPException(status_code=413, detail="Document exceeds the size limit.")
        try:
            segments = extract_segments(
                data,
                file.content_type or "application/octet-stream",
                file.filename,
            )
        except ExtractionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        for segment in segments:
            segment.trust = source_trust
        findings = inspect_segments(segments, effective_settings)
        decision = evaluate_policy(
            segments,
            findings,
            effective_settings,
            requested_tools=[
                tool.strip()
                for tool in requested_tools.split(",")
                if tool.strip()
            ],
            network_requested=network_requested,
            memory_write_requested=memory_write_requested,
            secret_access_requested=secret_access_requested,
        )
        return InspectionResult(
            request_id=f"req-{uuid.uuid4().hex}",
            decision=decision,
            findings=findings,
            sanitized_text=sanitize_segments(segments, decision),
        )

    @app.post("/v1/text/inspect", response_model=InspectionResult)
    async def inspect_text_endpoint(payload: dict[str, Any]) -> InspectionResult:
        text = payload.get("text")
        if not isinstance(text, str):
            raise HTTPException(status_code=422, detail="text must be a string.")
        requested_capabilities = payload.get("requested_capabilities", {})
        if not isinstance(requested_capabilities, dict):
            raise HTTPException(
                status_code=422,
                detail="requested_capabilities must be an object.",
            )
        requested_tools = requested_capabilities.get("tools", [])
        if not isinstance(requested_tools, list) or not all(
            isinstance(tool, str) for tool in requested_tools
        ):
            raise HTTPException(
                status_code=422,
                detail="requested_capabilities.tools must be an array of strings.",
            )
        return inspect_text(
            text,
            effective_settings,
            source=str(payload.get("source", "user_message")),
            trust=str(payload.get("trust", "external_untrusted")),
            requested_tools=requested_tools,
            network_requested=bool(requested_capabilities.get("network", False)),
            memory_write_requested=bool(
                requested_capabilities.get("memory_write", False)
            ),
            secret_access_requested=bool(
                requested_capabilities.get("secret_access", False)
            ),
        )

    @app.post("/v1/tools/authorize", response_model=ToolAuthorizationResult)
    async def authorize_tool_endpoint(
        payload: ToolAuthorizationRequest,
    ) -> ToolAuthorizationResult:
        return authorize_tool(payload, effective_settings)

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
    ) -> JSONResponse:
        try:
            payload = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON body.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Request body must be an object.")
        try:
            prepared = prepare_chat_request(payload, effective_settings)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if prepared.decision.action == DecisionAction.BLOCK:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PROMPT_INJECTION_BLOCKED",
                    "request_id": prepared.request_id,
                    "risk_score": prepared.decision.risk_score,
                    "reason_codes": prepared.decision.reason_codes,
                },
            )
        try:
            response = await effective_provider.chat_completions(
                prepared.provider_request
            )
        except ProviderConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Upstream model returned HTTP {exc.response.status_code}.",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Upstream model request failed: {type(exc).__name__}.",
            ) from exc

        inspected = inspect_output(response, effective_settings)
        headers = {
            "X-PIF-Request-ID": prepared.request_id,
            "X-PIF-Action": prepared.decision.action.value,
            "X-PIF-Risk": f"{prepared.decision.risk_score:.2f}",
            "X-PIF-Output-Redacted": str(inspected.redacted).lower(),
        }
        return JSONResponse(content=inspected.value, headers=headers)

    return app


app = create_app()
