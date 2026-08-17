import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.routes import router
from app.config import get_ai_provider_name, get_ai_timeout_seconds
from app.enrichment.providers import MockEnrichmentProvider
from app.investigation.assistant import (
    InvestigationAssistant,
    InvestigationUnavailableError,
)
from app.investigation.mock import MockInvestigationAssistant
from app.web.routes import web_router

MAX_ALERT_BODY_BYTES = 256 * 1024

logger = logging.getLogger(__name__)


class UnavailableInvestigationAssistant(InvestigationAssistant):
    """Explicitly unavailable AI assistant used when the configured live provider cannot start."""

    def __init__(self, provider_name: str) -> None:
        self._provider_name = provider_name

    async def investigate(self, context: object, timeout_seconds: float) -> dict[str, object]:
        raise InvestigationUnavailableError(
            "AI provider "
            f"{self._provider_name!r} is unavailable; "
            "deterministic triage remains authoritative"
        )


def select_investigation_assistant() -> InvestigationAssistant:
    """Select the configured AI provider without silently substituting the mock.

    `mock` is the default offline provider. Any explicit non-`mock` provider is
    attempted live; if it cannot initialize, we keep an explicitly unavailable
    assistant so the workflow can mark AI as degraded without pretending a live
    result ever existed.
    """
    provider_name = get_ai_provider_name()
    if provider_name == "mock":
        return MockInvestigationAssistant()
    try:
        from app.investigation.live import AnthropicInvestigationAssistant

        return AnthropicInvestigationAssistant()
    except Exception:
        logger.warning(
            "AI provider %r is unavailable; "
            "deterministic triage remains authoritative and no mock result "
            "is substituted as if it were live",
            provider_name,
        )
        return UnavailableInvestigationAssistant(provider_name)


class AlertBodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_ALERT_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("path") != "/api/v1/alerts":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None and int(content_length) > self.max_bytes:
            response = JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "request_too_large",
                        "message": "request body exceeds 256 KiB",
                    }
                },
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def create_app(
    enrichment_provider: object | None = None,
    investigation_assistant: InvestigationAssistant | None = None,
    ai_timeout_seconds: float | None = None,
) -> FastAPI:
    application = FastAPI(
        title="SOC Automation Platform",
        description=(
            "Stage 1 deterministic processing plus Stage 2 bounded AI-assisted "
            "investigation for a CrowdStrike-style synthetic alert."
        ),
        version="0.2.0",
        openapi_tags=[
            {
                "name": "alerts",
                "description": (
                    "Alert ingestion, deterministic triage, and AI-assisted investigation"
                ),
            }
        ],
    )
    application.state.enrichment_provider = enrichment_provider or MockEnrichmentProvider()
    application.state.investigation_assistant = (
        investigation_assistant or select_investigation_assistant()
    )
    application.state.ai_timeout_seconds = (
        ai_timeout_seconds if ai_timeout_seconds is not None else get_ai_timeout_seconds()
    )
    application.add_middleware(AlertBodySizeLimitMiddleware)
    application.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "web" / "static")),
        name="static",
    )
    application.include_router(web_router)
    application.include_router(router)

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "details": exc.errors(),
                }
            },
        )

    @application.exception_handler(HTTPException)
    async def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        message = str(exc.detail) if isinstance(exc.detail, str) else "request failed"
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": "request_error", "message": message}},
        )

    @application.exception_handler(Exception)
    async def unexpected_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
        logging.getLogger(__name__).exception("Unhandled application error", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "an internal error occurred"}},
        )

    return application


app = create_app()
