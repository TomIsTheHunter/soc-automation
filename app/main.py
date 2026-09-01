import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.routes import router
from app.config import DEFAULT_MAX_ALERT_BODY_BYTES, Settings, get_settings
from app.enrichment.providers import MockEnrichmentProvider
from app.investigation.assistant import (
    InvestigationAssistant,
    InvestigationUnavailableError,
)
from app.investigation.mock import MockInvestigationAssistant
from app.models import ErrorDetail, ErrorResponse
from app.observability import configure_logging, log_event
from app.web.routes import web_router

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


def select_investigation_assistant(settings: Settings | None = None) -> InvestigationAssistant:
    """Select the configured AI provider without silently substituting the mock.

    `mock` is the default offline provider. Any explicit non-`mock` provider is
    attempted live; if it cannot initialize, we keep an explicitly unavailable
    assistant so the workflow can mark AI as degraded without pretending a live
    result ever existed.
    """
    settings = settings or get_settings()
    provider_name = settings.ai_provider
    if provider_name == "mock":
        return MockInvestigationAssistant()
    try:
        from app.investigation.live import AnthropicInvestigationAssistant

        api_key = (
            settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
        )
        return AnthropicInvestigationAssistant(
            api_key=api_key, max_retries=settings.ai_live_max_retries
        )
    except Exception as exc:
        log_event(
            logger,
            logging.WARNING,
            f"AI provider {provider_name!r} is unavailable; deterministic triage remains "
            "authoritative and no mock result is substituted as if it were live",
            event="provider_degraded",
            provider=provider_name,
            result="unavailable",
            error_type=type(exc).__name__,
        )
        return UnavailableInvestigationAssistant(provider_name)


class AlertBodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = DEFAULT_MAX_ALERT_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("path") != "/api/v1/alerts":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None and int(content_length) > self.max_bytes:
            log_event(
                logger,
                logging.WARNING,
                f"Rejected oversized request body: path={scope.get('path')} "
                f"content_length={content_length.decode('latin-1')} max_bytes={self.max_bytes}",
                event="request_rejected",
                workflow_stage="received",
                result="rejected",
                error_type="request_too_large",
            )
            response = JSONResponse(
                status_code=413,
                content=ErrorResponse(
                    error=ErrorDetail(
                        code="request_too_large",
                        message=f"request body exceeds {self.max_bytes} bytes",
                    )
                ).model_dump(mode="json"),
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def create_app(
    enrichment_provider: object | None = None,
    investigation_assistant: InvestigationAssistant | None = None,
    ai_timeout_seconds: float | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="SOC Automation Platform",
        description=(
            "Stage 1 deterministic processing plus Stage 2 bounded AI-assisted "
            "investigation for a CrowdStrike-style synthetic alert."
        ),
        version="0.3.0",
        openapi_tags=[
            {
                "name": "alerts",
                "description": (
                    "Alert ingestion, deterministic triage, and AI-assisted investigation"
                ),
            }
        ],
    )
    application.state.settings = settings
    application.state.enrichment_provider = enrichment_provider or MockEnrichmentProvider()
    application.state.investigation_assistant = (
        investigation_assistant or select_investigation_assistant(settings)
    )
    application.state.ai_timeout_seconds = (
        ai_timeout_seconds
        if ai_timeout_seconds is not None
        else settings.ai_provider_timeout_seconds
    )
    application.add_middleware(
        AlertBodySizeLimitMiddleware, max_bytes=settings.max_alert_body_bytes
    )
    application.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "web" / "static")),
        name="static",
    )
    application.include_router(web_router)
    application.include_router(router)

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness: is the process alive and able to respond at all?

        Deliberately lightweight - no dependency checks. An optional
        provider being unavailable must never make this endpoint fail; see
        `/health/ready` for that distinction and docs/operations.md for the
        full rationale.
        """
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def readiness() -> JSONResponse:
        """Readiness: is the service ready to do its intended work?

        The deterministic triage pipeline has no external dependency and is
        always reported available. The AI investigation assistant is
        explicitly non-authoritative (see docs/adr/001-failure-handling.md)
        - when it is unavailable the service is reported `degraded`, not
        `unhealthy`, because the core security workflow is unaffected.
        """
        ai_unavailable = isinstance(
            application.state.investigation_assistant, UnavailableInvestigationAssistant
        )
        body = {
            "status": "degraded" if ai_unavailable else "healthy",
            "checks": {
                "triage": "available",
                "ai_provider": "unavailable" if ai_unavailable else "available",
            },
        }
        return JSONResponse(status_code=200, content=body)

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Log only field locations/types, never field values - the request body
        # may contain attacker-controlled or sensitive content.
        errors = [{"loc": error.get("loc"), "type": error.get("type")} for error in exc.errors()]
        log_event(
            logger,
            logging.WARNING,
            f"Rejected invalid request: method={request.method} "
            f"path={request.url.path} errors={errors}",
            event="request_rejected",
            workflow_stage="received",
            result="rejected",
            error_type="validation_error",
        )
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=ErrorDetail(
                    code="validation_error",
                    message="request validation failed",
                    details=[dict(error) for error in exc.errors()],
                )
            ).model_dump(mode="json"),
        )

    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        message = str(exc.detail) if isinstance(exc.detail, str) else "request failed"
        log_event(
            logger,
            logging.WARNING,
            f"Rejected request: method={request.method} path={request.url.path} "
            f"status={exc.status_code} detail={message}",
            event="request_rejected",
            workflow_stage="received",
            result="rejected",
            error_type=f"http_{exc.status_code}",
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=ErrorDetail(code="request_error", message=message)
            ).model_dump(mode="json"),
        )

    @application.exception_handler(Exception)
    async def unexpected_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
        log_event(
            logger,
            logging.ERROR,
            "Unhandled application error",
            event="unhandled_exception",
            workflow_stage="received",
            result="error",
            error_type=type(exc).__name__,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error=ErrorDetail(code="internal_error", message="an internal error occurred")
            ).model_dump(mode="json"),
        )

    return application


app = create_app()
