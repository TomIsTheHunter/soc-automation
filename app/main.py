import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.routes import router
from app.enrichment.providers import MockEnrichmentProvider

MAX_ALERT_BODY_BYTES = 256 * 1024


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


def create_app(enrichment_provider: object | None = None) -> FastAPI:
    application = FastAPI(
        title="SOC Automation Platform",
        description="Stage 1 deterministic processing for a CrowdStrike-style synthetic alert.",
        version="0.1.0",
        openapi_tags=[
            {"name": "alerts", "description": "Alert ingestion and deterministic triage"}
        ],
    )
    application.state.enrichment_provider = enrichment_provider or MockEnrichmentProvider()
    application.add_middleware(AlertBodySizeLimitMiddleware)
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
