"""Mock-backed case-management provider ("IncidentDesk").

Demonstrates the case-management integration boundary end to end,
including a property the enrichment/vulnerability categories didn't need:
idempotent writes. Creating a case is a side-effecting POST - a naive
retry of a failed create request could create a duplicate incident.
`create_case()` attaches a stable `Idempotency-Key` header (generated
automatically if not supplied) via `BaseIntegrationClient.post()`, reused
across every retry of the same logical request. See
docs/adr/003-idempotent-writes.md.

Unlike the read-only enrichment/vulnerability mocks (fixed, shared,
read-only lookup tables), this mock vendor must track which idempotency
keys it has already seen, so each `IncidentDeskClient` gets its own
isolated in-memory store via `build_mock_incident_desk_transport()` - a
factory, never shared module-level mutable state that could leak between
clients/tests.
"""

import logging
import time
from collections.abc import Callable

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from app.case_management.providers import CaseManagementProvider, CaseManagementUnavailableError
from app.integrations.base import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    ApiKeyAuth,
    BaseIntegrationClient,
    RetryPolicy,
)
from app.integrations.errors import IntegrationError, IntegrationValidationError
from app.models import CaseResult, CaseStatus

logger = logging.getLogger(__name__)

PROVIDER_NAME = "mock-incident-desk"
DEFAULT_BASE_URL = "https://mock-incident-desk.example/v1"
# Retries beyond the first attempt; see docs/adr/002-provider-resilience.md.
DEFAULT_MAX_RETRIES = 2


class IncidentDeskVendorResponse(BaseModel):
    """Raw, provider-specific response schema - never exposed outside this module."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    status: str
    source: str


def build_mock_incident_desk_transport() -> Callable[[httpx.Request], httpx.Response]:
    """Build a fresh mock vendor transport with its own isolated idempotency-key store.

    A factory (not a module-level singleton) so each client/test gets
    independent state - the in-memory equivalent of a real vendor's
    per-tenant idempotency-key store.
    """
    seen: dict[str, dict[str, object]] = {}
    counter = {"next_id": 1}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-api-key") != "mock-incident-desk-api-key":
            return httpx.Response(401, json={"error": "invalid or missing API key"})
        idempotency_key = request.headers.get("idempotency-key")
        if not idempotency_key:
            return httpx.Response(400, json={"error": "missing Idempotency-Key header"})
        cached = seen.get(idempotency_key)
        if cached is not None:
            return httpx.Response(200, json=cached)
        case_id = f"CASE-{counter['next_id']}"
        counter["next_id"] += 1
        record: dict[str, object] = {
            "case_id": case_id,
            "status": "open",
            "source": PROVIDER_NAME,
        }
        seen[idempotency_key] = record
        return httpx.Response(201, json=record)

    return handler


class IncidentDeskClient(BaseIntegrationClient):
    """Mock-backed case-management provider client."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            provider_name=PROVIDER_NAME,
            base_url=base_url,
            auth=ApiKeyAuth(api_key),
            read_timeout_seconds=read_timeout_seconds,
            retry_policy=RetryPolicy(max_attempts=max_retries + 1),
            transport=transport
            if transport is not None
            else httpx.MockTransport(build_mock_incident_desk_transport()),
            sleep=sleep,
        )

    def create_case(
        self, *, alert_id: str, summary: str, idempotency_key: str | None = None
    ) -> IncidentDeskVendorResponse:
        raw = self.post(
            "/cases",
            json_body={"alert_id": alert_id, "summary": summary},
            idempotency_key=idempotency_key,
            operation="create_case",
        )
        try:
            return IncidentDeskVendorResponse.model_validate(raw)
        except ValidationError as exc:
            raise IntegrationValidationError(
                f"{PROVIDER_NAME} returned an unexpected response schema",
                provider=PROVIDER_NAME,
            ) from exc


_STATUS_MAP = {
    "open": CaseStatus.OPEN,
    "in_progress": CaseStatus.IN_PROGRESS,
    "closed": CaseStatus.CLOSED,
}


def _normalize(vendor_response: IncidentDeskVendorResponse) -> CaseResult:
    return CaseResult(
        case_id=vendor_response.case_id,
        status=_STATUS_MAP.get(vendor_response.status, CaseStatus.OPEN),
        source=PROVIDER_NAME,
    )


class IncidentDeskCaseManagementProvider(CaseManagementProvider):
    """Adapts the mock-backed IncidentDesk API into the platform's `CaseResult` contract.

    Interchangeable 1:1 with `app.case_management.providers.MockCaseManagementProvider`
    via the shared `CaseManagementProvider` interface.
    """

    def __init__(self, client: IncidentDeskClient) -> None:
        self._client = client

    def create_case(
        self, *, alert_id: str, summary: str, idempotency_key: str | None = None
    ) -> CaseResult:
        try:
            vendor_response = self._client.create_case(
                alert_id=alert_id, summary=summary, idempotency_key=idempotency_key
            )
        except IntegrationError as exc:
            raise CaseManagementUnavailableError(
                f"{PROVIDER_NAME} unavailable for alert {alert_id!r}"
            ) from exc
        return _normalize(vendor_response)
