"""Mock-backed threat-intelligence enrichment provider.

Demonstrates the full integration boundary end to end:

    SOC workflow -> ThreatIntelEnrichmentProvider -> ThreatIntelClient
    -> BaseIntegrationClient (auth, timeout, bounded retry/backoff, error
    classification) -> mocked HTTP transport (simulated vendor)
    -> ThreatIntelVendorResponse (raw provider schema)
    -> EnrichmentResult (normalized internal model)

No real network call is ever made: `httpx.MockTransport` stands in for the
vendor the same way `tests/conftest.py` already uses `httpx.ASGITransport`
to exercise the FastAPI app without a real socket. The request/response
code path (headers, status codes, JSON parsing, schema validation, retry
behavior) is real; only the transport is swapped. See
docs/integration-architecture.md and docs/adr/002-provider-resilience.md.

`ThreatIntelClient.list_indicators()` additionally demonstrates the base
client's cursor pagination (`BaseIntegrationClient.get_paginated`) against
a synthetic multi-page `/indicators/list` endpoint - not wired into
`ThreatIntelEnrichmentProvider`/the SOC workflow, since nothing there
needs a bulk indicator listing today.
"""

import logging
import time
from collections.abc import Callable

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from app.enrichment.providers import EnrichmentProvider, EnrichmentUnavailableError
from app.integrations.base import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    ApiKeyAuth,
    BaseIntegrationClient,
    RetryPolicy,
)
from app.integrations.errors import (
    IntegrationError,
    IntegrationNotFoundError,
    IntegrationValidationError,
)
from app.models import Confidence, EnrichmentResult, Indicator, Reputation

logger = logging.getLogger(__name__)

PROVIDER_NAME = "mock-threat-intel"
DEFAULT_BASE_URL = "https://mock-threat-intel.example/v1"
# Retries beyond the first attempt; see docs/adr/002-provider-resilience.md.
DEFAULT_MAX_RETRIES = 2

# Fixed synthetic vendor "backend" data, served only over the mocked HTTP
# boundary below. Deliberately separate from app/enrichment/table.py, which
# backs the existing in-process MockEnrichmentProvider - the two providers
# are independent implementations of the same EnrichmentProvider interface.
_VENDOR_RECORDS: dict[str, dict[str, object]] = {
    "198.51.100.10": {
        "ioc": "198.51.100.10",
        "verdict": "malicious",
        "score": 92,
        "source": PROVIDER_NAME,
        "tags": ["c2", "botnet"],
    },
    "203.0.113.10": {
        "ioc": "203.0.113.10",
        "verdict": "benign",
        "score": 5,
        "source": PROVIDER_NAME,
        "tags": [],
    },
}


class ThreatIntelVendorResponse(BaseModel):
    """Raw, provider-specific response schema - never exposed outside this module."""

    model_config = ConfigDict(extra="forbid")

    ioc: str
    verdict: str
    score: int
    source: str
    tags: list[str] = []


# Page size for the synthetic /indicators/list endpoint below - deliberately
# small (1) so the fixed 2-record _VENDOR_RECORDS table still exercises
# multi-page pagination in tests without needing more synthetic data.
_LIST_PAGE_SIZE = 1


def _handle_list_indicators(request: httpx.Request) -> httpx.Response:
    """Serve one page of `/indicators/list`, cursor = the next start offset."""
    records = list(_VENDOR_RECORDS.values())
    cursor = request.url.params.get("cursor")
    try:
        start = int(cursor) if cursor else 0
    except ValueError:
        return httpx.Response(400, json={"error": "invalid cursor"})
    page = records[start : start + _LIST_PAGE_SIZE]
    next_start = start + _LIST_PAGE_SIZE
    next_cursor = str(next_start) if next_start < len(records) else None
    return httpx.Response(200, json={"items": page, "next_cursor": next_cursor})


def mock_threat_intel_transport(request: httpx.Request) -> httpx.Response:
    """Simulate the external vendor's HTTP API for `httpx.MockTransport`.

    Validates the API-key header the same way a real vendor would, so the
    authentication flow is genuinely exercised rather than assumed.
    """
    if request.headers.get("x-api-key") != "mock-threat-intel-api-key":
        return httpx.Response(401, json={"error": "invalid or missing API key"})
    if request.url.path.endswith("/indicators/list"):
        return _handle_list_indicators(request)
    indicator = request.url.params.get("indicator", "")
    record = _VENDOR_RECORDS.get(indicator)
    if record is None:
        return httpx.Response(404, json={"error": "indicator not found"})
    return httpx.Response(200, json=record)


class ThreatIntelClient(BaseIntegrationClient):
    """Mock-backed threat-intelligence provider client."""

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
            else httpx.MockTransport(mock_threat_intel_transport),
            sleep=sleep,
        )

    def lookup_indicator(self, indicator: str) -> ThreatIntelVendorResponse:
        raw = self.get(
            "/indicators/lookup", params={"indicator": indicator}, operation="lookup_indicator"
        )
        try:
            return ThreatIntelVendorResponse.model_validate(raw)
        except ValidationError as exc:
            raise IntegrationValidationError(
                f"{PROVIDER_NAME} returned an unexpected response schema",
                provider=PROVIDER_NAME,
            ) from exc

    def list_indicators(self) -> list[ThreatIntelVendorResponse]:
        """Fetch every known indicator across all pages of `/indicators/list`."""
        raw_items = self.get_paginated("/indicators/list", operation="list_indicators")
        try:
            return [ThreatIntelVendorResponse.model_validate(item) for item in raw_items]
        except ValidationError as exc:
            raise IntegrationValidationError(
                f"{PROVIDER_NAME} returned an unexpected response schema",
                provider=PROVIDER_NAME,
            ) from exc


_VERDICT_TO_REPUTATION = {
    "malicious": Reputation.MALICIOUS,
    "benign": Reputation.BENIGN,
}


def _normalize(
    vendor_response: ThreatIntelVendorResponse, indicator: Indicator
) -> EnrichmentResult:
    reputation = _VERDICT_TO_REPUTATION.get(vendor_response.verdict, Reputation.UNKNOWN)
    if reputation is Reputation.UNKNOWN:
        confidence = Confidence.LOW
    else:
        decisiveness = abs(vendor_response.score - 50)
        confidence = (
            Confidence.HIGH
            if decisiveness >= 40
            else Confidence.MEDIUM
            if decisiveness >= 15
            else Confidence.LOW
        )
    return EnrichmentResult(
        indicator=indicator,
        reputation=reputation,
        confidence=confidence,
        source=PROVIDER_NAME,
        category=vendor_response.tags[0] if vendor_response.tags else None,
    )


class ThreatIntelEnrichmentProvider(EnrichmentProvider):
    """Adapts the mock-backed threat-intel API into the platform's `EnrichmentResult` contract.

    Interchangeable 1:1 with `app.enrichment.providers.MockEnrichmentProvider`
    via the shared `EnrichmentProvider` interface - see
    docs/integration-architecture.md for the interchangeability walkthrough.
    """

    def __init__(self, client: ThreatIntelClient) -> None:
        self._client = client

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        try:
            vendor_response = self._client.lookup_indicator(indicator.value)
        except IntegrationNotFoundError:
            return EnrichmentResult(
                indicator=indicator,
                reputation=Reputation.UNKNOWN,
                confidence=Confidence.LOW,
                source=PROVIDER_NAME,
            )
        except IntegrationError as exc:
            raise EnrichmentUnavailableError(
                f"{PROVIDER_NAME} enrichment unavailable for indicator {indicator.value!r}"
            ) from exc
        return _normalize(vendor_response, indicator)
