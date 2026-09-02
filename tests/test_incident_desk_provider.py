"""Contract tests for the mock-backed case-management provider ("IncidentDesk").

Exercises the same integration boundary as
tests/test_threat_intel_provider.py, for this write-based provider
category:

    IncidentDeskCaseManagementProvider.create_case()
    -> IncidentDeskClient.create_case() -> BaseIntegrationClient.post()
    -> mocked HTTP transport (simulated vendor, its own isolated
    idempotency-key store) -> IncidentDeskVendorResponse (raw schema)
    -> CaseResult (normalized)

The key property demonstrated here that enrichment/vulnerability never
needed: a retried POST (due to a transient failure) must not create a
duplicate case. Generic retry/backoff mechanics are already exhaustively
covered in tests/test_integrations_base.py.
"""

import httpx
import pytest

from app.case_management.providers import CaseManagementUnavailableError
from app.integrations.case_management.incident_desk import (
    IncidentDeskCaseManagementProvider,
    IncidentDeskClient,
    build_mock_incident_desk_transport,
)
from app.models import CaseStatus

API_KEY = "mock-incident-desk-api-key"


class _RecordingSleep:
    """Fake `sleep` that records delays instead of waiting.

    See the identical helper in tests/test_integrations_base.py for why
    this exists (verify retry behavior without real wall-clock delay).
    """

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _provider(
    transport: httpx.MockTransport, *, sleep: _RecordingSleep | None = None
) -> IncidentDeskCaseManagementProvider:
    client = IncidentDeskClient(
        api_key=API_KEY, transport=transport, sleep=sleep or _RecordingSleep()
    )
    return IncidentDeskCaseManagementProvider(client)


def test_201_creates_case_and_maps_to_normalized_model() -> None:
    provider = _provider(httpx.MockTransport(build_mock_incident_desk_transport()))
    case = provider.create_case(alert_id="synthetic-high-001", summary="synthetic alert")
    assert case.status == CaseStatus.OPEN
    assert case.case_id.startswith("CASE-")
    assert case.source == "mock-incident-desk"


def test_same_idempotency_key_returns_the_same_case() -> None:
    provider = _provider(httpx.MockTransport(build_mock_incident_desk_transport()))
    first = provider.create_case(
        alert_id="synthetic-high-001", summary="synthetic alert", idempotency_key="alert-key-1"
    )
    second = provider.create_case(
        alert_id="synthetic-high-001",
        summary="synthetic alert (duplicate call)",
        idempotency_key="alert-key-1",
    )
    assert first.case_id == second.case_id


def test_retried_post_due_to_transient_failure_does_not_create_a_duplicate_case() -> None:
    """The core idempotency demonstration: base.py's own retry (a second
    attempt after a transient 503) reuses the same Idempotency-Key
    (already proven directly in tests/test_integrations_base.py), so the
    mock vendor sees one logical request, not two."""
    transport_handler = build_mock_incident_desk_transport()
    calls: list[int] = []

    def flaky_then_delegating(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, text="bad gateway")
        return transport_handler(request)

    provider = _provider(httpx.MockTransport(flaky_then_delegating))
    case = provider.create_case(
        alert_id="synthetic-high-001", summary="synthetic alert", idempotency_key="stable-key-1"
    )
    assert len(calls) == 2  # one transient failure, then a successful retry

    # A separate call reusing the same key - as a caller retrying at a
    # higher level would - must resolve to the identical case, proving
    # the vendor never recorded a second one for this key.
    again = provider.create_case(
        alert_id="synthetic-high-001", summary="synthetic alert", idempotency_key="stable-key-1"
    )
    assert again.case_id == case.case_id


def test_401_is_classified_and_raises_case_management_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid or missing API key"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(CaseManagementUnavailableError) as excinfo:
        provider.create_case(alert_id="synthetic-high-001", summary="synthetic alert")
    assert API_KEY not in str(excinfo.value)


def test_invalid_schema_fails_cleanly() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # Missing required "status"/"source" fields.
        return httpx.Response(201, json={"case_id": "CASE-1"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(CaseManagementUnavailableError):
        provider.create_case(alert_id="synthetic-high-001", summary="synthetic alert")
