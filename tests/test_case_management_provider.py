"""Tests for the CaseManagementProvider abstraction and its in-process mock.

Mirrors tests/test_vulnerability_provider.py's structure: in-process
mock/failing-provider unit tests plus an interchangeability check against
the HTTP-integration provider (IncidentDeskCaseManagementProvider).
"""

import httpx
import pytest

from app.case_management.providers import (
    CaseManagementUnavailableError,
    FailingCaseManagementProvider,
    MockCaseManagementProvider,
)
from app.integrations.case_management.incident_desk import (
    IncidentDeskCaseManagementProvider,
    IncidentDeskClient,
    build_mock_incident_desk_transport,
)
from app.models import CaseStatus

ALERT_ID = "synthetic-high-001"


def test_mock_provider_creates_an_open_case() -> None:
    case = MockCaseManagementProvider().create_case(alert_id=ALERT_ID, summary="synthetic alert")
    assert case.status == CaseStatus.OPEN
    assert case.case_id


def test_mock_provider_is_idempotent_per_alert_by_default() -> None:
    """Calling create_case() twice for the same alert must not create two cases."""
    provider = MockCaseManagementProvider()
    first = provider.create_case(alert_id=ALERT_ID, summary="synthetic alert")
    second = provider.create_case(alert_id=ALERT_ID, summary="synthetic alert (retry)")
    assert first.case_id == second.case_id


def test_mock_provider_creates_distinct_cases_for_distinct_alerts() -> None:
    provider = MockCaseManagementProvider()
    first = provider.create_case(alert_id="alert-1", summary="first")
    second = provider.create_case(alert_id="alert-2", summary="second")
    assert first.case_id != second.case_id


def test_mock_provider_honors_an_explicit_idempotency_key() -> None:
    provider = MockCaseManagementProvider()
    first = provider.create_case(alert_id="alert-1", summary="first", idempotency_key="fixed-key")
    second = provider.create_case(alert_id="alert-1", summary="first", idempotency_key="fixed-key")
    assert first.case_id == second.case_id


def test_failing_provider_raises_case_management_unavailable() -> None:
    with pytest.raises(CaseManagementUnavailableError):
        FailingCaseManagementProvider().create_case(alert_id=ALERT_ID, summary="synthetic alert")


def test_mock_and_incident_desk_providers_agree_on_shape() -> None:
    """Interchangeability: both implementations of CaseManagementProvider
    return an open CaseResult for a fresh alert - the property that would
    matter once a consumer depends on the interface."""
    mock_case = MockCaseManagementProvider().create_case(
        alert_id=ALERT_ID, summary="synthetic alert"
    )

    client = IncidentDeskClient(
        api_key="mock-incident-desk-api-key",
        transport=httpx.MockTransport(build_mock_incident_desk_transport()),
    )
    incident_desk_case = IncidentDeskCaseManagementProvider(client).create_case(
        alert_id=ALERT_ID, summary="synthetic alert"
    )

    assert mock_case.status == incident_desk_case.status == CaseStatus.OPEN
