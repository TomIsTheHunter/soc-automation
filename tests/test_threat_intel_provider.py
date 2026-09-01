"""Contract tests for the mock-backed threat-intelligence enrichment provider.

Exercises the meaningful integration boundary end to end:

    ThreatIntelEnrichmentProvider.enrich() -> ThreatIntelClient.lookup_indicator()
    -> BaseIntegrationClient.get() -> mocked HTTP transport (simulated vendor)
    -> ThreatIntelVendorResponse (raw schema) -> EnrichmentResult (normalized)

Every scenario replaces only the mocked HTTP transport, never the client or
adapter code - the same technique `tests/conftest.py` uses for the FastAPI
app itself (`httpx.ASGITransport`).
"""

import httpx
import pytest

from app.adapters.crowdstrike import CrowdStrikeStyleAlertAdapter
from app.enrichment.providers import EnrichmentUnavailableError, MockEnrichmentProvider
from app.integrations.enrichment.threat_intel import (
    ThreatIntelClient,
    ThreatIntelEnrichmentProvider,
    mock_threat_intel_transport,
)
from app.models import Confidence, CrowdStrikeStyleAlert, Indicator, IndicatorType, Reputation
from app.services.indicators import extract_indicators
from app.triage.engine import triage_alert
from fixtures.alerts import BENIGN_ALERT, HIGH_RISK_ALERT

API_KEY = "mock-threat-intel-api-key"
MALICIOUS_INDICATOR = Indicator(
    type=IndicatorType.IP, value="198.51.100.10", source="destination_ip"
)
BENIGN_INDICATOR = Indicator(type=IndicatorType.IP, value="203.0.113.10", source="destination_ip")
UNKNOWN_INDICATOR = Indicator(type=IndicatorType.IP, value="192.0.2.99", source="destination_ip")


class _RecordingSleep:
    """Fake `sleep` that records delays instead of waiting.

    See the identical helper in tests/test_integrations_base.py for why
    this exists (verify retry/backoff without real wall-clock delay).
    """

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _provider(
    transport: httpx.MockTransport, *, sleep: _RecordingSleep | None = None
) -> ThreatIntelEnrichmentProvider:
    client = ThreatIntelClient(
        api_key=API_KEY, transport=transport, sleep=sleep or _RecordingSleep()
    )
    return ThreatIntelEnrichmentProvider(client)


def test_200_maps_malicious_verdict_to_normalized_model() -> None:
    provider = _provider(httpx.MockTransport(mock_threat_intel_transport))
    result = provider.enrich(MALICIOUS_INDICATOR)
    assert result.reputation == Reputation.MALICIOUS
    assert result.confidence == Confidence.HIGH
    assert result.source == "mock-threat-intel"
    assert result.category == "c2"


def test_200_maps_benign_verdict_to_normalized_model() -> None:
    provider = _provider(httpx.MockTransport(mock_threat_intel_transport))
    result = provider.enrich(BENIGN_INDICATOR)
    assert result.reputation == Reputation.BENIGN
    assert result.confidence == Confidence.HIGH
    assert result.category is None


def test_404_is_handled_as_unknown_not_a_generic_exception() -> None:
    provider = _provider(httpx.MockTransport(mock_threat_intel_transport))
    result = provider.enrich(UNKNOWN_INDICATOR)
    assert result.reputation == Reputation.UNKNOWN
    assert result.confidence == Confidence.LOW


def test_401_is_classified_and_raises_enrichment_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid or missing API key"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(EnrichmentUnavailableError) as excinfo:
        provider.enrich(MALICIOUS_INDICATOR)
    assert "mock-threat-intel-api-key" not in str(excinfo.value)


def test_500_is_classified_and_raises_enrichment_unavailable_without_leaking_credentials() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(EnrichmentUnavailableError) as excinfo:
        provider.enrich(MALICIOUS_INDICATOR)
    assert "mock-threat-intel-api-key" not in str(excinfo.value)


def test_invalid_json_is_handled_safely() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json{{{")

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(EnrichmentUnavailableError):
        provider.enrich(MALICIOUS_INDICATOR)


def test_valid_json_invalid_schema_fails_cleanly() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # Missing required "verdict"/"score" fields from the vendor schema.
        return httpx.Response(200, json={"ioc": "198.51.100.10", "source": "mock-threat-intel"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(EnrichmentUnavailableError):
        provider.enrich(MALICIOUS_INDICATOR)


def test_provider_recovers_after_one_transient_503() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, text="bad gateway")
        return mock_threat_intel_transport(request)

    sleep = _RecordingSleep()
    provider = _provider(httpx.MockTransport(handler), sleep=sleep)
    result = provider.enrich(MALICIOUS_INDICATOR)
    assert result.reputation == Reputation.MALICIOUS
    assert len(calls) == 2
    assert len(sleep.calls) == 1


def test_provider_exhausts_retries_on_persistent_503() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503, text="bad gateway")

    sleep = _RecordingSleep()
    provider = _provider(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(EnrichmentUnavailableError) as excinfo:
        provider.enrich(MALICIOUS_INDICATOR)
    assert API_KEY not in str(excinfo.value)
    assert len(calls) == 3
    assert len(sleep.calls) == 2


def test_provider_429_rate_limited_raises_enrichment_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0.1"}, json={"error": "rate limited"})

    sleep = _RecordingSleep()
    provider = _provider(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(EnrichmentUnavailableError) as excinfo:
        provider.enrich(MALICIOUS_INDICATOR)
    assert API_KEY not in str(excinfo.value)
    assert sleep.calls == [0.1, 0.1]


def test_provider_timeout_raises_enrichment_unavailable_with_meaningful_message() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("provider did not respond in time")

    sleep = _RecordingSleep()
    provider = _provider(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(EnrichmentUnavailableError) as excinfo:
        provider.enrich(MALICIOUS_INDICATOR)
    assert API_KEY not in str(excinfo.value)
    # Meaningful, provider-attributable failure - not a generic message.
    assert "mock-threat-intel" in str(excinfo.value)
    assert len(sleep.calls) == 2


def test_provider_interchangeability_with_deterministic_triage() -> None:
    """Swapping MockEnrichmentProvider for ThreatIntelEnrichmentProvider changes nothing else.

    Runs the real indicator-extraction + triage pipeline (not the HTTP API)
    against both providers for the same alert and asserts on an identical
    triage outcome - proving the rest of the application depends only on
    the `EnrichmentProvider`/`EnrichmentResult` contract, never on which
    provider produced it.
    """
    normalized = CrowdStrikeStyleAlertAdapter().adapt(
        CrowdStrikeStyleAlert.model_validate(HIGH_RISK_ALERT)
    )
    indicators = extract_indicators(normalized)

    mock_results = [MockEnrichmentProvider().enrich(item) for item in indicators]
    threat_intel_provider = _provider(httpx.MockTransport(mock_threat_intel_transport))
    threat_intel_results = [threat_intel_provider.enrich(item) for item in indicators]

    mock_triage = triage_alert(normalized, mock_results, enrichment_available=True)
    threat_intel_triage = triage_alert(normalized, threat_intel_results, enrichment_available=True)

    assert mock_triage.decision == threat_intel_triage.decision == "ESCALATE"
    assert mock_triage.rules_triggered == threat_intel_triage.rules_triggered


def test_provider_interchangeability_on_benign_alert() -> None:
    normalized = CrowdStrikeStyleAlertAdapter().adapt(
        CrowdStrikeStyleAlert.model_validate(BENIGN_ALERT)
    )
    indicators = extract_indicators(normalized)

    mock_results = [MockEnrichmentProvider().enrich(item) for item in indicators]
    threat_intel_provider = _provider(httpx.MockTransport(mock_threat_intel_transport))
    threat_intel_results = [threat_intel_provider.enrich(item) for item in indicators]

    mock_triage = triage_alert(normalized, mock_results, enrichment_available=True)
    threat_intel_triage = triage_alert(normalized, threat_intel_results, enrichment_available=True)

    assert mock_triage.decision == threat_intel_triage.decision
    assert mock_triage.rules_triggered == threat_intel_triage.rules_triggered


def test_list_indicators_follows_pagination_across_the_fixed_vendor_table() -> None:
    """ThreatIntelClient.list_indicators() demonstrates get_paginated() end to end.

    Not wired into ThreatIntelEnrichmentProvider/the SOC workflow - see the
    module docstring.
    """
    client = ThreatIntelClient(
        api_key=API_KEY, transport=httpx.MockTransport(mock_threat_intel_transport)
    )
    results = client.list_indicators()
    assert {item.ioc for item in results} == {"198.51.100.10", "203.0.113.10"}
    assert {item.verdict for item in results} == {"malicious", "benign"}
