"""Contract tests for the mock-backed vulnerability/asset-context provider.

Exercises the same integration boundary as
tests/test_threat_intel_provider.py, for this provider category:

    AssetIntelVulnerabilityProvider.get_context() -> AssetIntelClient.get_asset_context()
    -> BaseIntegrationClient.get() -> mocked HTTP transport (simulated vendor)
    -> AssetIntelVendorResponse (raw schema) -> VulnerabilityContext (normalized)

Resilience mechanics (retry/backoff/rate-limit bounds) are already
exhaustively covered generically in tests/test_integrations_base.py; this
file only proves the wiring is correct for this provider, not every
failure class again.
"""

import httpx
import pytest

from app.integrations.vulnerability.asset_intel import (
    AssetIntelClient,
    AssetIntelVulnerabilityProvider,
    mock_asset_intel_transport,
)
from app.models import AssetCriticality
from app.vulnerability.providers import VulnerabilityContextUnavailableError

API_KEY = "mock-asset-intel-api-key"


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
) -> AssetIntelVulnerabilityProvider:
    client = AssetIntelClient(
        api_key=API_KEY, transport=transport, sleep=sleep or _RecordingSleep()
    )
    return AssetIntelVulnerabilityProvider(client)


def test_200_maps_critical_asset_to_normalized_model() -> None:
    provider = _provider(httpx.MockTransport(mock_asset_intel_transport))
    context = provider.get_context("workstation-07")
    assert context.criticality == AssetCriticality.CRITICAL
    assert context.critical_vulnerability_count == 3
    assert context.source == "mock-asset-intel"


def test_200_maps_low_criticality_asset_to_normalized_model() -> None:
    provider = _provider(httpx.MockTransport(mock_asset_intel_transport))
    context = provider.get_context("workstation-08")
    assert context.criticality == AssetCriticality.LOW
    assert context.critical_vulnerability_count == 0


def test_404_is_handled_as_unknown_not_a_generic_exception() -> None:
    provider = _provider(httpx.MockTransport(mock_asset_intel_transport))
    context = provider.get_context("workstation-does-not-exist")
    assert context.criticality == AssetCriticality.UNKNOWN
    assert context.critical_vulnerability_count == 0


def test_401_is_classified_and_raises_context_unavailable_without_leaking_credentials() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid or missing API key"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(VulnerabilityContextUnavailableError) as excinfo:
        provider.get_context("workstation-07")
    assert API_KEY not in str(excinfo.value)


def test_invalid_schema_fails_cleanly() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # Missing required "criticality"/"open_critical_cves" fields.
        return httpx.Response(200, json={"asset": "workstation-07", "source": "mock-asset-intel"})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(VulnerabilityContextUnavailableError):
        provider.get_context("workstation-07")


def test_recovers_after_one_transient_503() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, text="bad gateway")
        return mock_asset_intel_transport(request)

    provider = _provider(httpx.MockTransport(handler))
    context = provider.get_context("workstation-07")
    assert context.criticality == AssetCriticality.CRITICAL
    assert len(calls) == 2
