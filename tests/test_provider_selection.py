"""Tests for `app/main.py: select_enrichment_provider`.

Mirrors the existing `select_investigation_assistant` pattern: `mock` is
always available; any other configured value attempts the mock-backed
threat-intel integration, degrading to an explicitly failing provider
(never a silently substituted mock) if construction fails.
"""

import logging

import pytest

import app.main as main_module
from app.config import get_settings
from app.enrichment.providers import (
    EnrichmentUnavailableError,
    FailingEnrichmentProvider,
    MockEnrichmentProvider,
)
from app.integrations.enrichment.threat_intel import ThreatIntelEnrichmentProvider
from app.models import Indicator, IndicatorType


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ENRICHMENT_PROVIDER", "THREAT_INTEL_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_mock_is_selected_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    provider = main_module.select_enrichment_provider(get_settings())
    assert isinstance(provider, MockEnrichmentProvider)


def test_threat_intel_is_selected_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("ENRICHMENT_PROVIDER", "threat-intel")
    provider = main_module.select_enrichment_provider(get_settings())
    assert isinstance(provider, ThreatIntelEnrichmentProvider)


def test_construction_failure_degrades_to_failing_provider(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic construction failure")

    _clear_env(monkeypatch)
    monkeypatch.setenv("ENRICHMENT_PROVIDER", "threat-intel")
    monkeypatch.setattr(main_module, "ThreatIntelClient", _boom)

    with caplog.at_level(logging.WARNING, logger="app.main"):
        provider = main_module.select_enrichment_provider(get_settings())

    assert isinstance(provider, FailingEnrichmentProvider)
    with pytest.raises(EnrichmentUnavailableError):
        provider.enrich(Indicator(type=IndicatorType.IP, value="192.0.2.1", source="test"))
    assert any(getattr(record, "event", None) == "provider_degraded" for record in caplog.records)
