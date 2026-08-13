from ipaddress import ip_address, ip_network

from app.adapters.crowdstrike import CrowdStrikeStyleAlertAdapter
from app.enrichment.providers import MockEnrichmentProvider
from app.enrichment.table import SYNTHETIC_LOOKUP_TABLE
from app.models import CrowdStrikeStyleAlert, IndicatorType, Reputation
from app.services.indicators import extract_indicators
from app.triage.engine import triage_alert
from fixtures.alerts import AMBIGUOUS_ALERT, BENIGN_ALERT, HIGH_RISK_ALERT


def test_adapter_isolated_from_fastapi() -> None:
    normalized = CrowdStrikeStyleAlertAdapter().adapt(
        CrowdStrikeStyleAlert.model_validate(HIGH_RISK_ALERT)
    )
    assert normalized.source_alert_id == HIGH_RISK_ALERT["alert_id"]
    assert normalized.internal_alert_id is not None
    assert normalized.destination_ip == ip_address("198.51.100.10")


def test_lookup_table_drives_enrichment_and_indicators() -> None:
    alert = CrowdStrikeStyleAlert.model_validate(HIGH_RISK_ALERT)
    normalized = CrowdStrikeStyleAlertAdapter().adapt(alert)
    indicators = extract_indicators(normalized)
    results = [MockEnrichmentProvider().enrich(item) for item in indicators]
    assert any(
        item.indicator.value == "198.51.100.10" and item.reputation == Reputation.MALICIOUS
        for item in results
    )
    assert all(
        item.indicator.value in SYNTHETIC_LOOKUP_TABLE
        for item in results
        if item.indicator.value in SYNTHETIC_LOOKUP_TABLE
    )
    assert any(item.type == IndicatorType.HASH for item in indicators)


def test_rule_precedence_and_catch_all() -> None:
    normalized = CrowdStrikeStyleAlertAdapter().adapt(
        CrowdStrikeStyleAlert.model_validate(HIGH_RISK_ALERT)
    )
    result = triage_alert(normalized, [], enrichment_available=False)
    assert result.decision == "ANALYST_REVIEW"
    assert result.rules_triggered == ["RULE_B_ENRICHMENT_UNAVAILABLE"]

    ambiguous = CrowdStrikeStyleAlertAdapter().adapt(
        CrowdStrikeStyleAlert.model_validate(AMBIGUOUS_ALERT)
    )
    result = triage_alert(
        ambiguous,
        [MockEnrichmentProvider().enrich(item) for item in extract_indicators(ambiguous)],
        True,
    )
    assert result.decision == "ANALYST_REVIEW"
    assert result.rules_triggered == ["RULE_D_AMBIGUOUS_CATCH_ALL"]


def test_all_fixture_ips_are_rfc5737() -> None:
    documentation_ranges = [
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
        ip_network("203.0.113.0/24"),
    ]
    for fixture in (HIGH_RISK_ALERT, BENIGN_ALERT, AMBIGUOUS_ALERT):
        for field in ("source_ip", "destination_ip"):
            address = ip_address(str(fixture[field]))
            assert any(address in network for network in documentation_ranges)


def test_naive_timestamp_rejected() -> None:
    payload = HIGH_RISK_ALERT.copy()
    payload["timestamp"] = "2026-01-15T12:00:00"
    try:
        CrowdStrikeStyleAlert.model_validate(payload)
    except ValueError:
        return
    raise AssertionError("naive timestamp was accepted")
