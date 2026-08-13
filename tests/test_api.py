from typing import Any

from app.enrichment.providers import FailingEnrichmentProvider
from app.main import create_app


def test_health_and_high_risk_workflow(client: Any, high_risk_alert: dict[str, object]) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    response = client.post("/api/v1/alerts", json=high_risk_alert)
    body = response.json()
    assert response.status_code == 200
    assert body["alert"]["source_alert_id"] == "synthetic-high-001"
    assert body["triage"]["decision"] == "ESCALATE"
    assert body["triage"]["rules_triggered"] == ["RULE_A_HIGH_RISK_MALICIOUS"]
    assert [entry["stage"] for entry in body["processing_history"]] == [
        "received",
        "validated",
        "normalized",
        "indicators_extracted",
        "enriched",
        "triaged",
    ]


def test_benign_and_ambiguous_fixtures(
    client: Any, benign_alert: dict[str, object], ambiguous_alert: dict[str, object]
) -> None:
    assert (
        client.post("/api/v1/alerts", json=benign_alert).json()["triage"]["decision"] == "LOW_RISK"
    )
    assert (
        client.post("/api/v1/alerts", json=ambiguous_alert).json()["triage"]["decision"]
        == "ANALYST_REVIEW"
    )


def test_enrichment_failure_fails_closed(client: Any, high_risk_alert: dict[str, object]) -> None:
    failing_client = type(client)()
    failing_client.application = create_app(FailingEnrichmentProvider())
    response = failing_client.post("/api/v1/alerts", json=high_risk_alert)
    body = response.json()
    assert response.status_code == 200
    assert body["triage"]["decision"] == "ANALYST_REVIEW"
    assert body["triage"]["rules_triggered"] == ["RULE_B_ENRICHMENT_UNAVAILABLE"]
    assert all(item["available"] is False for item in body["enrichment"])
    assert body["indicators"]


def test_validation_errors_are_structured_and_do_not_leak_details(
    client: Any, high_risk_alert: dict[str, object]
) -> None:
    missing = high_risk_alert.copy()
    del missing["hostname"]
    response = client.post("/api/v1/alerts", json=missing)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "Traceback" not in response.text
    assert "site-packages" not in response.text


def test_invalid_values_and_unsupported_source(
    client: Any, high_risk_alert: dict[str, object]
) -> None:
    invalid = high_risk_alert.copy()
    invalid["severity"] = "SEVERE"
    assert client.post("/api/v1/alerts", json=invalid).status_code == 422
    invalid["severity"] = "HIGH"
    invalid["destination_ip"] = "not-an-ip"
    assert client.post("/api/v1/alerts", json=invalid).status_code == 422
    invalid["destination_ip"] = "203.0.113.10"
    invalid["source"] = "unsupported"
    response = client.post("/api/v1/alerts", json=invalid)
    assert response.status_code == 422
    assert response.json()["error"]["message"] == "unsupported alert source"


def test_malformed_and_oversized_payloads(client: Any, high_risk_alert: dict[str, object]) -> None:
    malformed = client.post(
        "/api/v1/alerts", content=b"{not-json", headers={"content-type": "application/json"}
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "validation_error"
    oversized = client.post(
        "/api/v1/alerts",
        content=b"x" * (256 * 1024 + 1),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "request_too_large"
