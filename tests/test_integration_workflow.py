"""Single integration test exercising the complete Stage 1 + Stage 2 pipeline.

synthetic alert -> API -> normalization -> enrichment -> triage
-> AI assistance -> validation -> final structured result

Uses only mock providers (no external APIs); runs fully offline under
`pytest-socket`. Individual units are already covered by
tests/test_services.py and tests/test_ai_investigation.py - this test
verifies the pieces are wired together correctly end to end, asserting on
each stage boundary rather than only the final response.
"""

from typing import Any

from app.enrichment.table import SYNTHETIC_LOOKUP_TABLE
from fixtures.alerts import HIGH_RISK_ALERT


def test_complete_workflow_end_to_end(client: Any) -> None:
    response = client.post("/api/v1/alerts", json=HIGH_RISK_ALERT)
    assert response.status_code == 200
    body = response.json()

    # 1. Normalization: source ID preserved, internal ID generated.
    assert body["alert"]["source_alert_id"] == HIGH_RISK_ALERT["alert_id"]
    assert body["alert"]["internal_alert_id"]
    assert body["alert"]["severity"] == "HIGH"

    # 2. Indicator extraction: IP + hash indicators present with context.
    indicator_values = {item["value"] for item in body["indicators"]}
    assert HIGH_RISK_ALERT["destination_ip"] in indicator_values
    assert HIGH_RISK_ALERT["file_hash"] in indicator_values
    assert {item["source"] for item in body["indicators"]} >= {
        "source_ip",
        "destination_ip",
        "file_hash",
    }

    # 3. Enrichment: matches the documented, fixed lookup table exactly.
    destination_enrichment = next(
        item
        for item in body["enrichment"]
        if item["indicator"]["value"] == HIGH_RISK_ALERT["destination_ip"]
    )
    expected = SYNTHETIC_LOOKUP_TABLE[str(HIGH_RISK_ALERT["destination_ip"])]
    assert destination_enrichment["reputation"] == expected.reputation.value
    assert destination_enrichment["confidence"] == expected.confidence.value
    assert destination_enrichment["category"] == expected.category

    # 4. Deterministic triage: authoritative escalation via Rule A.
    assert body["triage"]["decision"] == "ESCALATE"
    assert body["triage"]["rules_triggered"] == ["RULE_A_HIGH_RISK_MALICIOUS"]
    assert body["triage"]["reason"]

    # 5. AI-assisted investigation: validated structured output, advisory only.
    analysis = body["ai_assisted_analysis"]
    assert analysis["status"] == "available"
    assert analysis["decision_authority"] == "DETERMINISTIC"
    assert analysis["conflicts_with_triage"] is False
    ai_result = analysis["result"]
    assert ai_result["provider_name"] == "mock"
    assert ai_result["risk_assessment"] == "HIGH"
    assert ai_result["confidence"] == "HIGH"
    assert any(
        HIGH_RISK_ALERT["destination_ip"] in evidence for evidence in ai_result["key_evidence"]
    )

    # 6. AI output never changes the authoritative decision.
    assert body["triage"]["decision"] == "ESCALATE"

    # 7. Processing history is complete and ordered.
    stages = [entry["stage"] for entry in body["processing_history"]]
    assert stages == [
        "received",
        "validated",
        "normalized",
        "indicators_extracted",
        "enriched",
        "triaged",
        "ai_requested",
        "ai_received",
        "ai_validated",
    ]
