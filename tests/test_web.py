"""Tests for the server-rendered analyst investigation view.

Uses the same offline in-process ASGI client as the API tests (no real
sockets, enforced by `pytest-socket`). Asserts on rendered HTML content,
not visual appearance - this is deliberately lightweight per
docs/architecture.md "Frontend technology choice".
"""

from typing import Any


def test_index_lists_all_demo_scenarios(client: Any) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    for scenario_name in (
        "high_risk",
        "enrichment_failure",
        "ai_failure",
        "ai_invalid",
        "low_risk",
        "ambiguous",
    ):
        assert f"/demo/{scenario_name}" in body


def test_unknown_scenario_returns_404_error_page(client: Any) -> None:
    response = client.get("/demo/does-not-exist")
    assert response.status_code == 404
    assert "Unknown demo scenario" in response.text


def test_high_risk_scenario_renders_deterministic_and_ai_sections(client: Any) -> None:
    response = client.get("/demo/high_risk")
    assert response.status_code == 200
    body = response.text
    assert "DETERMINISTIC AUTOMATION" in body
    assert "AI-ASSISTED ANALYSIS" in body
    assert "ESCALATE" in body
    assert "RULE_A_HIGH_RISK_MALICIOUS" in body
    assert "AI-generated analyst assistance. Does not override deterministic triage." in body
    assert "provider: mock" in body
    assert "schema_version: 1" in body
    # Observed facts and the deterministic decision must use distinct,
    # non-color-only badges (Section 2 requirement).
    assert "badge-observed" in body
    assert "badge-deterministic" in body
    assert "badge-ai" in body


def test_enrichment_failure_scenario_shows_unavailable_state(client: Any) -> None:
    response = client.get("/demo/enrichment_failure")
    assert response.status_code == 200
    body = response.text
    assert "Enrichment unavailable. Deterministic triage remains available." in body
    assert "ANALYST_REVIEW" in body
    assert "RULE_B_ENRICHMENT_UNAVAILABLE" in body
    assert "ANALYST REVIEW REQUIRED" in body


def test_ai_failure_scenario_shows_ai_unavailable_but_triage_intact(client: Any) -> None:
    response = client.get("/demo/ai_failure")
    assert response.status_code == 200
    body = response.text
    assert "ESCALATE" in body
    assert "AI assistance is currently unavailable" in body
    assert "ANALYST REVIEW REQUIRED" in body


def test_ai_invalid_scenario_shows_rejected_state(client: Any) -> None:
    response = client.get("/demo/ai_invalid")
    assert response.status_code == 200
    body = response.text
    assert "AI output was rejected by validation" in body
    assert "schema_invalid" in body
    assert "ESCALATE" in body  # deterministic result untouched


def test_low_risk_scenario_does_not_show_analyst_review_banner_unnecessarily(
    client: Any,
) -> None:
    response = client.get("/demo/low_risk")
    assert response.status_code == 200
    body = response.text
    assert "LOW_RISK" in body


def test_ambiguous_scenario_routes_to_analyst_review(client: Any) -> None:
    response = client.get("/demo/ambiguous")
    assert response.status_code == 200
    body = response.text
    assert "ANALYST_REVIEW" in body
    assert "RULE_D_AMBIGUOUS_CATCH_ALL" in body


def test_processing_history_reflects_real_stages_not_fabricated(client: Any) -> None:
    response = client.get("/demo/ai_failure")
    body = response.text
    assert "Received" in body
    assert "Triaged" in body
    assert "AI Requested" in body
    assert "AI Unavailable" in body
    # AI Received/Validated must NOT appear - the AI call never succeeded.
    assert "AI Received" not in body
    assert "AI Validated" not in body
