"""Tests for structured logging, alert correlation, degraded-state
observability, and sensitive-data protection.

See docs/operations.md for the full structured-field and event reference
these tests exercise. Failure-path and provider tests use obviously-fake
placeholder secrets (e.g. `sk-fake-test-...`), never realistic-looking
values - see the Secret Handling Protocol in docs/engineering-hardening.md.
"""

import asyncio
import json
import logging
import sys
import types
from datetime import UTC, datetime
from typing import Any

import pytest
from pytest_socket import disable_socket, enable_socket

from app.enrichment.providers import FailingEnrichmentProvider, MockEnrichmentProvider
from app.investigation.assistant import InvestigationUnavailableError
from app.investigation.context import build_investigation_context
from app.investigation.mock import FailingInvestigationAssistant, MockInvestigationAssistant
from app.main import create_app
from app.models import CrowdStrikeStyleAlert, Severity, TriageDecision, TriageResult
from app.models.alert import NormalizedAlert
from app.observability import StructuredFormatter, log_event
from app.services.workflow import run_alert_workflow
from fixtures.alerts import HIGH_RISK_ALERT

FAKE_API_KEY = "sk-fake-test-0000000000"


def _run_async(coro: Any) -> Any:
    """See the identical helper in tests/test_ai_investigation.py for why this exists."""
    enable_socket()
    try:
        return asyncio.run(coro)
    finally:
        disable_socket()


@pytest.fixture
def high_risk_payload() -> CrowdStrikeStyleAlert:
    return CrowdStrikeStyleAlert.model_validate(HIGH_RISK_ALERT)


class _CaptureHandler(logging.Handler):
    """Collects each record rendered through a given formatter."""

    def __init__(self, formatter: logging.Formatter) -> None:
        super().__init__()
        self.setFormatter(formatter)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


# --------------------------------------------------------------------------
# Structured formatter
# --------------------------------------------------------------------------


def test_structured_formatter_emits_valid_json_with_expected_fields() -> None:
    logger = logging.getLogger("test.structured_formatter")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = _CaptureHandler(StructuredFormatter())
    logger.addHandler(handler)
    try:
        log_event(
            logger,
            logging.INFO,
            "Alert received",
            event="alert_received",
            alert_id="ALT-test-1",
            workflow_stage="received",
            duration_ms=12.5,
            review_required=False,
        )
    finally:
        logger.removeHandler(handler)

    assert len(handler.lines) == 1
    payload = json.loads(handler.lines[0])
    assert payload["message"] == "Alert received"
    assert payload["level"] == "INFO"
    assert payload["event"] == "alert_received"
    assert payload["alert_id"] == "ALT-test-1"
    assert payload["workflow_stage"] == "received"
    assert payload["duration_ms"] == 12.5
    assert payload["review_required"] is False
    assert "timestamp" in payload


# --------------------------------------------------------------------------
# Alert correlation across the full workflow
# --------------------------------------------------------------------------


def test_alert_correlation_across_workflow_stages(
    high_risk_payload: CrowdStrikeStyleAlert, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.services.workflow"):
        _run_async(
            run_alert_workflow(
                high_risk_payload,
                MockEnrichmentProvider(),
                MockInvestigationAssistant(),
                8.0,
            )
        )

    events = {
        getattr(record, "event", None): getattr(record, "alert_id", None)
        for record in caplog.records
    }
    expected_alert_id = HIGH_RISK_ALERT["alert_id"]
    for event_name in (
        "alert_received",
        "alert_validated",
        "enrichment_completed",
        "triage_completed",
        "ai_investigation_attempted",
        "ai_investigation_completed",
        "workflow_completed",
    ):
        assert event_name in events, f"missing {event_name!r} event in workflow logs"
        assert events[event_name] == expected_alert_id


def test_workflow_completed_event_reflects_final_outcome(
    high_risk_payload: CrowdStrikeStyleAlert, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.services.workflow"):
        _run_async(
            run_alert_workflow(
                high_risk_payload,
                MockEnrichmentProvider(),
                MockInvestigationAssistant(),
                8.0,
            )
        )
    completed = next(r for r in caplog.records if getattr(r, "event", None) == "workflow_completed")
    assert getattr(completed, "result", None) == "ESCALATE"
    assert getattr(completed, "duration_ms", -1) >= 0
    assert hasattr(completed, "review_required")


# --------------------------------------------------------------------------
# Degraded operation is observable and distinguishable from "no result"
# --------------------------------------------------------------------------


def test_enrichment_degraded_produces_provider_degraded_event(
    high_risk_payload: CrowdStrikeStyleAlert, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="app.services.workflow"):
        _run_async(
            run_alert_workflow(
                high_risk_payload,
                FailingEnrichmentProvider(),
                MockInvestigationAssistant(),
                8.0,
            )
        )
    degraded = [
        record
        for record in caplog.records
        if getattr(record, "event", None) == "provider_degraded"
        and getattr(record, "provider", None) == "enrichment"
    ]
    assert degraded, "expected a provider_degraded event for the enrichment provider"
    assert getattr(degraded[0], "result", None) == "unavailable"
    assert getattr(degraded[0], "alert_id", None) == HIGH_RISK_ALERT["alert_id"]
    assert getattr(degraded[0], "error_type", None) == "EnrichmentUnavailableError"


def test_ai_unavailable_is_degraded_and_forces_analyst_review(
    high_risk_payload: CrowdStrikeStyleAlert, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.services.workflow"):
        _run_async(
            run_alert_workflow(
                high_risk_payload,
                MockEnrichmentProvider(),
                FailingInvestigationAssistant(),
                8.0,
            )
        )
    degraded = [
        record
        for record in caplog.records
        if getattr(record, "event", None) == "provider_degraded"
        and getattr(record, "provider", None) == "FailingInvestigationAssistant"
    ]
    assert degraded, "expected a provider_degraded event for the AI provider"
    assert getattr(degraded[0], "result", None) == "unavailable"

    review_events = [
        record
        for record in caplog.records
        if getattr(record, "event", None) == "analyst_review_required"
    ]
    assert review_events, "expected an analyst_review_required event"
    assert getattr(review_events[0], "review_required", None) is True


# --------------------------------------------------------------------------
# Readiness reflects healthy-but-degraded, never fails outright
# --------------------------------------------------------------------------


def test_readiness_reports_healthy_with_default_mock_provider(client: Any) -> None:
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"] == {"triage": "available", "ai_provider": "available"}


def test_readiness_reports_degraded_when_ai_provider_unavailable(
    client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_PROVIDER", "live")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    degraded_client = type(client)()
    degraded_client.application = create_app()

    response = degraded_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["ai_provider"] == "unavailable"
    assert body["checks"]["triage"] == "available"


def test_liveness_is_unaffected_by_ai_provider_availability(
    client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_PROVIDER", "live")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    degraded_client = type(client)()
    degraded_client.application = create_app()

    response = degraded_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# --------------------------------------------------------------------------
# Sensitive data must never reach the logs, even on provider failure
# --------------------------------------------------------------------------


def test_auth_failure_never_logs_the_configured_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uses an obviously-fake placeholder key, never a realistic-looking one."""
    module = types.ModuleType("anthropic")

    class _FakeAuthError(Exception):
        pass

    class _FakeMessages:
        async def create(self, **kwargs: Any) -> Any:
            raise _FakeAuthError(f"invalid x-api-key header provided: {FAKE_API_KEY}")

    class _FakeAsyncAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            self.messages = _FakeMessages()

    module.AsyncAnthropic = _FakeAsyncAnthropic  # type: ignore[attr-defined]
    module.AuthenticationError = _FakeAuthError  # type: ignore[attr-defined]
    module.PermissionDeniedError = type("_UnusedPermissionDenied", (Exception,), {})  # type: ignore[attr-defined]
    module.RateLimitError = type("_UnusedRateLimit", (Exception,), {})  # type: ignore[attr-defined]
    module.APIConnectionError = type("_UnusedConnection", (Exception,), {})  # type: ignore[attr-defined]
    module.APIStatusError = type("_UnusedStatus", (Exception,), {})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", module)

    from app.investigation.live import AnthropicInvestigationAssistant

    assistant = AnthropicInvestigationAssistant(api_key=FAKE_API_KEY)
    alert = NormalizedAlert(
        source_alert_id="synthetic-logging-test",
        timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
        hostname="workstation-1",
        username="synthetic.user",
        severity=Severity.HIGH,
        detection_description="synthetic",
    )
    triage = TriageResult(
        decision=TriageDecision.ESCALATE,
        rules_triggered=["RULE_A_HIGH_RISK_MALICIOUS"],
        reason="synthetic logging test fixture",
    )
    context = build_investigation_context(alert, [], [], triage)

    root = logging.getLogger()
    handler = _CaptureHandler(StructuredFormatter())
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.WARNING)
    try:
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(context, 5.0))
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    assert handler.lines, "expected at least one log line to be captured"
    for line in handler.lines:
        assert FAKE_API_KEY not in line
