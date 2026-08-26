"""The complete Stage 1 + Stage 2 alert-processing pipeline.

This is the single source of truth for
`validate -> adapt -> normalize -> extract -> enrich -> triage -> investigate
-> validate AI output`. Both the JSON API route
(`app/api/routes.py`) and the server-rendered demo view
(`app/web/routes.py`) call this function so the demo can never drift from
the real, tested pipeline.
"""

import asyncio
import logging
import time
from datetime import UTC, datetime

from app.adapters.crowdstrike import CrowdStrikeStyleAlertAdapter, UnsupportedSourceError
from app.enrichment.providers import EnrichmentProvider, EnrichmentUnavailableError
from app.investigation.assistant import InvestigationAssistant, InvestigationUnavailableError
from app.investigation.context import build_investigation_context
from app.investigation.validation import InvestigationValidationError, validate_investigation_result
from app.models import (
    AIAssistedAnalysis,
    AIConfidence,
    AIRiskAssessment,
    AIStatus,
    Confidence,
    CrowdStrikeStyleAlert,
    EnrichmentResult,
    ProcessingHistoryEntry,
    ProcessingResponse,
    ProcessingStage,
    Reputation,
    TriageDecision,
    TriageResult,
)
from app.observability import log_event
from app.services.indicators import extract_indicators
from app.triage.engine import triage_alert

logger = logging.getLogger(__name__)


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def utc_now() -> datetime:
    return datetime.now(UTC)


def history_entry(stage: ProcessingStage, **context: object) -> ProcessingHistoryEntry:
    return ProcessingHistoryEntry(stage=stage, timestamp=utc_now(), context=context)


def ai_conflicts_with_triage(decision: TriageDecision, risk_assessment: AIRiskAssessment) -> bool:
    """Detect (never resolve) disagreement between the AI and deterministic triage.

    The deterministic decision always remains authoritative; this only makes
    a detected conflict visible to the analyst.
    """
    if decision == TriageDecision.ESCALATE and risk_assessment in {
        AIRiskAssessment.LOW,
        AIRiskAssessment.MEDIUM,
    }:
        return True
    if decision == TriageDecision.LOW_RISK and risk_assessment == AIRiskAssessment.HIGH:
        return True
    return False


async def run_alert_workflow(
    payload: CrowdStrikeStyleAlert,
    enrichment_provider: EnrichmentProvider,
    investigation_assistant: InvestigationAssistant,
    ai_timeout_seconds: float,
) -> ProcessingResponse:
    """Run the complete Stage 1 + Stage 2 pipeline for one synthetic alert.

    Raises `UnsupportedSourceError` if the source adapter rejects the
    payload; callers translate that into their own error presentation
    (HTTP 422 for the API, an error page for the demo view).
    """
    workflow_started = time.perf_counter()
    log_event(
        logger,
        logging.INFO,
        "Alert received",
        event="alert_received",
        alert_id=payload.alert_id,
        workflow_stage=ProcessingStage.RECEIVED.value,
    )
    history = [history_entry(ProcessingStage.RECEIVED)]
    history.append(history_entry(ProcessingStage.VALIDATED))

    normalized = CrowdStrikeStyleAlertAdapter().adapt(payload)
    alert_id = normalized.source_alert_id
    history.append(history_entry(ProcessingStage.NORMALIZED, source_alert_id=alert_id))
    log_event(
        logger,
        logging.INFO,
        "Alert validated and normalized",
        event="alert_validated",
        alert_id=alert_id,
        workflow_stage=ProcessingStage.NORMALIZED.value,
    )

    indicators = extract_indicators(normalized)
    history.append(history_entry(ProcessingStage.INDICATORS_EXTRACTED, count=len(indicators)))

    enrichment: list[EnrichmentResult] = []
    enrichment_available = True
    enrichment_started = time.perf_counter()
    try:
        enrichment = [enrichment_provider.enrich(indicator) for indicator in indicators]
    except EnrichmentUnavailableError as exc:
        enrichment_available = False
        enrichment = [
            EnrichmentResult(
                indicator=indicator,
                reputation=Reputation.UNKNOWN,
                confidence=Confidence.LOW,
                source="unavailable",
                available=False,
            )
            for indicator in indicators
        ]
        log_event(
            logger,
            logging.WARNING,
            f"Enrichment unavailable for alert {alert_id}",
            event="provider_degraded",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.ENRICHED.value,
            provider="enrichment",
            result="unavailable",
            error_type=type(exc).__name__,
            duration_ms=_elapsed_ms(enrichment_started),
        )
    except Exception as exc:
        enrichment_available = False
        enrichment = [
            EnrichmentResult(
                indicator=indicator,
                reputation=Reputation.UNKNOWN,
                confidence=Confidence.LOW,
                source="unavailable",
                available=False,
            )
            for indicator in indicators
        ]
        log_event(
            logger,
            logging.ERROR,
            f"Unexpected enrichment failure for alert {alert_id}",
            event="provider_degraded",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.ENRICHED.value,
            provider="enrichment",
            result="error",
            error_type=type(exc).__name__,
            duration_ms=_elapsed_ms(enrichment_started),
            exc_info=True,
        )
    else:
        log_event(
            logger,
            logging.INFO,
            "Enrichment completed",
            event="enrichment_completed",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.ENRICHED.value,
            provider="enrichment",
            result="success",
            duration_ms=_elapsed_ms(enrichment_started),
        )
    history.append(history_entry(ProcessingStage.ENRICHED, available=enrichment_available))

    triage: TriageResult = triage_alert(normalized, enrichment, enrichment_available)
    history.append(history_entry(ProcessingStage.TRIAGED, decision=triage.decision))
    log_event(
        logger,
        logging.INFO,
        "Triage completed",
        event="triage_completed",
        alert_id=alert_id,
        workflow_stage=ProcessingStage.TRIAGED.value,
        result=triage.decision.value,
    )

    investigation_context = build_investigation_context(normalized, indicators, enrichment, triage)
    history.append(history_entry(ProcessingStage.AI_REQUESTED))
    provider_name = type(investigation_assistant).__name__
    log_event(
        logger,
        logging.INFO,
        "AI investigation attempted",
        event="ai_investigation_attempted",
        alert_id=alert_id,
        workflow_stage=ProcessingStage.AI_REQUESTED.value,
        provider=provider_name,
    )

    ai_status = AIStatus.UNAVAILABLE
    ai_result = None
    rejection_reason: str | None = None
    ai_started = time.perf_counter()
    try:
        raw_output = await asyncio.wait_for(
            investigation_assistant.investigate(investigation_context, ai_timeout_seconds),
            timeout=ai_timeout_seconds,
        )
        history.append(history_entry(ProcessingStage.AI_RECEIVED))
        ai_result = validate_investigation_result(raw_output, investigation_context)
        ai_status = AIStatus.AVAILABLE
        history.append(history_entry(ProcessingStage.AI_VALIDATED, confidence=ai_result.confidence))
        log_event(
            logger,
            logging.INFO,
            "AI investigation completed",
            event="ai_investigation_completed",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.AI_VALIDATED.value,
            provider=provider_name,
            result="available",
            duration_ms=_elapsed_ms(ai_started),
        )
    except TimeoutError:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="timeout"))
        log_event(
            logger,
            logging.WARNING,
            f"AI investigation timed out for alert {alert_id}",
            event="provider_degraded",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.AI_UNAVAILABLE.value,
            provider=provider_name,
            result="timeout",
            error_type="TimeoutError",
            duration_ms=_elapsed_ms(ai_started),
        )
    except InvestigationUnavailableError as exc:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="provider_unavailable"))
        log_event(
            logger,
            logging.WARNING,
            f"AI investigation provider unavailable for alert {alert_id}",
            event="provider_degraded",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.AI_UNAVAILABLE.value,
            provider=provider_name,
            result="unavailable",
            error_type=type(exc).__name__,
            duration_ms=_elapsed_ms(ai_started),
        )
    except InvestigationValidationError as exc:
        ai_status = AIStatus.REJECTED
        rejection_reason = f"{exc.reason.value}: {exc}"
        history.append(history_entry(ProcessingStage.AI_REJECTED, reason=rejection_reason))
        log_event(
            logger,
            logging.WARNING,
            f"AI investigation output rejected for alert {alert_id}",
            event="ai_investigation_rejected",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.AI_REJECTED.value,
            provider=provider_name,
            result="rejected",
            error_type=exc.reason.value,
            duration_ms=_elapsed_ms(ai_started),
        )
    except Exception as exc:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="unexpected_error"))
        log_event(
            logger,
            logging.ERROR,
            f"Unexpected AI investigation failure for alert {alert_id}",
            event="ai_investigation_failed",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.AI_UNAVAILABLE.value,
            provider=provider_name,
            result="error",
            error_type=type(exc).__name__,
            duration_ms=_elapsed_ms(ai_started),
            exc_info=True,
        )

    conflicts_with_triage = (
        ai_status == AIStatus.AVAILABLE
        and ai_result is not None
        and (ai_conflicts_with_triage(triage.decision, ai_result.risk_assessment))
    )
    low_confidence = (
        ai_status == AIStatus.AVAILABLE
        and ai_result is not None
        and ai_result.confidence == AIConfidence.LOW
    )
    analyst_review_required = (
        ai_status != AIStatus.AVAILABLE or conflicts_with_triage or low_confidence
    )
    if analyst_review_required:
        history.append(
            history_entry(
                ProcessingStage.ANALYST_REVIEW,
                ai_status=ai_status,
                conflicts_with_triage=conflicts_with_triage,
            )
        )
        log_event(
            logger,
            logging.INFO,
            "Analyst review required",
            event="analyst_review_required",
            alert_id=alert_id,
            workflow_stage=ProcessingStage.ANALYST_REVIEW.value,
            result=ai_status.value,
            review_required=True,
        )

    ai_assisted_analysis = AIAssistedAnalysis(
        status=ai_status,
        result=ai_result,
        rejection_reason=rejection_reason,
        conflicts_with_triage=conflicts_with_triage,
        analyst_review_required=analyst_review_required,
    )

    log_event(
        logger,
        logging.INFO,
        "Alert workflow completed",
        event="workflow_completed",
        alert_id=alert_id,
        workflow_stage="completed",
        result=triage.decision.value,
        review_required=analyst_review_required,
        duration_ms=_elapsed_ms(workflow_started),
    )

    return ProcessingResponse(
        alert=normalized,
        indicators=indicators,
        enrichment=enrichment,
        triage=triage,
        ai_assisted_analysis=ai_assisted_analysis,
        processing_history=history,
    )


__all__ = ["run_alert_workflow", "UnsupportedSourceError"]
