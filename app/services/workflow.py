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
from app.services.indicators import extract_indicators
from app.triage.engine import triage_alert

logger = logging.getLogger(__name__)


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
    history = [history_entry(ProcessingStage.RECEIVED)]
    history.append(history_entry(ProcessingStage.VALIDATED))

    normalized = CrowdStrikeStyleAlertAdapter().adapt(payload)
    history.append(
        history_entry(ProcessingStage.NORMALIZED, source_alert_id=normalized.source_alert_id)
    )

    indicators = extract_indicators(normalized)
    history.append(history_entry(ProcessingStage.INDICATORS_EXTRACTED, count=len(indicators)))

    enrichment: list[EnrichmentResult] = []
    enrichment_available = True
    try:
        enrichment = [enrichment_provider.enrich(indicator) for indicator in indicators]
    except EnrichmentUnavailableError:
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
        logger.warning("Enrichment unavailable for alert %s", normalized.source_alert_id)
    except Exception:
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
        logger.exception("Unexpected enrichment failure for alert %s", normalized.source_alert_id)
    history.append(history_entry(ProcessingStage.ENRICHED, available=enrichment_available))

    triage: TriageResult = triage_alert(normalized, enrichment, enrichment_available)
    history.append(history_entry(ProcessingStage.TRIAGED, decision=triage.decision))

    investigation_context = build_investigation_context(normalized, indicators, enrichment, triage)
    history.append(history_entry(ProcessingStage.AI_REQUESTED))

    ai_status = AIStatus.UNAVAILABLE
    ai_result = None
    rejection_reason: str | None = None
    try:
        raw_output = await asyncio.wait_for(
            investigation_assistant.investigate(investigation_context, ai_timeout_seconds),
            timeout=ai_timeout_seconds,
        )
        history.append(history_entry(ProcessingStage.AI_RECEIVED))
        ai_result = validate_investigation_result(raw_output, investigation_context)
        ai_status = AIStatus.AVAILABLE
        history.append(history_entry(ProcessingStage.AI_VALIDATED, confidence=ai_result.confidence))
    except TimeoutError:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="timeout"))
        logger.warning("AI investigation timed out for alert %s", normalized.source_alert_id)
    except InvestigationUnavailableError as exc:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="provider_unavailable"))
        logger.warning(
            "AI investigation provider unavailable for alert %s: %s",
            normalized.source_alert_id,
            exc,
        )
    except InvestigationValidationError as exc:
        ai_status = AIStatus.REJECTED
        rejection_reason = f"{exc.reason.value}: {exc}"
        history.append(history_entry(ProcessingStage.AI_REJECTED, reason=rejection_reason))
        logger.warning(
            "AI investigation output rejected for alert %s: %s",
            normalized.source_alert_id,
            rejection_reason,
        )
    except Exception:
        history.append(history_entry(ProcessingStage.AI_UNAVAILABLE, reason="unexpected_error"))
        logger.exception(
            "Unexpected AI investigation failure for alert %s", normalized.source_alert_id
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

    ai_assisted_analysis = AIAssistedAnalysis(
        status=ai_status,
        result=ai_result,
        rejection_reason=rejection_reason,
        conflicts_with_triage=conflicts_with_triage,
        analyst_review_required=analyst_review_required,
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
