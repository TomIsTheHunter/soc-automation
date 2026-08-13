import logging
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.adapters.crowdstrike import CrowdStrikeStyleAlertAdapter, UnsupportedSourceError
from app.enrichment.providers import (
    EnrichmentProvider,
    EnrichmentUnavailableError,
)
from app.models import (
    Confidence,
    CrowdStrikeStyleAlert,
    EnrichmentResult,
    ProcessingHistoryEntry,
    ProcessingResponse,
    ProcessingStage,
    Reputation,
    TriageResult,
)
from app.services.indicators import extract_indicators
from app.triage.engine import triage_alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["alerts"])


def utc_now() -> datetime:
    return datetime.now(UTC)


def provider_from_request(request: Request) -> EnrichmentProvider:
    return cast(EnrichmentProvider, request.app.state.enrichment_provider)


def history_entry(stage: ProcessingStage, **context: object) -> ProcessingHistoryEntry:
    return ProcessingHistoryEntry(stage=stage, timestamp=utc_now(), context=context)


@router.post(
    "/alerts",
    response_model=ProcessingResponse,
    status_code=status.HTTP_200_OK,
    responses={413: {"description": "Request body exceeds the configured limit"}},
)
def ingest_alert(
    payload: CrowdStrikeStyleAlert,
    provider: Annotated[EnrichmentProvider, Depends(provider_from_request)],
) -> ProcessingResponse:
    history = [history_entry(ProcessingStage.RECEIVED)]
    history.append(history_entry(ProcessingStage.VALIDATED))
    try:
        normalized = CrowdStrikeStyleAlertAdapter().adapt(payload)
    except UnsupportedSourceError as exc:
        raise HTTPException(status_code=422, detail="unsupported alert source") from exc
    history.append(
        history_entry(ProcessingStage.NORMALIZED, source_alert_id=normalized.source_alert_id)
    )

    indicators = extract_indicators(normalized)
    history.append(history_entry(ProcessingStage.INDICATORS_EXTRACTED, count=len(indicators)))

    enrichment: list[EnrichmentResult] = []
    enrichment_available = True
    try:
        enrichment = [provider.enrich(indicator) for indicator in indicators]
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
    return ProcessingResponse(
        alert=normalized,
        indicators=indicators,
        enrichment=enrichment,
        triage=triage,
        processing_history=history,
    )
