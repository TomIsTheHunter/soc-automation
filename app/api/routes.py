"""Thin FastAPI route for alert ingestion.

Business logic lives in `app.services.workflow.run_alert_workflow`; this
module only wires HTTP concerns (dependency injection, status codes, error
translation) around it.
"""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.adapters.crowdstrike import UnsupportedSourceError
from app.enrichment.providers import EnrichmentProvider, FailingEnrichmentProvider
from app.investigation.assistant import InvestigationAssistant
from app.investigation.mock import FailingInvestigationAssistant
from app.models import CrowdStrikeStyleAlert, ErrorResponse, ProcessingResponse
from app.services.workflow import run_alert_workflow

router = APIRouter(prefix="/api/v1", tags=["alerts"])

# Demo-scenario query parameter. See docs/architecture.md "Demo scenario
# mechanism" - this swaps in the same Stage 1/2 test doubles used by the
# test suite, for exactly one request, via the existing DI seam. The alert
# payload, adapter, triage engine, and response models are unchanged.
SCENARIO_QUERY_PARAM = "scenario"
SCENARIO_ENRICHMENT_FAILURE = "enrichment_failure"
SCENARIO_AI_FAILURE = "ai_failure"


def provider_from_request(request: Request) -> EnrichmentProvider:
    if request.query_params.get(SCENARIO_QUERY_PARAM) == SCENARIO_ENRICHMENT_FAILURE:
        return FailingEnrichmentProvider()
    return cast(EnrichmentProvider, request.app.state.enrichment_provider)


def investigation_assistant_from_request(request: Request) -> InvestigationAssistant:
    if request.query_params.get(SCENARIO_QUERY_PARAM) == SCENARIO_AI_FAILURE:
        return FailingInvestigationAssistant()
    return cast(InvestigationAssistant, request.app.state.investigation_assistant)


def ai_timeout_from_request(request: Request) -> float:
    return cast(float, request.app.state.ai_timeout_seconds)


@router.post(
    "/alerts",
    response_model=ProcessingResponse,
    status_code=status.HTTP_200_OK,
    responses={
        413: {"description": "Request body exceeds the configured limit", "model": ErrorResponse},
        422: {"description": "Validation or unsupported-source error", "model": ErrorResponse},
    },
)
async def ingest_alert(
    payload: CrowdStrikeStyleAlert,
    provider: Annotated[EnrichmentProvider, Depends(provider_from_request)],
    ai_assistant: Annotated[InvestigationAssistant, Depends(investigation_assistant_from_request)],
    ai_timeout_seconds: Annotated[float, Depends(ai_timeout_from_request)],
) -> ProcessingResponse:
    try:
        return await run_alert_workflow(payload, provider, ai_assistant, ai_timeout_seconds)
    except UnsupportedSourceError as exc:
        raise HTTPException(status_code=422, detail="unsupported alert source") from exc
