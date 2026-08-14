"""Server-rendered analyst investigation view (no separate frontend build).

Chosen per docs/architecture.md "Frontend technology choice": FastAPI +
Jinja2 templates with a few lines of vanilla JS, reusing the same
`run_alert_workflow` pipeline as the JSON API. This avoids introducing a
Node/npm toolchain or a second CI job for a stage whose purpose is
presentation, not new capability.
"""

from pathlib import Path
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.adapters.crowdstrike import UnsupportedSourceError
from app.models import CrowdStrikeStyleAlert, ProcessingHistoryEntry
from app.services.workflow import run_alert_workflow
from app.web.demo_scenarios import DEMO_SCENARIOS

web_router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

STAGE_LABELS = {
    "received": "Received",
    "validated": "Validated",
    "normalized": "Normalized",
    "indicators_extracted": "Indicators Extracted",
    "enriched": "Enriched",
    "triaged": "Triaged",
    "ai_requested": "AI Requested",
    "ai_received": "AI Received",
    "ai_validated": "AI Validated",
    "ai_rejected": "AI Rejected",
    "ai_unavailable": "AI Unavailable",
    "analyst_review": "Analyst Review",
}
FAILURE_STAGES = {"ai_rejected", "ai_unavailable"}
WARNING_STAGES = {"analyst_review"}


def history_display_rows(history: list[ProcessingHistoryEntry]) -> list[dict[str, object]]:
    """Turn actual processing-history entries into display rows.

    Only stages that genuinely ran appear here - nothing is fabricated for
    presentation purposes.
    """
    rows: list[dict[str, object]] = []
    for entry in history:
        stage_value = entry.stage.value
        if stage_value in FAILURE_STAGES:
            css = "history-fail"
        elif stage_value in WARNING_STAGES:
            css = "history-warn"
        else:
            css = "history-ok"
        rows.append(
            {
                "label": STAGE_LABELS.get(stage_value, stage_value),
                "css": css,
                "context": entry.context,
            }
        )
    return rows


def ai_timeout_from_request(request: Request) -> float:
    return cast(float, request.app.state.ai_timeout_seconds)


@web_router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"scenarios": DEMO_SCENARIOS.values()})


@web_router.get("/demo/{scenario_name}", response_class=HTMLResponse)
async def run_demo_scenario(
    request: Request,
    scenario_name: str,
    ai_timeout_seconds: Annotated[float, Depends(ai_timeout_from_request)],
) -> HTMLResponse:
    scenario = DEMO_SCENARIOS.get(scenario_name)
    if scenario is None:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "message": f"Unknown demo scenario: {scenario_name!r}",
                "scenarios": DEMO_SCENARIOS.values(),
            },
            status_code=404,
        )

    payload = CrowdStrikeStyleAlert.model_validate(scenario.alert_payload)
    enrichment_provider = scenario.make_enrichment_provider()
    investigation_assistant = scenario.make_investigation_assistant()

    try:
        result = await run_alert_workflow(
            payload, enrichment_provider, investigation_assistant, ai_timeout_seconds
        )
    except UnsupportedSourceError as exc:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"message": str(exc), "scenarios": DEMO_SCENARIOS.values()},
            status_code=422,
        )

    return templates.TemplateResponse(
        request,
        "investigation.html",
        {
            "scenario": scenario,
            "result": result,
            "history_rows": history_display_rows(result.processing_history),
        },
    )
