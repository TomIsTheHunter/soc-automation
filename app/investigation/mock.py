"""Deterministic mock AI provider and test-double assistants.

`MockInvestigationAssistant` is REQUIRED: CI and the full test suite must
work without any API key, network access, or external LLM. It is driven by
the fixed, documented lookup table in app/investigation/table.py.

The other classes in this module are lightweight test doubles that make it
possible to exercise every Stage 2 failure path (unavailable, slow/timeout,
malformed, policy-violating, ungrounded evidence) without any external
service, mirroring the Stage 1 `FailingEnrichmentProvider` pattern.
"""

import asyncio
from typing import Any

from app.investigation.assistant import InvestigationAssistant, InvestigationUnavailableError
from app.investigation.table import lookup_mock_entry
from app.models import (
    INVESTIGATION_RESULT_SCHEMA_VERSION,
    AIRiskAssessment,
    InvestigationContext,
    RecommendedAction,
)

MOCK_PROVIDER_NAME = "mock"


def _build_key_evidence(context: InvestigationContext) -> list[str]:
    evidence = [
        f"hostname={context.alert.hostname}",
        f"username={context.alert.username}",
    ]
    for indicator in context.indicators:
        evidence.append(f"{indicator.type.value}={indicator.value} (source={indicator.source})")
    return evidence[:10]


def _build_summary(context: InvestigationContext, risk_assessment: AIRiskAssessment) -> str:
    return (
        f"Deterministic triage returned {context.deterministic_triage.decision.value} for host "
        f"{context.alert.hostname} (severity {context.alert.severity.value}). The fixed mock "
        f"lookup table assesses this combination as {risk_assessment.value} risk."
    )


def _build_recommended_actions(
    context: InvestigationContext,
) -> list[RecommendedAction]:
    decision = context.deterministic_triage.decision.value
    if decision == "ESCALATE":
        return [
            RecommendedAction.REVIEW_PROCESS_TREE,
            RecommendedAction.INSPECT_NETWORK_CONNECTIONS,
            RecommendedAction.ESCALATE_TO_SENIOR_ANALYST,
        ]
    if decision == "ANALYST_REVIEW":
        return [
            RecommendedAction.REVIEW_PROCESS_TREE,
            RecommendedAction.CHECK_RELATED_ALERTS,
        ]
    return [RecommendedAction.NO_FURTHER_ACTION_RECOMMENDED]


def _build_uncertainties(context: InvestigationContext) -> list[str]:
    if any(not item.available for item in context.enrichment):
        return ["Enrichment data was unavailable at analysis time."]
    if not context.enrichment:
        return ["No indicators were available to enrich."]
    return []


class MockInvestigationAssistant(InvestigationAssistant):
    """Deterministic, offline, table-driven investigation assistant."""

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        entry = lookup_mock_entry(
            context.deterministic_triage.decision, context.alert.severity, context.enrichment
        )
        return {
            "schema_version": INVESTIGATION_RESULT_SCHEMA_VERSION,
            "provider_name": MOCK_PROVIDER_NAME,
            "summary": _build_summary(context, entry.risk_assessment),
            "key_evidence": _build_key_evidence(context),
            "risk_assessment": entry.risk_assessment.value,
            "recommended_actions": [action.value for action in _build_recommended_actions(context)],
            "confidence": entry.confidence.value,
            "uncertainties": _build_uncertainties(context),
        }


class FailingInvestigationAssistant(InvestigationAssistant):
    """Test double: always unavailable."""

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        raise InvestigationUnavailableError("synthetic investigation provider unavailable")


class SlowInvestigationAssistant(InvestigationAssistant):
    """Test double: ignores the requested timeout to prove call-site enforcement."""

    def __init__(self, delay_seconds: float = 60.0) -> None:
        self._delay_seconds = delay_seconds

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        await asyncio.sleep(self._delay_seconds)
        return {
            "schema_version": INVESTIGATION_RESULT_SCHEMA_VERSION,
            "provider_name": MOCK_PROVIDER_NAME,
            "summary": "should never be reached",
            "key_evidence": [],
            "risk_assessment": "LOW",
            "recommended_actions": ["no_further_action_recommended"],
            "confidence": "LOW",
            "uncertainties": [],
        }


class MalformedInvestigationAssistant(InvestigationAssistant):
    """Test double: returns raw output that fails schema validation."""

    def __init__(self, raw_output: dict[str, Any]) -> None:
        self._raw_output = raw_output

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        return self._raw_output


class PolicyViolatingInvestigationAssistant(InvestigationAssistant):
    """Test double: schema-valid output containing a prohibited-action keyword."""

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        return {
            "schema_version": INVESTIGATION_RESULT_SCHEMA_VERSION,
            "provider_name": MOCK_PROVIDER_NAME,
            "summary": f"Recommend isolate host {context.alert.hostname} immediately.",
            "key_evidence": [f"hostname={context.alert.hostname}"],
            "risk_assessment": "HIGH",
            "recommended_actions": ["escalate_to_senior_analyst"],
            "confidence": "HIGH",
            "uncertainties": [],
        }


class UngroundedEvidenceInvestigationAssistant(InvestigationAssistant):
    """Test double: schema-valid output whose evidence references unrelated data."""

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        return {
            "schema_version": INVESTIGATION_RESULT_SCHEMA_VERSION,
            "provider_name": MOCK_PROVIDER_NAME,
            "summary": "Investigation summary based on supplied evidence.",
            "key_evidence": ["destination_ip=203.0.113.250 observed in unrelated feed"],
            "risk_assessment": "HIGH",
            "recommended_actions": ["escalate_to_senior_analyst"],
            "confidence": "HIGH",
            "uncertainties": [],
        }
