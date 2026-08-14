"""Named demo scenarios used by the server-rendered analyst view.

Each scenario pairs one existing Stage 1 synthetic fixture with a provider
combination, then runs it through the exact same
`app.services.workflow.run_alert_workflow` pipeline used by the real API
and the test suite. No result is hard-coded here: the fixture, adapter,
triage engine, and response models are identical to the production path -
only the enrichment/AI provider implementation changes, via the same
dependency-injection seam described in docs/architecture.md.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.enrichment.providers import (
    EnrichmentProvider,
    FailingEnrichmentProvider,
    MockEnrichmentProvider,
)
from app.investigation.assistant import InvestigationAssistant
from app.investigation.mock import (
    FailingInvestigationAssistant,
    MalformedInvestigationAssistant,
    MockInvestigationAssistant,
)
from fixtures.alerts import AMBIGUOUS_ALERT, BENIGN_ALERT, HIGH_RISK_ALERT


@dataclass(frozen=True)
class DemoScenario:
    name: str
    title: str
    description: str
    alert_payload: dict[str, Any]
    make_enrichment_provider: Callable[[], EnrichmentProvider]
    make_investigation_assistant: Callable[[], InvestigationAssistant]


def _malformed_ai_output() -> MalformedInvestigationAssistant:
    # Missing required fields - fails schema validation (extra="forbid" and
    # required-field enforcement both apply), demonstrating "invalid AI
    # output" degrading safely rather than being trusted.
    return MalformedInvestigationAssistant({"schema_version": 1, "provider_name": "mock"})


DEMO_SCENARIOS: dict[str, DemoScenario] = {
    "high_risk": DemoScenario(
        name="high_risk",
        title="High-Risk Malicious Alert",
        description=(
            "Malicious enrichment evidence on a HIGH-severity alert causes "
            "deterministic escalation (Rule A); AI provides advisory context."
        ),
        alert_payload=HIGH_RISK_ALERT,
        make_enrichment_provider=MockEnrichmentProvider,
        make_investigation_assistant=MockInvestigationAssistant,
    ),
    "enrichment_failure": DemoScenario(
        name="enrichment_failure",
        title="Enrichment Provider Failure",
        description=(
            "Threat-intelligence enrichment is unavailable; deterministic "
            "triage fails closed to ANALYST_REVIEW (Rule B) rather than "
            "assuming safety."
        ),
        alert_payload=HIGH_RISK_ALERT,
        make_enrichment_provider=FailingEnrichmentProvider,
        make_investigation_assistant=MockInvestigationAssistant,
    ),
    "ai_failure": DemoScenario(
        name="ai_failure",
        title="AI Investigation Provider Failure",
        description=(
            "The AI investigation assistant is unavailable; the "
            "deterministic ESCALATE decision remains fully intact."
        ),
        alert_payload=HIGH_RISK_ALERT,
        make_enrichment_provider=MockEnrichmentProvider,
        make_investigation_assistant=FailingInvestigationAssistant,
    ),
    "ai_invalid": DemoScenario(
        name="ai_invalid",
        title="Invalid AI Output Rejected",
        description=(
            "The AI assistant returns structurally invalid output; schema "
            "validation rejects it before it can reach the analyst as fact."
        ),
        alert_payload=HIGH_RISK_ALERT,
        make_enrichment_provider=MockEnrichmentProvider,
        make_investigation_assistant=_malformed_ai_output,
    ),
    "low_risk": DemoScenario(
        name="low_risk",
        title="Low-Risk Benign Alert",
        description=(
            "Benign enrichment evidence on a LOW-severity alert keeps "
            "deterministic triage at LOW_RISK (Rule C) without AI influence."
        ),
        alert_payload=BENIGN_ALERT,
        make_enrichment_provider=MockEnrichmentProvider,
        make_investigation_assistant=MockInvestigationAssistant,
    ),
    "ambiguous": DemoScenario(
        name="ambiguous",
        title="Ambiguous / Conflicting Signals",
        description=(
            "Mixed severity and enrichment signals match no escalation or "
            "low-risk rule, so the catch-all (Rule D) routes to analyst "
            "review."
        ),
        alert_payload=AMBIGUOUS_ALERT,
        make_enrichment_provider=MockEnrichmentProvider,
        make_investigation_assistant=MockInvestigationAssistant,
    ),
}
