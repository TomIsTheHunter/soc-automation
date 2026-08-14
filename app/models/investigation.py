"""AI-assisted investigation contracts.

These models define the strict, machine-validated boundary between the
deterministic Stage 1 workflow and the bounded AI investigation assistant
introduced in Stage 2. The AI is advisory only: `ProcessingResponse` keeps the
deterministic `triage` result as the single authoritative decision and adds
`ai_assisted_analysis` as a clearly separated, non-authoritative field.
"""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import NormalizedAlert, Severity
from app.models.workflow import (
    EnrichmentResult,
    Indicator,
    ProcessingHistoryEntry,
    TriageDecision,
    TriageResult,
)

INVESTIGATION_RESULT_SCHEMA_VERSION = 1


class AIConfidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AIRiskAssessment(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNCERTAIN = "UNCERTAIN"


class RecommendedAction(StrEnum):
    """Controlled, investigation-oriented vocabulary.

    Constraining this to an enum makes most prohibited ("close alert",
    "isolate host", ...) actions structurally impossible to express, which is
    the first of the two policy-validation layers described in
    docs/ai-security-design.md.
    """

    REVIEW_PROCESS_TREE = "review_process_tree"
    CHECK_RELATED_ALERTS = "check_related_alerts"
    INSPECT_NETWORK_CONNECTIONS = "inspect_network_connections"
    REVIEW_USER_ACTIVITY_HISTORY = "review_user_activity_history"
    CORRELATE_WITH_OTHER_HOSTS = "correlate_with_other_hosts"
    ESCALATE_TO_SENIOR_ANALYST = "escalate_to_senior_analyst"
    NO_FURTHER_ACTION_RECOMMENDED = "no_further_action_recommended"


class InvestigationResult(BaseModel):
    """Strict AI output contract. Unknown fields are rejected, not stripped."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int
    provider_name: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=2000)
    key_evidence: list[str] = Field(default_factory=list, max_length=20)
    risk_assessment: AIRiskAssessment
    recommended_actions: list[RecommendedAction] = Field(min_length=1, max_length=10)
    confidence: AIConfidence
    uncertainties: list[str] = Field(default_factory=list, max_length=20)


class InvestigationAlertContext(BaseModel):
    """Explicit allowlist of alert fields the AI is permitted to see.

    Deliberately excludes raw source metadata and any field not needed for
    investigation assistance (data minimization). See
    docs/ai-security-design.md for the documented rationale.
    """

    model_config = ConfigDict(extra="forbid")

    internal_alert_id: UUID
    timestamp: datetime
    hostname: str
    username: str
    severity: Severity
    detection_description: str
    process_name: str | None = None
    command_line: str | None = None


class DeterministicTriageContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: TriageDecision
    rules_triggered: list[str]
    reason: str


class InvestigationContext(BaseModel):
    """The complete, trusted, minimized input given to the AI assistant.

    This is constructed exclusively from internal application structures
    (never the raw HTTP request body), which is the boundary documented in
    docs/ai-security-design.md.
    """

    model_config = ConfigDict(extra="forbid")

    alert: InvestigationAlertContext
    indicators: list[Indicator]
    enrichment: list[EnrichmentResult]
    deterministic_triage: DeterministicTriageContext


class AIStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"


class AIAssistedAnalysis(BaseModel):
    """Non-authoritative AI assistance, clearly separated from `triage`."""

    model_config = ConfigDict(extra="forbid")

    status: AIStatus
    result: InvestigationResult | None = None
    rejection_reason: str | None = None
    decision_authority: Literal["DETERMINISTIC"] = "DETERMINISTIC"
    conflicts_with_triage: bool = False
    analyst_review_required: bool = False


class ProcessingResponse(BaseModel):
    """The complete Stage 1 + Stage 2 structured processing result.

    `triage` (deterministic) remains authoritative. `ai_assisted_analysis` is
    always advisory and can never change `triage.decision`.
    """

    model_config = ConfigDict(extra="forbid")

    alert: NormalizedAlert
    indicators: list[Indicator]
    enrichment: list[EnrichmentResult]
    triage: TriageResult
    ai_assisted_analysis: AIAssistedAnalysis
    processing_history: list[ProcessingHistoryEntry] = Field(min_length=1)
