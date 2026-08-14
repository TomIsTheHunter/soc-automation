from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IndicatorType(StrEnum):
    IP = "ip"
    HASH = "hash"


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str = Field(min_length=1)
    source: str = Field(min_length=1)


class Reputation(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: Indicator
    reputation: Reputation
    confidence: Confidence
    source: str = "mock-threat-intelligence"
    category: str | None = None
    available: bool = True


class TriageDecision(StrEnum):
    ESCALATE = "ESCALATE"
    ANALYST_REVIEW = "ANALYST_REVIEW"
    LOW_RISK = "LOW_RISK"


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: TriageDecision
    rules_triggered: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProcessingStage(StrEnum):
    RECEIVED = "received"
    VALIDATED = "validated"
    NORMALIZED = "normalized"
    INDICATORS_EXTRACTED = "indicators_extracted"
    ENRICHED = "enriched"
    TRIAGED = "triaged"
    AI_REQUESTED = "ai_requested"
    AI_RECEIVED = "ai_received"
    AI_VALIDATED = "ai_validated"
    AI_REJECTED = "ai_rejected"
    AI_UNAVAILABLE = "ai_unavailable"
    ANALYST_REVIEW = "analyst_review"


class ProcessingHistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: ProcessingStage
    timestamp: datetime
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)
