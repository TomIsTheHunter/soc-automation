"""Inbound webhook payload from the IncidentDesk case-management vendor.

Mirrors `CrowdStrikeStyleAlert`'s validation conventions (`extra="forbid"`,
UTC-aware timestamp). This is the one *inbound* (vendor -> platform)
boundary in the integration layer - every other provider category is
outbound (platform -> vendor). See docs/adr/004-webhook-ingestion.md.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.case import CaseStatus


class IncidentDeskWebhookEvent(StrEnum):
    CASE_UPDATED = "case.updated"
    CASE_CLOSED = "case.closed"


class IncidentDeskWebhookPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_id: str = Field(min_length=1, max_length=200)
    event: IncidentDeskWebhookEvent
    case_id: str = Field(min_length=1, max_length=200)
    status: CaseStatus
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)
