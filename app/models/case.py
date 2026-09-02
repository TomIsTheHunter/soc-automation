"""Normalized case-management model.

Mirrors `EnrichmentResult`/`VulnerabilityContext`: any provider in this
category adapts its own raw response into this one model. Unlike those
two read-only categories, creating a case is a side-effecting write - see
`app/case_management/providers.py` and docs/adr/003-idempotent-writes.md
for why idempotency matters here in a way it never did for a GET-based
lookup.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class CaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    status: CaseStatus
    source: str = "mock-case-management"
