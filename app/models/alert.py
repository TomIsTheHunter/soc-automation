from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

IPAddress = IPv4Address | IPv6Address


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


HIGH_RISK_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


class CrowdStrikeStyleAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    severity: Severity
    process_name: str | None = Field(default=None, max_length=255)
    command_line: str | None = Field(default=None, max_length=10_000)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    file_hash: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    detection_description: str = Field(min_length=1, max_length=10_000)
    source: str = Field(min_length=1, max_length=100)

    @field_validator("timestamp")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internal_alert_id: UUID = Field(default_factory=uuid4)
    source_alert_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    severity: Severity
    detection_description: str = Field(min_length=1, max_length=10_000)
    process_name: str | None = Field(default=None, max_length=255)
    command_line: str | None = Field(default=None, max_length=10_000)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    file_hash: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    source_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)
