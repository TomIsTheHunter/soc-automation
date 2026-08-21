"""Boundary validation tests for `CrowdStrikeStyleAlert`.

These exercise the model directly (no HTTP layer) to prove that malformed
external input is rejected at the intended boundary - Pydantic validation
of the inbound alert model - rather than failing unpredictably deeper in
the pipeline. `tests/test_api.py` covers the same boundary end-to-end
through the HTTP layer for a representative subset.
"""

from typing import Any

import pytest
from pydantic import ValidationError

from app.models import CrowdStrikeStyleAlert
from fixtures.alerts import HIGH_RISK_ALERT


def _payload(**overrides: Any) -> dict[str, Any]:
    payload = HIGH_RISK_ALERT.copy()
    payload.update(overrides)
    return payload


def test_valid_alert_is_accepted() -> None:
    CrowdStrikeStyleAlert.model_validate(_payload())


def test_missing_alert_id_rejected() -> None:
    payload = _payload()
    del payload["alert_id"]
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(payload)


def test_empty_alert_id_rejected() -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(alert_id=""))


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "2026-01-15T12:00:00",  # naive, no timezone
        "not-a-timestamp",
        "",
    ],
)
def test_invalid_timestamp_rejected(bad_timestamp: str) -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(timestamp=bad_timestamp))


def test_unknown_severity_rejected() -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(severity="SEVERE"))


def test_severity_wrong_type_rejected() -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(severity=5))


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_ip", "not-an-ip"),
        ("destination_ip", "999.999.999.999"),
        ("file_hash", "not-a-hash"),
        ("file_hash", "deadbeef"),  # valid hex but wrong length for SHA-256
    ],
)
def test_incorrect_ioc_type_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(**{field: value}))


def test_empty_file_hash_rejected() -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(file_hash=""))


@pytest.mark.parametrize(
    "field,max_length",
    [
        ("alert_id", 200),
        ("hostname", 255),
        ("username", 255),
        ("detection_description", 10_000),
    ],
)
def test_oversized_field_rejected(field: str, max_length: int) -> None:
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(**{field: "x" * (max_length + 1)}))


def test_unexpected_nested_data_rejected() -> None:
    """Unknown top-level fields (e.g. attacker-supplied extra structure) must be rejected."""
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(unexpected_nested={"a": {"b": ["c", "d"]}}))


def test_wrong_type_for_string_field_rejected() -> None:
    """A nested object where a scalar string is expected must be rejected, not coerced."""
    with pytest.raises(ValidationError):
        CrowdStrikeStyleAlert.model_validate(_payload(hostname={"nested": "value"}))


def test_missing_required_fields_rejected() -> None:
    for field in ("hostname", "username", "severity", "detection_description", "source"):
        payload = _payload()
        del payload[field]
        with pytest.raises(ValidationError):
            CrowdStrikeStyleAlert.model_validate(payload)
