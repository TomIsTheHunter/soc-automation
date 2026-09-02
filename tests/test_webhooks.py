"""Tests for inbound IncidentDesk webhook ingestion (`app/api/webhooks.py`).

Uses the default mock `INCIDENT_DESK_WEBHOOK_SECRET` (the `client` fixture
builds a fresh app with default `Settings` per test). See
docs/adr/004-webhook-ingestion.md for the security model these tests
verify: HMAC signature verification, fail-closed behavior, and bounded
duplicate-delivery detection.
"""

import hashlib
import hmac
import json
import logging
from typing import Any

import pytest

from app.config import DEFAULT_INCIDENT_DESK_WEBHOOK_SECRET

URL = "/api/v1/webhooks/incident-desk"
SIGNATURE_HEADER = "X-Incident-Desk-Signature"

VALID_PAYLOAD: dict[str, object] = {
    "delivery_id": "delivery-001",
    "event": "case.updated",
    "case_id": "CASE-1",
    "status": "open",
    "occurred_at": "2026-01-15T12:00:00Z",
}


def _body(payload: dict[str, object] = VALID_PAYLOAD) -> bytes:
    return json.dumps(payload).encode("utf-8")


def _sign(body: bytes, secret: str = DEFAULT_INCIDENT_DESK_WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post(client: Any, body: bytes, signature: str | None) -> Any:
    headers = {"content-type": "application/json"}
    if signature is not None:
        headers[SIGNATURE_HEADER] = signature
    return client.post(URL, content=body, headers=headers)


def test_valid_signature_and_payload_is_accepted(client: Any) -> None:
    body = _body()
    response = _post(client, body, _sign(body))
    assert response.status_code == 200
    assert response.json() == {"status": "received"}


def test_missing_signature_header_is_rejected(client: Any) -> None:
    body = _body()
    response = _post(client, body, signature=None)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_signature"


def test_invalid_signature_is_rejected(client: Any) -> None:
    body = _body()
    response = _post(client, body, "sha256=" + "0" * 64)
    assert response.status_code == 401


def test_signature_computed_with_the_wrong_secret_is_rejected(client: Any) -> None:
    body = _body()
    response = _post(client, body, _sign(body, secret="wrong-secret"))
    assert response.status_code == 401


def test_tampered_payload_after_signing_is_rejected(client: Any) -> None:
    signed_body = _body()
    signature = _sign(signed_body)
    tampered_body = _body({**VALID_PAYLOAD, "case_id": "CASE-9999"})
    response = _post(client, tampered_body, signature)
    assert response.status_code == 401


def test_malformed_signature_header_is_rejected(client: Any) -> None:
    body = _body()
    response = _post(client, body, "not-the-right-format")
    assert response.status_code == 401


@pytest.mark.parametrize(
    "invalid_payload",
    [
        {**VALID_PAYLOAD, "event": "case.deleted"},  # not in the controlled vocabulary
        {**VALID_PAYLOAD, "status": "archived"},  # not a valid CaseStatus
        {k: v for k, v in VALID_PAYLOAD.items() if k != "case_id"},  # missing required field
        {**VALID_PAYLOAD, "occurred_at": "2026-01-15T12:00:00"},  # naive timestamp
        {**VALID_PAYLOAD, "unexpected_field": "value"},  # extra="forbid"
    ],
)
def test_invalid_payload_schema_is_rejected(
    client: Any, invalid_payload: dict[str, object]
) -> None:
    body = _body(invalid_payload)
    response = _post(client, body, _sign(body))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_oversized_payload_is_rejected(client: Any) -> None:
    oversized = _body() + b" " * (16 * 1024 + 1)
    response = _post(client, oversized, _sign(oversized))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_duplicate_delivery_is_ignored_but_still_acknowledged(client: Any) -> None:
    body = _body()
    signature = _sign(body)
    first = _post(client, body, signature)
    second = _post(client, body, signature)
    assert first.status_code == 200
    assert first.json() == {"status": "received"}
    assert second.status_code == 200
    assert second.json() == {"status": "duplicate_ignored"}


def test_different_delivery_ids_are_not_treated_as_duplicates(client: Any) -> None:
    first_body = _body()
    second_body = _body({**VALID_PAYLOAD, "delivery_id": "delivery-002"})
    first = _post(client, first_body, _sign(first_body))
    second = _post(client, second_body, _sign(second_body))
    assert first.json() == {"status": "received"}
    assert second.json() == {"status": "received"}


def test_rejected_and_accepted_webhooks_are_logged_server_side(
    client: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.api.webhooks"):
        _post(client, _body(), signature=None)
        body = _body({**VALID_PAYLOAD, "delivery_id": "delivery-003"})
        _post(client, body, _sign(body))

    events = [getattr(r, "event", None) for r in caplog.records]
    assert "webhook_rejected" in events
    assert "webhook_received" in events


def test_webhook_secret_never_leaks_in_any_response(client: Any) -> None:
    responses = [
        _post(client, _body(), signature=None),
        _post(client, _body(), "sha256=" + "0" * 64),
        _post(client, _body(), _sign(_body())),
    ]
    for response in responses:
        assert DEFAULT_INCIDENT_DESK_WEBHOOK_SECRET not in response.text
