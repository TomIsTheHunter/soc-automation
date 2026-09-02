"""Inbound webhook ingestion for the IncidentDesk case-management vendor.

This is the one *inbound* boundary in the integration layer - every other
provider category (enrichment, vulnerability, case management) is the
platform calling out to a vendor; here the vendor calls in. See
docs/adr/004-webhook-ingestion.md for the security model this route
implements: HMAC-SHA256 signature verification (constant-time comparison,
fail closed on anything missing/malformed/mismatched) and bounded
in-memory duplicate-delivery detection.

This application has no persistent store (see docs/architecture.md), so a
verified, non-duplicate webhook is logged as a structured event and
acknowledged - it does not update any case record, since none is
persisted anywhere in this application.
"""

import hashlib
import hmac
import logging
from collections import OrderedDict
from typing import cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.config import Settings
from app.models import ErrorDetail, ErrorResponse, IncidentDeskWebhookPayload
from app.observability import log_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

SIGNATURE_HEADER = "x-incident-desk-signature"
MAX_SEEN_DELIVERIES = 1000


def verify_webhook_signature(*, secret: str, raw_body: bytes, signature_header: str | None) -> bool:
    """Verify an HMAC-SHA256 webhook signature in constant time.

    Expects the `sha256=<hexdigest>` format (the GitHub/Stripe-style
    convention). Returns `False` for anything missing, malformed, or
    non-matching - never raises, so the caller can fail closed with one
    check. Uses `hmac.compare_digest` rather than `==` to avoid a
    timing-attack side channel on the comparison itself.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    provided = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


def _is_duplicate_delivery(seen: OrderedDict[str, None], delivery_id: str) -> bool:
    """Bounded in-memory duplicate-delivery check.

    Most webhook providers use at-least-once delivery, so the same
    `delivery_id` can legitimately arrive more than once. `seen` is capped
    at `MAX_SEEN_DELIVERIES` (an LRU via `OrderedDict`) so an attacker
    sending many unique IDs can never grow this without bound.
    """
    if delivery_id in seen:
        seen.move_to_end(delivery_id)
        return True
    seen[delivery_id] = None
    if len(seen) > MAX_SEEN_DELIVERIES:
        seen.popitem(last=False)
    return False


@router.post(
    "/incident-desk",
    responses={
        401: {"description": "Missing or invalid webhook signature", "model": ErrorResponse},
        413: {"description": "Request body exceeds the configured limit", "model": ErrorResponse},
        422: {"description": "Payload failed schema validation", "model": ErrorResponse},
    },
)
async def receive_incident_desk_webhook(request: Request) -> JSONResponse:
    settings = cast(Settings, request.app.state.settings)
    raw_body = await request.body()

    signature_header = request.headers.get(SIGNATURE_HEADER)
    if not verify_webhook_signature(
        secret=settings.incident_desk_webhook_secret.get_secret_value(),
        raw_body=raw_body,
        signature_header=signature_header,
    ):
        log_event(
            logger,
            logging.WARNING,
            "Rejected IncidentDesk webhook: invalid or missing signature",
            event="webhook_rejected",
            provider="mock-incident-desk",
            result="rejected",
            error_type="invalid_signature",
        )
        return JSONResponse(
            status_code=401,
            content=ErrorResponse(
                error=ErrorDetail(
                    code="invalid_signature", message="webhook signature missing or invalid"
                )
            ).model_dump(mode="json"),
        )

    try:
        payload = IncidentDeskWebhookPayload.model_validate_json(raw_body)
    except ValidationError as exc:
        log_event(
            logger,
            logging.WARNING,
            "Rejected IncidentDesk webhook: schema validation failed",
            event="webhook_rejected",
            provider="mock-incident-desk",
            result="rejected",
            error_type="validation_error",
        )
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=ErrorDetail(
                    code="validation_error",
                    message="webhook payload failed schema validation",
                    # Only safe, structural fields - never raw values or ctx.error
                    # exception objects, matching the RequestValidationError
                    # handler in app/main.py.
                    details=[
                        {"loc": error.get("loc"), "type": error.get("type")}
                        for error in exc.errors()
                    ],
                )
            ).model_dump(mode="json"),
        )

    seen: OrderedDict[str, None] = request.app.state.webhook_delivery_ids_seen
    if _is_duplicate_delivery(seen, payload.delivery_id):
        log_event(
            logger,
            logging.INFO,
            f"Ignored duplicate IncidentDesk webhook delivery {payload.delivery_id!r}",
            event="webhook_duplicate_ignored",
            provider="mock-incident-desk",
            result="ignored",
        )
        return JSONResponse(status_code=200, content={"status": "duplicate_ignored"})

    log_event(
        logger,
        logging.INFO,
        f"IncidentDesk webhook received: case {payload.case_id} -> {payload.status.value}",
        event="webhook_received",
        provider="mock-incident-desk",
        result="accepted",
    )
    return JSONResponse(status_code=200, content={"status": "received"})
