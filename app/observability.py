"""Structured, JSON-formatted logging shared across the application.

Every operationally significant event (alert lifecycle stage, provider
degradation, unhandled failure) is logged through `log_event`, which
attaches one fixed set of field names (`STRUCTURED_FIELDS`) as `extra=` on
a stdlib `LogRecord`. Using one consistent set of names everywhere - never
`alert`/`alert_id`/`alertId`/`id` variants for the same concept - is what
makes one alert's lifecycle traceable end to end by grepping/filtering for
a single `alert_id` value. See docs/operations.md for the full field
reference and representative examples.

Deliberately built on stdlib `logging` rather than a third-party
structured-logging library (e.g. `structlog`): the application is small,
has no existing logging framework dependency, and stdlib `logging` +
`extra=` already covers every requirement in this phase.
"""

import json
import logging
from typing import Any

# The fixed set of structured fields every event may carry. A call site
# should never invent a new ad-hoc field name for a concept already covered
# here (e.g. a second "id" field for the alert) - reuse these.
STRUCTURED_FIELDS: tuple[str, ...] = (
    "event",
    "alert_id",
    "workflow_stage",
    "provider",
    "duration_ms",
    "result",
    "review_required",
    "error_type",
    "operation",
    "attempt",
    "retry",
    "status_code",
)


class StructuredFormatter(logging.Formatter):
    """Render one JSON object per log line.

    Only the human-readable `message` plus the fixed `STRUCTURED_FIELDS`
    are ever emitted - a call site cannot accidentally leak sensitive data
    by passing it as a stray keyword argument, since anything not in
    `STRUCTURED_FIELDS` is simply not picked up by this formatter.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in STRUCTURED_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level_name: str = "INFO") -> None:
    """Install the structured JSON formatter on the root logger.

    Idempotent - safe to call repeatedly (e.g. once per `create_app()`,
    including in tests that construct many apps per run) without stacking
    duplicate handlers.
    """
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root.handlers = [handler]
    root.setLevel(level)


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    *,
    event: str,
    alert_id: str | None = None,
    workflow_stage: str | None = None,
    provider: str | None = None,
    duration_ms: float | None = None,
    result: str | None = None,
    review_required: bool | None = None,
    error_type: str | None = None,
    operation: str | None = None,
    attempt: int | None = None,
    retry: bool | None = None,
    status_code: int | None = None,
    exc_info: bool | BaseException = False,
) -> None:
    """Log one structured operational event with consistent field names.

    `message` should stay a short, human-readable summary - structured
    fields (not string interpolation of untrusted/provider data) are the
    supported way to attach detail, and are what tests/queries assert on.
    """
    fields = {
        "event": event,
        "alert_id": alert_id,
        "workflow_stage": workflow_stage,
        "provider": provider,
        "duration_ms": duration_ms,
        "result": result,
        "review_required": review_required,
        "error_type": error_type,
        "operation": operation,
        "attempt": attempt,
        "retry": retry,
        "status_code": status_code,
    }
    extra = {key: value for key, value in fields.items() if value is not None}
    logger.log(level, message, extra=extra, exc_info=exc_info)
