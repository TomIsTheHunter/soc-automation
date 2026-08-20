import logging
import os

DEFAULT_AI_PROVIDER = "mock"
DEFAULT_AI_TIMEOUT_SECONDS = 8.0

logger = logging.getLogger(__name__)


def get_ai_provider_name() -> str:
    return os.environ.get("AI_PROVIDER", DEFAULT_AI_PROVIDER)


def get_ai_timeout_seconds() -> float:
    raw = os.environ.get("AI_PROVIDER_TIMEOUT_SECONDS")
    if raw is None:
        return DEFAULT_AI_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "AI_PROVIDER_TIMEOUT_SECONDS=%r is not a valid number; using default %.1fs",
            raw,
            DEFAULT_AI_TIMEOUT_SECONDS,
        )
        return DEFAULT_AI_TIMEOUT_SECONDS
    if value <= 0:
        logger.warning(
            "AI_PROVIDER_TIMEOUT_SECONDS=%s must be positive; using default %.1fs",
            value,
            DEFAULT_AI_TIMEOUT_SECONDS,
        )
        return DEFAULT_AI_TIMEOUT_SECONDS
    return value
