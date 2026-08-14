import os

DEFAULT_AI_PROVIDER = "mock"
DEFAULT_AI_TIMEOUT_SECONDS = 8.0


def get_ai_provider_name() -> str:
    return os.environ.get("AI_PROVIDER", DEFAULT_AI_PROVIDER)


def get_ai_timeout_seconds() -> float:
    raw = os.environ.get("AI_PROVIDER_TIMEOUT_SECONDS")
    if raw is None:
        return DEFAULT_AI_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_AI_TIMEOUT_SECONDS
