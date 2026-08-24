"""Centralized, typed application configuration.

This is the single place in the application that reads environment
variables. Everything else (`app/main.py`, `app/investigation/live.py`,
routes) receives configuration through a `Settings` instance instead of
touching `os.environ` directly, so configuration dependencies are explicit
and testable.

Each setting has a documented, intentional behavior when missing or invalid
- see docs/configuration.md for the full table. Summary:

- `AI_PROVIDER`: safe default (`"mock"`); an empty value falls back to the
  default with a warning (degraded, not fatal).
- `AI_PROVIDER_TIMEOUT_SECONDS`: safe default (8.0s); invalid or non-positive
  values fall back to the default with a warning (degraded, not fatal - the
  deterministic pipeline is unaffected either way).
- `ANTHROPIC_API_KEY`: no default, optional. Only required if `AI_PROVIDER`
  selects a live provider; missing it degrades the AI assistant to
  `unavailable` rather than failing the whole application (see
  `app/main.py: select_investigation_assistant`).
- `MAX_ALERT_BODY_BYTES`: safe default (256 KiB). Unlike the two settings
  above, an invalid value **fails fast** at startup (`pydantic.ValidationError`)
  rather than silently falling back - this is a safety limit, not an
  operational tuning knob, so a misconfiguration here should be loud.
- `AI_LIVE_MAX_RETRIES`: safe default (2), only used by the live Anthropic
  provider. Bounds the SDK's own built-in retry policy for transient
  failures (connection errors, timeouts, HTTP 429/5xx); authentication,
  authorization, and invalid-request errors are never retried by the SDK
  regardless of this value. A negative or non-numeric value degrades to
  the default with a warning (same graceful-degrade policy as the other
  AI settings - see docs/adr/001-failure-handling.md).
"""

import logging

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

DEFAULT_AI_PROVIDER = "mock"
DEFAULT_AI_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_ALERT_BODY_BYTES = 256 * 1024
DEFAULT_AI_LIVE_MAX_RETRIES = 2


class Settings(BaseSettings):
    """Typed application configuration, loaded from environment variables.

    A `.env` file (never committed - see `.gitignore`) is also read if
    present, matching `.env.example`.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="forbid")

    ai_provider: str = Field(default=DEFAULT_AI_PROVIDER, alias="AI_PROVIDER")
    ai_provider_timeout_seconds: float = Field(
        default=DEFAULT_AI_TIMEOUT_SECONDS, alias="AI_PROVIDER_TIMEOUT_SECONDS"
    )
    max_alert_body_bytes: int = Field(
        default=DEFAULT_MAX_ALERT_BODY_BYTES, gt=0, alias="MAX_ALERT_BODY_BYTES"
    )
    ai_live_max_retries: int = Field(
        default=DEFAULT_AI_LIVE_MAX_RETRIES, alias="AI_LIVE_MAX_RETRIES"
    )
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    @field_validator("ai_provider", mode="before")
    @classmethod
    def _default_empty_provider(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            logger.warning("AI_PROVIDER is empty; using default %r", DEFAULT_AI_PROVIDER)
            return DEFAULT_AI_PROVIDER
        return value

    @field_validator("ai_provider_timeout_seconds", mode="before")
    @classmethod
    def _validate_timeout(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_AI_TIMEOUT_SECONDS
        try:
            parsed = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            logger.warning(
                "AI_PROVIDER_TIMEOUT_SECONDS=%r is not a valid number; using default %.1fs",
                value,
                DEFAULT_AI_TIMEOUT_SECONDS,
            )
            return DEFAULT_AI_TIMEOUT_SECONDS
        if parsed <= 0:
            logger.warning(
                "AI_PROVIDER_TIMEOUT_SECONDS=%s must be positive; using default %.1fs",
                parsed,
                DEFAULT_AI_TIMEOUT_SECONDS,
            )
            return DEFAULT_AI_TIMEOUT_SECONDS
        return parsed

    @field_validator("ai_live_max_retries", mode="before")
    @classmethod
    def _validate_live_max_retries(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_AI_LIVE_MAX_RETRIES
        try:
            parsed = int(value)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            logger.warning(
                "AI_LIVE_MAX_RETRIES=%r is not a valid integer; using default %d",
                value,
                DEFAULT_AI_LIVE_MAX_RETRIES,
            )
            return DEFAULT_AI_LIVE_MAX_RETRIES
        if parsed < 0:
            logger.warning(
                "AI_LIVE_MAX_RETRIES=%d must not be negative; using default %d",
                parsed,
                DEFAULT_AI_LIVE_MAX_RETRIES,
            )
            return DEFAULT_AI_LIVE_MAX_RETRIES
        return parsed


def get_settings() -> Settings:
    """Build a fresh `Settings` from the current environment.

    Deliberately not memoized: this is a stateless app with no I/O cost
    beyond a handful of `os.environ` reads, and per-call construction keeps
    environment-variable-based tests (`monkeypatch.setenv`) simple and
    correct with no cache to invalidate.
    """
    return Settings()
