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
- `LOG_LEVEL`: safe default (`"INFO"`); an unrecognized value degrades to
  the default with a warning (degraded, not fatal - never worth failing
  application startup over). See docs/operations.md for the structured
  logging this controls.
- `THREAT_INTEL_BASE_URL` / `THREAT_INTEL_API_KEY`: configuration for the
  mock-backed threat-intelligence enrichment integration
  (`app/integrations/enrichment/threat_intel.py`). Both have safe,
  non-secret defaults since the provider talks to a mocked HTTP transport,
  not a real vendor - see docs/integration-architecture.md.
- `THREAT_INTEL_TIMEOUT_SECONDS` / `THREAT_INTEL_MAX_RETRIES`: the same
  timeout/graceful-degrade pattern as `AI_PROVIDER_TIMEOUT_SECONDS`/
  `AI_LIVE_MAX_RETRIES`, applied to the threat-intel integration client's
  read timeout and bounded retry policy - see
  docs/adr/002-provider-resilience.md.
- `ENRICHMENT_PROVIDER`: safe default (`"mock"`), same empty-value
  graceful-degrade pattern as `AI_PROVIDER`. Any other value attempts the
  mock-backed threat-intel integration; see
  `app/main.py: select_enrichment_provider`.
- `ASSET_INTEL_BASE_URL` / `ASSET_INTEL_API_KEY` / `ASSET_INTEL_TIMEOUT_SECONDS`
  / `ASSET_INTEL_MAX_RETRIES`: configuration for the mock-backed
  vulnerability/asset-context integration
  (`app/integrations/vulnerability/asset_intel.py`), mirroring the
  `THREAT_INTEL_*` settings exactly. Not yet consulted by any runtime
  selector - see docs/integration-architecture.md's "What was
  deliberately not wired".
- `INCIDENT_DESK_WEBHOOK_SECRET`: HMAC-SHA256 shared secret used to
  verify inbound IncidentDesk webhooks (`app/api/webhooks.py`). Safe,
  non-secret default for the mock/demo integration, same reasoning as
  `THREAT_INTEL_API_KEY` - see docs/adr/004-webhook-ingestion.md.
- `MAX_WEBHOOK_BODY_BYTES`: safe default (16 KiB). Same fail-fast policy
  as `MAX_ALERT_BODY_BYTES` - a safety limit, not a tuning knob.
"""

import logging

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

DEFAULT_AI_PROVIDER = "mock"
DEFAULT_AI_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_ALERT_BODY_BYTES = 256 * 1024
DEFAULT_AI_LIVE_MAX_RETRIES = 2
DEFAULT_LOG_LEVEL = "INFO"
VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
DEFAULT_THREAT_INTEL_BASE_URL = "https://mock-threat-intel.example/v1"
# Not a real secret: this placeholder only ever authenticates against the
# in-process mocked HTTP transport in threat_intel.py, never a live vendor.
DEFAULT_THREAT_INTEL_API_KEY = "mock-threat-intel-api-key"
DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS = 5.0
DEFAULT_THREAT_INTEL_MAX_RETRIES = 2
DEFAULT_ENRICHMENT_PROVIDER = "mock"
DEFAULT_ASSET_INTEL_BASE_URL = "https://mock-asset-intel.example/v1"
# Not a real secret: this placeholder only ever authenticates against the
# in-process mocked HTTP transport in asset_intel.py, never a live vendor.
DEFAULT_ASSET_INTEL_API_KEY = "mock-asset-intel-api-key"
DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS = 5.0
DEFAULT_ASSET_INTEL_MAX_RETRIES = 2
# Not a real secret: this placeholder only ever verifies the mock webhook
# fixtures used in this app's own tests/demo, never a live vendor.
DEFAULT_INCIDENT_DESK_WEBHOOK_SECRET = "mock-incident-desk-webhook-secret"
DEFAULT_MAX_WEBHOOK_BODY_BYTES = 16 * 1024


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
    log_level: str = Field(default=DEFAULT_LOG_LEVEL, alias="LOG_LEVEL")
    threat_intel_base_url: str = Field(
        default=DEFAULT_THREAT_INTEL_BASE_URL, alias="THREAT_INTEL_BASE_URL"
    )
    threat_intel_api_key: SecretStr = Field(
        default=SecretStr(DEFAULT_THREAT_INTEL_API_KEY), alias="THREAT_INTEL_API_KEY"
    )
    threat_intel_timeout_seconds: float = Field(
        default=DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS, alias="THREAT_INTEL_TIMEOUT_SECONDS"
    )
    threat_intel_max_retries: int = Field(
        default=DEFAULT_THREAT_INTEL_MAX_RETRIES, alias="THREAT_INTEL_MAX_RETRIES"
    )
    enrichment_provider: str = Field(
        default=DEFAULT_ENRICHMENT_PROVIDER, alias="ENRICHMENT_PROVIDER"
    )
    asset_intel_base_url: str = Field(
        default=DEFAULT_ASSET_INTEL_BASE_URL, alias="ASSET_INTEL_BASE_URL"
    )
    asset_intel_api_key: SecretStr = Field(
        default=SecretStr(DEFAULT_ASSET_INTEL_API_KEY), alias="ASSET_INTEL_API_KEY"
    )
    asset_intel_timeout_seconds: float = Field(
        default=DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS, alias="ASSET_INTEL_TIMEOUT_SECONDS"
    )
    asset_intel_max_retries: int = Field(
        default=DEFAULT_ASSET_INTEL_MAX_RETRIES, alias="ASSET_INTEL_MAX_RETRIES"
    )
    incident_desk_webhook_secret: SecretStr = Field(
        default=SecretStr(DEFAULT_INCIDENT_DESK_WEBHOOK_SECRET),
        alias="INCIDENT_DESK_WEBHOOK_SECRET",
    )
    max_webhook_body_bytes: int = Field(
        default=DEFAULT_MAX_WEBHOOK_BODY_BYTES, gt=0, alias="MAX_WEBHOOK_BODY_BYTES"
    )

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

    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_LOG_LEVEL
        if isinstance(value, str) and value.strip().upper() in VALID_LOG_LEVELS:
            return value.strip().upper()
        logger.warning(
            "LOG_LEVEL=%r is not a recognized level; using default %r",
            value,
            DEFAULT_LOG_LEVEL,
        )
        return DEFAULT_LOG_LEVEL

    @field_validator("threat_intel_timeout_seconds", mode="before")
    @classmethod
    def _validate_threat_intel_timeout(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS
        try:
            parsed = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            logger.warning(
                "THREAT_INTEL_TIMEOUT_SECONDS=%r is not a valid number; using default %.1fs",
                value,
                DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS,
            )
            return DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS
        if parsed <= 0:
            logger.warning(
                "THREAT_INTEL_TIMEOUT_SECONDS=%s must be positive; using default %.1fs",
                parsed,
                DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS,
            )
            return DEFAULT_THREAT_INTEL_TIMEOUT_SECONDS
        return parsed

    @field_validator("threat_intel_max_retries", mode="before")
    @classmethod
    def _validate_threat_intel_max_retries(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_THREAT_INTEL_MAX_RETRIES
        try:
            parsed = int(value)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            logger.warning(
                "THREAT_INTEL_MAX_RETRIES=%r is not a valid integer; using default %d",
                value,
                DEFAULT_THREAT_INTEL_MAX_RETRIES,
            )
            return DEFAULT_THREAT_INTEL_MAX_RETRIES
        if parsed < 0:
            logger.warning(
                "THREAT_INTEL_MAX_RETRIES=%d must not be negative; using default %d",
                parsed,
                DEFAULT_THREAT_INTEL_MAX_RETRIES,
            )
            return DEFAULT_THREAT_INTEL_MAX_RETRIES
        return parsed

    @field_validator("enrichment_provider", mode="before")
    @classmethod
    def _default_empty_enrichment_provider(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            logger.warning(
                "ENRICHMENT_PROVIDER is empty; using default %r", DEFAULT_ENRICHMENT_PROVIDER
            )
            return DEFAULT_ENRICHMENT_PROVIDER
        return value

    @field_validator("asset_intel_timeout_seconds", mode="before")
    @classmethod
    def _validate_asset_intel_timeout(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS
        try:
            parsed = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            logger.warning(
                "ASSET_INTEL_TIMEOUT_SECONDS=%r is not a valid number; using default %.1fs",
                value,
                DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS,
            )
            return DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS
        if parsed <= 0:
            logger.warning(
                "ASSET_INTEL_TIMEOUT_SECONDS=%s must be positive; using default %.1fs",
                parsed,
                DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS,
            )
            return DEFAULT_ASSET_INTEL_TIMEOUT_SECONDS
        return parsed

    @field_validator("asset_intel_max_retries", mode="before")
    @classmethod
    def _validate_asset_intel_max_retries(cls, value: object) -> object:
        if value is None or value == "":
            return DEFAULT_ASSET_INTEL_MAX_RETRIES
        try:
            parsed = int(value)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            logger.warning(
                "ASSET_INTEL_MAX_RETRIES=%r is not a valid integer; using default %d",
                value,
                DEFAULT_ASSET_INTEL_MAX_RETRIES,
            )
            return DEFAULT_ASSET_INTEL_MAX_RETRIES
        if parsed < 0:
            logger.warning(
                "ASSET_INTEL_MAX_RETRIES=%d must not be negative; using default %d",
                parsed,
                DEFAULT_ASSET_INTEL_MAX_RETRIES,
            )
            return DEFAULT_ASSET_INTEL_MAX_RETRIES
        return parsed


def get_settings() -> Settings:
    """Build a fresh `Settings` from the current environment.

    Deliberately not memoized: this is a stateless app with no I/O cost
    beyond a handful of `os.environ` reads, and per-call construction keeps
    environment-variable-based tests (`monkeypatch.setenv`) simple and
    correct with no cache to invalidate.
    """
    return Settings()
