"""Tests for `app/config.py`: the centralized typed `Settings` model."""

import logging

import pytest
from pydantic import ValidationError

from app.config import (
    DEFAULT_AI_LIVE_MAX_RETRIES,
    DEFAULT_AI_PROVIDER,
    DEFAULT_AI_TIMEOUT_SECONDS,
    DEFAULT_MAX_ALERT_BODY_BYTES,
    Settings,
    get_settings,
)


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AI_PROVIDER",
        "AI_PROVIDER_TIMEOUT_SECONDS",
        "MAX_ALERT_BODY_BYTES",
        "AI_LIVE_MAX_RETRIES",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------
# Defaults / valid configuration
# --------------------------------------------------------------------------


def test_all_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    settings = get_settings()
    assert settings.ai_provider == DEFAULT_AI_PROVIDER
    assert settings.ai_provider_timeout_seconds == DEFAULT_AI_TIMEOUT_SECONDS
    assert settings.max_alert_body_bytes == DEFAULT_MAX_ALERT_BODY_BYTES
    assert settings.ai_live_max_retries == DEFAULT_AI_LIVE_MAX_RETRIES
    assert settings.anthropic_api_key is None


def test_valid_explicit_values_are_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_PROVIDER", "live")
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "3.5")
    monkeypatch.setenv("MAX_ALERT_BODY_BYTES", "1024")
    monkeypatch.setenv("AI_LIVE_MAX_RETRIES", "5")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-placeholder-value")
    settings = get_settings()
    assert settings.ai_provider == "live"
    assert settings.ai_provider_timeout_seconds == 3.5
    assert settings.max_alert_body_bytes == 1024
    assert settings.ai_live_max_retries == 5
    assert settings.anthropic_api_key is not None
    assert settings.anthropic_api_key.get_secret_value() == "test-only-placeholder-value"


# --------------------------------------------------------------------------
# AI_PROVIDER: degrades to the default (graceful, not fatal)
# --------------------------------------------------------------------------


def test_empty_provider_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_PROVIDER", "   ")
    with caplog.at_level(logging.WARNING, logger="app.config"):
        settings = get_settings()
    assert settings.ai_provider == DEFAULT_AI_PROVIDER
    assert any("AI_PROVIDER is empty" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------
# AI_PROVIDER_TIMEOUT_SECONDS: degrades to the default (graceful, not fatal)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw_value", ["0", "-1", "-0.01"])
def test_non_positive_timeout_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw_value: str
) -> None:
    """Regression test for issue #3: non-positive timeouts must not be accepted silently."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", raw_value)
    with caplog.at_level(logging.WARNING, logger="app.config"):
        settings = get_settings()
    assert settings.ai_provider_timeout_seconds == DEFAULT_AI_TIMEOUT_SECONDS
    assert any("must be positive" in record.getMessage() for record in caplog.records)


def test_non_numeric_timeout_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "not-a-number")
    with caplog.at_level(logging.WARNING, logger="app.config"):
        settings = get_settings()
    assert settings.ai_provider_timeout_seconds == DEFAULT_AI_TIMEOUT_SECONDS
    assert any("is not a valid number" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------
# MAX_ALERT_BODY_BYTES: fails fast (a safety limit, not a tuning knob)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw_value", ["0", "-1", "not-a-number"])
def test_invalid_max_alert_body_bytes_fails_fast(
    monkeypatch: pytest.MonkeyPatch, raw_value: str
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("MAX_ALERT_BODY_BYTES", raw_value)
    with pytest.raises(ValidationError):
        get_settings()


# --------------------------------------------------------------------------
# ANTHROPIC_API_KEY: optional, never logged/leaked via repr
# --------------------------------------------------------------------------


def test_missing_api_key_is_none_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    assert get_settings().anthropic_api_key is None


def test_api_key_is_masked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-placeholder-value")
    settings = get_settings()
    assert "test-only-placeholder-value" not in repr(settings.anthropic_api_key)
    assert "test-only-placeholder-value" not in str(settings.anthropic_api_key)


def test_settings_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"unexpected_field": "value"})


# --------------------------------------------------------------------------
# AI_LIVE_MAX_RETRIES: degrades to the default (graceful, not fatal)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw_value", ["-1", "not-a-number"])
def test_invalid_live_max_retries_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw_value: str
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_LIVE_MAX_RETRIES", raw_value)
    with caplog.at_level(logging.WARNING, logger="app.config"):
        settings = get_settings()
    assert settings.ai_live_max_retries == DEFAULT_AI_LIVE_MAX_RETRIES
    assert any(
        "must not be negative" in record.getMessage()
        or "not a valid integer" in record.getMessage()
        for record in caplog.records
    )


def test_zero_live_max_retries_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero is a valid, deliberate choice (disable retries), not an error."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("AI_LIVE_MAX_RETRIES", "0")
    assert get_settings().ai_live_max_retries == 0
