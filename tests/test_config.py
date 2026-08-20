"""Tests for `app/config.py` env-var parsing and validation."""

import logging

import pytest

from app.config import DEFAULT_AI_TIMEOUT_SECONDS, get_ai_timeout_seconds


def test_missing_env_var_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_PROVIDER_TIMEOUT_SECONDS", raising=False)
    assert get_ai_timeout_seconds() == DEFAULT_AI_TIMEOUT_SECONDS


def test_valid_positive_value_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "3.5")
    assert get_ai_timeout_seconds() == 3.5


@pytest.mark.parametrize("raw_value", ["0", "-1", "-0.01"])
def test_non_positive_value_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw_value: str
) -> None:
    """Regression test for issue #3: non-positive timeouts must not be accepted silently."""
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", raw_value)
    with caplog.at_level(logging.WARNING, logger="app.config"):
        result = get_ai_timeout_seconds()
    assert result == DEFAULT_AI_TIMEOUT_SECONDS
    assert any("must be positive" in record.getMessage() for record in caplog.records)


def test_non_numeric_value_falls_back_to_default_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "not-a-number")
    with caplog.at_level(logging.WARNING, logger="app.config"):
        result = get_ai_timeout_seconds()
    assert result == DEFAULT_AI_TIMEOUT_SECONDS
    assert any("is not a valid number" in record.getMessage() for record in caplog.records)
