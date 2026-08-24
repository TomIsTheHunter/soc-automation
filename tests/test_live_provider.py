"""Unit tests for the optional live Anthropic provider's failure handling.

These are the only tests in the suite that exercise
`app/investigation/live.py` directly. The real `anthropic` package is never
installed in this environment or in CI (it is an optional extra), so a
minimal fake module is injected into `sys.modules` before constructing
`AnthropicInvestigationAssistant`. This lets us test retry/error
classification behavior without any real network access (still enforced
offline via `pytest-socket`) and without depending on the real SDK's
internals.

The fake mirrors just enough of the real SDK's exception hierarchy
(`APIStatusError` as the base for `AuthenticationError`,
`PermissionDeniedError`, `RateLimitError`; `APIConnectionError` as a
separate transport-level error) to prove that `live.py` classifies and
logs each category distinctly while always degrading to a single
`InvestigationUnavailableError` - never leaking a provider-specific
exception type into the rest of the application.
"""

import asyncio
import json
import logging
import sys
import types
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

import pytest
from pytest_socket import disable_socket, enable_socket

from app.investigation.assistant import InvestigationUnavailableError
from app.investigation.context import build_investigation_context
from app.investigation.live import DEFAULT_MAX_RETRIES, AnthropicInvestigationAssistant
from app.models import InvestigationContext, Severity, TriageDecision
from app.models.alert import NormalizedAlert
from app.models.workflow import TriageResult


def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """See the identical helper in tests/test_ai_investigation.py for why this exists."""
    enable_socket()
    try:
        return asyncio.run(coro)
    finally:
        disable_socket()


class FakeAPIStatusError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class FakeAuthenticationError(FakeAPIStatusError):
    pass


class FakePermissionDeniedError(FakeAPIStatusError):
    pass


class FakeRateLimitError(FakeAPIStatusError):
    pass


class FakeAPIConnectionError(Exception):
    pass


CreateImpl = Callable[..., Coroutine[Any, Any, Any]]


class _FakeMessages:
    def __init__(self) -> None:
        self.call_count = 0
        self.create_impl: CreateImpl | None = None

    async def create(self, **kwargs: Any) -> Any:
        self.call_count += 1
        assert self.create_impl is not None, "test must set messages.create_impl"
        return await self.create_impl(**kwargs)


class _FakeAsyncAnthropic:
    def __init__(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs
        self.messages = _FakeMessages()


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_TextBlock(text)]


@pytest.fixture
def fake_anthropic_module(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    module = types.ModuleType("anthropic")
    module.AsyncAnthropic = _FakeAsyncAnthropic  # type: ignore[attr-defined]
    module.AuthenticationError = FakeAuthenticationError  # type: ignore[attr-defined]
    module.PermissionDeniedError = FakePermissionDeniedError  # type: ignore[attr-defined]
    module.RateLimitError = FakeRateLimitError  # type: ignore[attr-defined]
    module.APIConnectionError = FakeAPIConnectionError  # type: ignore[attr-defined]
    module.APIStatusError = FakeAPIStatusError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", module)
    return module


@pytest.fixture
def investigation_context() -> InvestigationContext:
    alert = NormalizedAlert(
        source_alert_id="synthetic-live-provider-test",
        timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
        hostname="workstation-42",
        username="synthetic.user",
        severity=Severity.HIGH,
        detection_description="synthetic",
    )
    triage = TriageResult(
        decision=TriageDecision.ESCALATE,
        rules_triggered=["RULE_A_HIGH_RISK_MALICIOUS"],
        reason="synthetic live-provider test fixture",
    )
    return build_investigation_context(alert, [], [], triage)


def _make_assistant(_: types.ModuleType, max_retries: int = DEFAULT_MAX_RETRIES) -> Any:
    return AnthropicInvestigationAssistant(api_key="test-only-placeholder", max_retries=max_retries)


VALID_RAW_RESULT: dict[str, Any] = {
    "schema_version": 1,
    "provider_name": "anthropic-live",
    "summary": "Investigation summary for workstation-42.",
    "key_evidence": ["hostname=workstation-42"],
    "risk_assessment": "HIGH",
    "recommended_actions": ["escalate_to_senior_analyst"],
    "confidence": "HIGH",
    "uncertainties": [],
}


# --------------------------------------------------------------------------
# Explicit, bounded retry configuration
# --------------------------------------------------------------------------


def test_live_client_configures_explicit_bounded_max_retries(
    fake_anthropic_module: types.ModuleType,
) -> None:
    assistant = _make_assistant(fake_anthropic_module, max_retries=5)
    assert assistant._client.init_kwargs["max_retries"] == 5


def test_live_client_defaults_to_a_small_bounded_retry_count(
    fake_anthropic_module: types.ModuleType,
) -> None:
    assistant = _make_assistant(fake_anthropic_module)
    assert assistant._client.init_kwargs["max_retries"] == DEFAULT_MAX_RETRIES
    assert 0 <= assistant._client.init_kwargs["max_retries"] <= 5


# --------------------------------------------------------------------------
# Non-retryable failures: surfaced after exactly one call-site attempt
# --------------------------------------------------------------------------


def test_provider_401_is_not_retried(
    fake_anthropic_module: types.ModuleType,
    investigation_context: InvestigationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise FakeAuthenticationError("invalid api key", 401)

    assistant._client.messages.create_impl = _raise
    with caplog.at_level(logging.WARNING):
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(investigation_context, 5.0))
    assert assistant._client.messages.call_count == 1
    assert any("auth/permission" in record.getMessage() for record in caplog.records)


def test_provider_403_is_not_retried(
    fake_anthropic_module: types.ModuleType,
    investigation_context: InvestigationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise FakePermissionDeniedError("forbidden", 403)

    assistant._client.messages.create_impl = _raise
    with caplog.at_level(logging.WARNING):
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(investigation_context, 5.0))
    assert assistant._client.messages.call_count == 1
    assert any("auth/permission" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------
# Transient failures: already bounded-retried inside the SDK; a single call
# from this module's perspective either way (the SDK's retry loop lives
# inside the one awaited `messages.create` call, invisible to this code).
# --------------------------------------------------------------------------


def test_provider_429_is_surfaced_after_sdk_retries(
    fake_anthropic_module: types.ModuleType,
    investigation_context: InvestigationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise FakeRateLimitError("rate limited", 429)

    assistant._client.messages.create_impl = _raise
    with caplog.at_level(logging.WARNING):
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(investigation_context, 5.0))
    assert assistant._client.messages.call_count == 1
    assert any("rate-limited" in record.getMessage() for record in caplog.records)


def test_provider_503_uses_bounded_retry(
    fake_anthropic_module: types.ModuleType,
    investigation_context: InvestigationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A persistent 5xx is bounded by the explicit `max_retries` passed to the
    SDK client (see test_live_client_configures_explicit_bounded_max_retries);
    from this module's perspective it still surfaces as a single failure.
    """
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise FakeAPIStatusError("internal server error", 503)

    assistant._client.messages.create_impl = _raise
    with caplog.at_level(logging.WARNING):
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(investigation_context, 5.0))
    assert assistant._client.messages.call_count == 1
    assert any("request failed" in record.getMessage() for record in caplog.records)


def test_provider_connection_failure_is_surfaced(
    fake_anthropic_module: types.ModuleType,
    investigation_context: InvestigationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise FakeAPIConnectionError("connection reset")

    assistant._client.messages.create_impl = _raise
    with caplog.at_level(logging.WARNING):
        with pytest.raises(InvestigationUnavailableError):
            _run_async(assistant.investigate(investigation_context, 5.0))
    assert assistant._client.messages.call_count == 1
    assert any("request failed" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------
# Unexpected / malformed-response / timeout paths
# --------------------------------------------------------------------------


def test_unexpected_provider_exception_does_not_crash(
    fake_anthropic_module: types.ModuleType, investigation_context: InvestigationContext
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _raise(**kwargs: Any) -> Any:
        raise ValueError("synthetic unexpected SDK failure")

    assistant._client.messages.create_impl = _raise
    with pytest.raises(InvestigationUnavailableError):
        _run_async(assistant.investigate(investigation_context, 5.0))


def test_malformed_json_response_is_rejected(
    fake_anthropic_module: types.ModuleType, investigation_context: InvestigationContext
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _return_non_json(**kwargs: Any) -> Any:
        return _FakeResponse("this is not valid JSON")

    assistant._client.messages.create_impl = _return_non_json
    with pytest.raises(InvestigationUnavailableError):
        _run_async(assistant.investigate(investigation_context, 5.0))


def test_timeout_still_enforced_by_call_site(
    fake_anthropic_module: types.ModuleType, investigation_context: InvestigationContext
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _slow(**kwargs: Any) -> Any:
        await asyncio.sleep(60.0)
        return _FakeResponse(json.dumps(VALID_RAW_RESULT))

    assistant._client.messages.create_impl = _slow
    with pytest.raises(TimeoutError):
        _run_async(assistant.investigate(investigation_context, 0.05))


def test_happy_path_returns_parsed_dict(
    fake_anthropic_module: types.ModuleType, investigation_context: InvestigationContext
) -> None:
    assistant = _make_assistant(fake_anthropic_module)

    async def _ok(**kwargs: Any) -> Any:
        return _FakeResponse(json.dumps(VALID_RAW_RESULT))

    assistant._client.messages.create_impl = _ok
    result = _run_async(assistant.investigate(investigation_context, 5.0))
    assert result == VALID_RAW_RESULT
    assert assistant._client.messages.call_count == 1
