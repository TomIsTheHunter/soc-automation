"""Contract tests for the reusable integration client foundation.

These exercise `BaseIntegrationClient`/`ApiKeyAuth`/`BearerTokenAuth`
directly (independent of any specific provider) using `httpx.MockTransport`
handlers, so the real request/response code path - headers, status
classification, JSON parsing, retry/backoff - is genuinely exercised,
never bypassed by monkeypatching a client method.

Every test injects a recording fake `sleep` so retry/backoff behavior is
verified without real wall-clock delay. See
docs/adr/002-provider-resilience.md for the resilience policy these tests
verify.
"""

import logging

import httpx
import pytest

from app.integrations.base import ApiKeyAuth, BaseIntegrationClient, BearerTokenAuth, RetryPolicy
from app.integrations.errors import (
    IntegrationAuthError,
    IntegrationNotFoundError,
    IntegrationRateLimitedError,
    IntegrationServerError,
    IntegrationTimeoutError,
    IntegrationUnexpectedError,
    IntegrationValidationError,
)

API_KEY = "secret-key"


class _RecordingSleep:
    """Fake `sleep` that records requested delays instead of waiting."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _client(
    handler: httpx.MockTransport | None = None,
    *,
    retry_policy: RetryPolicy | None = None,
    sleep: _RecordingSleep | None = None,
) -> BaseIntegrationClient:
    return BaseIntegrationClient(
        provider_name="test-provider",
        base_url="https://provider.example",
        auth=ApiKeyAuth(API_KEY),
        transport=handler,
        retry_policy=retry_policy,
        sleep=sleep or _RecordingSleep(),
    )


def test_api_key_auth_sets_header() -> None:
    assert ApiKeyAuth("abc123").headers() == {"X-API-Key": "abc123"}


def test_bearer_token_auth_sets_authorization_header() -> None:
    assert BearerTokenAuth("tok-456").headers() == {"Authorization": "Bearer tok-456"}


def test_auth_headers_are_actually_attached_to_the_request() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json={"ok": True})

    client = _client(httpx.MockTransport(handler))
    client.get("/thing")
    assert seen_headers["x-api-key"] == API_KEY


def test_200_returns_parsed_json_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": 42})

    client = _client(httpx.MockTransport(handler))
    assert client.get("/thing") == {"value": 42}


# --- Non-retryable failures: exactly one attempt, no sleep -----------------


@pytest.mark.parametrize("status", [401, 403])
def test_401_403_raise_auth_error_without_retry(status: int) -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(status, json={"error": "denied"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationAuthError) as excinfo:
        client.get("/thing")
    assert excinfo.value.status_code == status
    assert API_KEY not in str(excinfo.value)
    assert len(calls) == 1
    assert sleep.calls == []


def test_404_raises_not_found_error_without_retry() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404, json={"error": "missing"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationNotFoundError):
        client.get("/thing")
    assert len(calls) == 1
    assert sleep.calls == []


def test_plain_500_is_not_retried_by_default() -> None:
    """Explicit engineering decision: a bare 500 is ambiguous, not a clear
    transient-infra signal like 502/503/504 - see
    docs/adr/002-provider-resilience.md."""
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(500, text="internal error")

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationServerError) as excinfo:
        client.get("/thing")
    assert API_KEY not in str(excinfo.value)
    assert len(calls) == 1
    assert sleep.calls == []


def test_other_4xx_raises_unexpected_error_without_retry() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(418, json={"error": "teapot"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationUnexpectedError):
        client.get("/thing")
    assert len(calls) == 1
    assert sleep.calls == []


def test_invalid_json_raises_validation_error_without_retry() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, text="not json{{{")

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationValidationError):
        client.get("/thing")
    assert len(calls) == 1
    assert sleep.calls == []


def test_non_object_json_raises_validation_error_without_retry() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationValidationError):
        client.get("/thing")


# --- Retryable failures: bounded retries, then a classified error ----------


@pytest.mark.parametrize("status", [502, 503, 504])
def test_gateway_errors_are_retried_then_raise_server_error(status: int) -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(status, text="bad gateway")

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationServerError) as excinfo:
        client.get("/thing")
    assert API_KEY not in str(excinfo.value)
    assert len(calls) == 3  # default RetryPolicy.max_attempts
    assert len(sleep.calls) == 2
    assert all(0 <= delay <= 8.0 for delay in sleep.calls)


def test_429_is_retried_then_raises_rate_limited_error() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(429, json={"error": "rate limited"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationRateLimitedError):
        client.get("/thing")
    assert len(calls) == 3
    assert len(sleep.calls) == 2


def test_timeout_is_retried_then_raises_integration_timeout_error() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectTimeout("timed out")

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationTimeoutError) as excinfo:
        client.get("/thing")
    assert API_KEY not in str(excinfo.value)
    assert len(calls) == 3
    assert len(sleep.calls) == 2


def test_connection_error_is_retried_then_raises_integration_timeout_error() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("connection refused")

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationTimeoutError):
        client.get("/thing")
    assert len(calls) == 3
    assert len(sleep.calls) == 2


def test_recovers_after_one_transient_failure() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, text="bad gateway")
        return httpx.Response(200, json={"ok": True})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    assert client.get("/thing") == {"ok": True}
    assert len(calls) == 2
    assert len(sleep.calls) == 1


def test_retries_are_bounded_by_a_custom_retry_policy() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503, text="bad gateway")

    sleep = _RecordingSleep()
    client = _client(
        httpx.MockTransport(handler), retry_policy=RetryPolicy(max_attempts=1), sleep=sleep
    )
    with pytest.raises(IntegrationServerError):
        client.get("/thing")
    assert len(calls) == 1
    assert sleep.calls == []


# --- Retry-After handling ---------------------------------------------------


def test_429_with_retry_after_respects_value_within_cap() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": "rate limited"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationRateLimitedError):
        client.get("/thing")
    assert sleep.calls[0] == 1.0


def test_429_without_retry_after_falls_back_to_bounded_backoff() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate limited"})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationRateLimitedError):
        client.get("/thing")
    assert all(0 <= delay <= 8.0 for delay in sleep.calls)


def test_429_with_malformed_retry_after_falls_back_to_bounded_backoff() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, headers={"Retry-After": "soon-ish"}, json={"error": "rate limited"}
        )

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationRateLimitedError):
        client.get("/thing")
    assert all(0 <= delay <= 8.0 for delay in sleep.calls)


def test_429_with_unreasonable_retry_after_is_capped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, headers={"Retry-After": "999999999"}, json={"error": "rate limited"}
        )

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    with pytest.raises(IntegrationRateLimitedError):
        client.get("/thing")
    assert all(delay <= 30.0 for delay in sleep.calls)  # RetryPolicy.max_retry_after_seconds


def test_successful_recovery_after_429_with_retry_after() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(
                429, headers={"Retry-After": "0.1"}, json={"error": "rate limited"}
            )
        return httpx.Response(200, json={"ok": True})

    sleep = _RecordingSleep()
    client = _client(httpx.MockTransport(handler), sleep=sleep)
    assert client.get("/thing") == {"ok": True}
    assert sleep.calls == [0.1]


# --- Observability -----------------------------------------------------------


def test_retry_and_failure_logs_never_leak_the_api_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="bad gateway")

    client = _client(httpx.MockTransport(handler))
    with caplog.at_level(logging.WARNING, logger="app.integrations.base"):
        with pytest.raises(IntegrationServerError):
            client.get("/thing", operation="do_thing")

    assert caplog.records
    for record in caplog.records:
        assert API_KEY not in record.getMessage()
        assert API_KEY not in repr(record.__dict__)

    retry_records = [r for r in caplog.records if getattr(r, "event", None) == "provider_retry"]
    failure_records = [
        r for r in caplog.records if getattr(r, "event", None) == "provider_degraded"
    ]
    assert len(retry_records) == 2
    assert len(failure_records) == 1
    assert getattr(retry_records[0], "operation", None) == "do_thing"
    assert getattr(retry_records[0], "attempt", None) == 1
    assert getattr(retry_records[0], "retry", None) is True
    assert getattr(retry_records[0], "status_code", None) == 503
    assert getattr(failure_records[0], "attempt", None) == 3
    assert getattr(failure_records[0], "retry", None) is False


# --- Pagination --------------------------------------------------------------


def test_get_paginated_follows_cursor_across_pages() -> None:
    pages = [
        {"items": [{"value": 1}], "next_cursor": "2"},
        {"items": [{"value": 2}], "next_cursor": "3"},
        {"items": [{"value": 3}], "next_cursor": None},
    ]
    seen_cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        seen_cursors.append(cursor)
        index = int(cursor) - 1 if cursor else 0
        return httpx.Response(200, json=pages[index])

    client = _client(httpx.MockTransport(handler))
    items = client.get_paginated("/things")
    assert items == [{"value": 1}, {"value": 2}, {"value": 3}]
    assert seen_cursors == [None, "2", "3"]


def test_get_paginated_stops_when_next_cursor_is_absent() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [{"value": "only"}]})

    client = _client(httpx.MockTransport(handler))
    assert client.get_paginated("/things") == [{"value": "only"}]


def test_get_paginated_is_bounded_by_max_pages() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        # A misbehaving/malicious provider that never stops paginating.
        return httpx.Response(200, json={"items": [{"n": len(calls)}], "next_cursor": "loop"})

    client = _client(httpx.MockTransport(handler))
    items = client.get_paginated("/things", max_pages=3)
    assert len(calls) == 3
    assert len(items) == 3


def test_get_paginated_raises_validation_error_for_missing_items_key() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationValidationError):
        client.get_paginated("/things")


# --- POST + idempotency -------------------------------------------------


def test_post_returns_parsed_json_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"created": True})

    client = _client(httpx.MockTransport(handler))
    assert client.post("/things", json_body={"name": "x"}) == {"created": True}


def test_post_generates_an_idempotency_key_when_none_supplied() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(201, json={"created": True})

    client = _client(httpx.MockTransport(handler))
    client.post("/things", json_body={"name": "x"})
    assert seen_headers["idempotency-key"]


def test_post_uses_the_supplied_idempotency_key() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(201, json={"created": True})

    client = _client(httpx.MockTransport(handler))
    client.post("/things", json_body={"name": "x"}, idempotency_key="fixed-key-123")
    assert seen_headers["idempotency-key"] == "fixed-key-123"


def test_post_reuses_the_same_idempotency_key_across_retries() -> None:
    """The property that makes retrying a POST safe: every retry of one
    logical call carries the identical Idempotency-Key, never a fresh one."""
    seen_keys: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers["idempotency-key"])
        if len(seen_keys) < 3:
            return httpx.Response(503, text="bad gateway")
        return httpx.Response(201, json={"created": True})

    client = _client(httpx.MockTransport(handler))
    client.post("/things", json_body={"name": "x"})
    assert len(seen_keys) == 3
    assert len(set(seen_keys)) == 1


def test_post_retryable_failure_then_success() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, text="bad gateway")
        return httpx.Response(201, json={"created": True})

    client = _client(httpx.MockTransport(handler))
    assert client.post("/things", json_body={"name": "x"}) == {"created": True}
    assert len(calls) == 2


def test_post_non_retryable_failure_raises_immediately_without_leaking_credentials() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, json={"error": "denied"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationAuthError) as excinfo:
        client.post("/things", json_body={"name": "x"})
    assert len(calls) == 1
    assert API_KEY not in str(excinfo.value)
