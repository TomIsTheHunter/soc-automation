"""Contract tests for the reusable integration client foundation.

These exercise `BaseIntegrationClient`/`ApiKeyAuth`/`BearerTokenAuth`
directly (independent of any specific provider) using `httpx.MockTransport`
handlers, so the real request/response code path - headers, status
classification, JSON parsing - is genuinely exercised, never bypassed by
monkeypatching a client method.
"""

import httpx
import pytest

from app.integrations.base import ApiKeyAuth, BaseIntegrationClient, BearerTokenAuth
from app.integrations.errors import (
    IntegrationAuthError,
    IntegrationNotFoundError,
    IntegrationServerError,
    IntegrationTimeoutError,
    IntegrationUnexpectedError,
    IntegrationValidationError,
)


def _client(handler: httpx.MockTransport | None = None) -> BaseIntegrationClient:
    return BaseIntegrationClient(
        provider_name="test-provider",
        base_url="https://provider.example",
        auth=ApiKeyAuth("secret-key"),
        transport=handler,
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
    assert seen_headers["x-api-key"] == "secret-key"


def test_200_returns_parsed_json_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": 42})

    client = _client(httpx.MockTransport(handler))
    assert client.get("/thing") == {"value": 42}


@pytest.mark.parametrize("status", [401, 403])
def test_401_403_raise_auth_error(status: int) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": "denied"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationAuthError) as excinfo:
        client.get("/thing")
    assert excinfo.value.status_code == status
    assert "secret-key" not in str(excinfo.value)


def test_404_raises_not_found_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "missing"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationNotFoundError):
        client.get("/thing")


def test_500_raises_server_error_without_leaking_credentials() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationServerError) as excinfo:
        client.get("/thing")
    assert "secret-key" not in str(excinfo.value)


def test_other_4xx_raises_unexpected_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(418, json={"error": "teapot"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationUnexpectedError):
        client.get("/thing")


def test_invalid_json_raises_validation_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json{{{")

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationValidationError):
        client.get("/thing")


def test_non_object_json_raises_validation_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationValidationError):
        client.get("/thing")


def test_timeout_raises_integration_timeout_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationTimeoutError):
        client.get("/thing")


def test_network_error_raises_unexpected_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationUnexpectedError):
        client.get("/thing")
