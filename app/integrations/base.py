"""Reusable HTTP client foundation for external security-integration providers.

Centralizes the plumbing every provider adapter would otherwise duplicate:
base URL, auth headers, timeout, request execution, and response
classification into `app.integrations.errors`. A provider adapter (e.g.
`app.integrations.enrichment.threat_intel`) only needs to know its own
endpoint paths and response schema - it never touches `httpx` directly.

Deliberately minimal: two small auth strategies plus one client class, no
plugin registry, retry policy, or generic request-building DSL. Retries,
pagination, and rate limiting are intentionally out of scope for this
foundation (see docs/integration-architecture.md) and should be added here
only when a provider actually needs them.
"""

import logging
from typing import Any, Protocol

import httpx

from app.integrations.errors import (
    IntegrationAuthError,
    IntegrationNotFoundError,
    IntegrationServerError,
    IntegrationTimeoutError,
    IntegrationUnexpectedError,
    IntegrationValidationError,
)
from app.observability import log_event

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 5.0


class AuthStrategy(Protocol):
    """Produces the headers needed to authenticate one request."""

    def headers(self) -> dict[str, str]: ...


class ApiKeyAuth:
    """API-key authentication applied via a configurable request header."""

    def __init__(self, api_key: str, header_name: str = "X-API-Key") -> None:
        self._api_key = api_key
        self._header_name = header_name

    def headers(self) -> dict[str, str]:
        return {self._header_name: self._api_key}


class BearerTokenAuth:
    """Bearer-token authentication applied via the `Authorization` header."""

    def __init__(self, token: str) -> None:
        self._token = token

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}


class BaseIntegrationClient:
    """Shared request/response plumbing for one external security provider."""

    def __init__(
        self,
        *,
        provider_name: str,
        base_url: str,
        auth: AuthStrategy,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.provider_name = provider_name
        self._auth = auth
        self._client = httpx.Client(base_url=base_url, timeout=timeout_seconds, transport=transport)

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Perform an authenticated GET and return the parsed JSON body.

        Every failure mode - timeout, network error, non-2xx status,
        invalid JSON - is raised as a subclass of `IntegrationError`.
        Callers never see a raw `httpx` exception or an unparsed response.
        """
        headers = {"Accept": "application/json", **self._auth.headers()}
        try:
            response = self._client.get(path, params=params, headers=headers)
        except httpx.TimeoutException as exc:
            log_event(
                logger,
                logging.WARNING,
                f"Request to {self.provider_name} timed out",
                event="provider_degraded",
                provider=self.provider_name,
                result="unavailable",
                error_type=type(exc).__name__,
            )
            raise IntegrationTimeoutError(
                f"Request to {self.provider_name} timed out", provider=self.provider_name
            ) from exc
        except httpx.HTTPError as exc:
            log_event(
                logger,
                logging.WARNING,
                f"Request to {self.provider_name} failed",
                event="provider_degraded",
                provider=self.provider_name,
                result="unavailable",
                error_type=type(exc).__name__,
            )
            raise IntegrationUnexpectedError(
                f"Request to {self.provider_name} failed", provider=self.provider_name
            ) from exc

        return self._parse_response(response)

    def _parse_response(self, response: httpx.Response) -> dict[str, Any]:
        status = response.status_code
        if status in (401, 403):
            raise IntegrationAuthError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        if status == 404:
            raise IntegrationNotFoundError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        if status >= 500:
            raise IntegrationServerError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        if status >= 400:
            raise IntegrationUnexpectedError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        try:
            body: Any = response.json()
        except ValueError as exc:
            raise IntegrationValidationError(
                f"{self.provider_name} returned a response that was not valid JSON",
                provider=self.provider_name,
                status_code=status,
            ) from exc
        if not isinstance(body, dict):
            raise IntegrationValidationError(
                f"{self.provider_name} returned an unexpected JSON shape",
                provider=self.provider_name,
                status_code=status,
            )
        return body

    def close(self) -> None:
        self._client.close()
