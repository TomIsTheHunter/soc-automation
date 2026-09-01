"""Reusable HTTP client foundation for external security-integration providers.

Centralizes the plumbing every provider adapter would otherwise duplicate:
base URL, auth headers, connect/read timeouts, bounded retry with backoff,
request execution, and response classification into
`app.integrations.errors`. A provider adapter (e.g.
`app.integrations.enrichment.threat_intel`) only needs to know its own
endpoint paths and response schema - it never touches `httpx` directly.

Resilience behavior (which failures are retried, backoff shape, `Retry-After`
handling) is documented and justified in
docs/adr/002-provider-resilience.md - this module implements that policy,
it does not restate the reasoning.

Deliberately minimal: two small auth strategies, one retry policy
dataclass, and one client class - no plugin registry, generic
request-building DSL, or second retry framework. Cursor-based pagination
is supported via `get_paginated()`, itself just a bounded loop over the
existing `get()` (retries/timeouts/logging already apply per page);
provider-specific/concurrency-based rate limiting remains out of scope
(see docs/integration-architecture.md) and should be added here only when
a provider actually needs it.
"""

import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.integrations.errors import (
    IntegrationAuthError,
    IntegrationNotFoundError,
    IntegrationRateLimitedError,
    IntegrationServerError,
    IntegrationTimeoutError,
    IntegrationUnexpectedError,
    IntegrationValidationError,
)
from app.observability import log_event

logger = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT_SECONDS = 2.0
DEFAULT_READ_TIMEOUT_SECONDS = 5.0

# Transient, worth retrying: rate limiting and gateway/availability signals.
# A plain 500 is deliberately excluded - see docs/adr/002-provider-resilience.md
# ("why a bare 500 is not retried by default").
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry behavior for transient integration failures.

    `max_attempts` includes the initial attempt (3 = 1 try + 2 retries).
    `max_retry_after_seconds` caps a provider-supplied `Retry-After` value
    so a malformed or malicious response can never cause an unbounded wait.
    """

    max_attempts: int = 3
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 8.0
    max_retry_after_seconds: float = 30.0


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


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def _parse_retry_after_seconds(value: str | None) -> float | None:
    """Parse a `Retry-After` header value (delay-seconds form only).

    Returns `None` for anything absent, negative, or not a plain number
    (including the HTTP-date form) - callers fall back to computed backoff
    rather than trusting an unparseable provider value.
    """
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    if seconds < 0:
        return None
    return seconds


class BaseIntegrationClient:
    """Shared request/response plumbing for one external security provider."""

    def __init__(
        self,
        *,
        provider_name: str,
        base_url: str,
        auth: AuthStrategy,
        connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
        retry_policy: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.provider_name = provider_name
        self._auth = auth
        self._retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep
        timeout = httpx.Timeout(
            connect=connect_timeout_seconds,
            read=read_timeout_seconds,
            write=read_timeout_seconds,
            pool=connect_timeout_seconds,
        )
        self._client = httpx.Client(base_url=base_url, timeout=timeout, transport=transport)

    def get(
        self, path: str, *, params: dict[str, Any] | None = None, operation: str | None = None
    ) -> dict[str, Any]:
        """Perform an authenticated GET, retrying transient failures, and return the JSON body.

        Every terminal failure mode - timeout, connection error, non-2xx
        status, invalid JSON - is raised as a subclass of `IntegrationError`.
        Only HTTP 429/502/503/504 and timeout/connection errors are ever
        retried, bounded by `self._retry_policy`; see
        docs/adr/002-provider-resilience.md for why every other failure
        class is not retried.
        """
        operation_name = operation or path
        headers = {"Accept": "application/json", **self._auth.headers()}
        attempt = 0
        while True:
            attempt += 1
            started = time.perf_counter()
            try:
                response = self._client.get(path, params=params, headers=headers)
            except httpx.TimeoutException as exc:
                if self._retry_after_exception(exc, attempt, operation_name, started):
                    continue
                raise IntegrationTimeoutError(
                    f"Request to {self.provider_name} timed out after {attempt} attempt(s)",
                    provider=self.provider_name,
                ) from exc
            except httpx.TransportError as exc:
                if self._retry_after_exception(exc, attempt, operation_name, started):
                    continue
                raise IntegrationTimeoutError(
                    f"Request to {self.provider_name} failed after {attempt} attempt(s) "
                    "(connection error)",
                    provider=self.provider_name,
                ) from exc
            except httpx.HTTPError as exc:
                self._log_failure(
                    operation_name, attempt, None, type(exc).__name__, _elapsed_ms(started)
                )
                raise IntegrationUnexpectedError(
                    f"Request to {self.provider_name} failed", provider=self.provider_name
                ) from exc

            status = response.status_code
            if status in RETRYABLE_STATUS_CODES and attempt < self._retry_policy.max_attempts:
                delay = self._compute_delay(attempt, response.headers.get("retry-after"))
                log_event(
                    logger,
                    logging.WARNING,
                    f"Request to {self.provider_name} returned HTTP {status}, retrying "
                    f"(attempt {attempt}/{self._retry_policy.max_attempts})",
                    event="provider_retry",
                    provider=self.provider_name,
                    operation=operation_name,
                    attempt=attempt,
                    status_code=status,
                    duration_ms=_elapsed_ms(started),
                    retry=True,
                )
                self._sleep(delay)
                continue
            return self._parse_response(response, operation_name, attempt, _elapsed_ms(started))

    def get_paginated(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        operation: str | None = None,
        items_key: str = "items",
        cursor_param: str = "cursor",
        next_cursor_key: str = "next_cursor",
        max_pages: int = 20,
    ) -> list[dict[str, Any]]:
        """Follow a cursor-paginated GET endpoint and return all items across pages.

        Each page is fetched via `get()`, so per-page auth/timeout/retry/
        logging behavior is unchanged - this only adds the cursor-following
        loop. Bounded by `max_pages` so a broken or malicious provider
        returning a cursor loop can never cause an unbounded number of
        requests, the same bounded philosophy as retries (see
        docs/adr/002-provider-resilience.md).
        """
        collected: list[dict[str, Any]] = []
        page_params = dict(params or {})
        for _ in range(max_pages):
            page = self.get(path, params=page_params, operation=operation)
            items = page.get(items_key)
            if not isinstance(items, list):
                raise IntegrationValidationError(
                    f"{self.provider_name} paginated response missing a {items_key!r} list",
                    provider=self.provider_name,
                )
            collected.extend(items)
            next_cursor = page.get(next_cursor_key)
            if not next_cursor:
                break
            page_params = {**(params or {}), cursor_param: next_cursor}
        return collected

    def _retry_after_exception(
        self, exc: Exception, attempt: int, operation: str, started: float
    ) -> bool:
        """Log a timeout/connection failure and decide whether to retry it.

        Returns `True` if the caller should retry (a delay has already been
        applied), `False` if retries are exhausted.
        """
        duration_ms = _elapsed_ms(started)
        error_type = type(exc).__name__
        if attempt < self._retry_policy.max_attempts:
            log_event(
                logger,
                logging.WARNING,
                f"Request to {self.provider_name} failed, retrying "
                f"(attempt {attempt}/{self._retry_policy.max_attempts})",
                event="provider_retry",
                provider=self.provider_name,
                operation=operation,
                attempt=attempt,
                duration_ms=duration_ms,
                retry=True,
                error_type=error_type,
            )
            self._sleep(self._compute_delay(attempt, None))
            return True
        self._log_failure(operation, attempt, None, error_type, duration_ms)
        return False

    def _compute_delay(self, attempt: int, retry_after_header: str | None) -> float:
        """Compute the bounded delay before the next attempt.

        A valid `Retry-After` is honored but capped at
        `max_retry_after_seconds`; otherwise falls back to exponential
        backoff capped at `backoff_max_seconds`, with jitter that never
        pushes the total past that same cap.
        """
        retry_after = _parse_retry_after_seconds(retry_after_header)
        if retry_after is not None:
            return min(retry_after, self._retry_policy.max_retry_after_seconds)
        base = min(
            self._retry_policy.backoff_base_seconds * (2.0 ** (attempt - 1)),
            self._retry_policy.backoff_max_seconds,
        )
        headroom = self._retry_policy.backoff_max_seconds - base
        jitter = random.uniform(0, headroom) if headroom > 0 else 0.0
        return base + jitter

    def _log_failure(
        self,
        operation: str,
        attempt: int,
        status_code: int | None,
        error_type: str,
        duration_ms: float,
    ) -> None:
        suffix = f" with HTTP {status_code}" if status_code is not None else ""
        log_event(
            logger,
            logging.WARNING,
            f"Request to {self.provider_name} failed{suffix} after {attempt} attempt(s)",
            event="provider_degraded",
            provider=self.provider_name,
            operation=operation,
            attempt=attempt,
            status_code=status_code,
            duration_ms=duration_ms,
            retry=False,
            error_type=error_type,
        )

    def _parse_response(
        self, response: httpx.Response, operation: str, attempt: int, duration_ms: float
    ) -> dict[str, Any]:
        status = response.status_code
        if status in (401, 403):
            self._log_failure(operation, attempt, status, "IntegrationAuthError", duration_ms)
            raise IntegrationAuthError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        if status == 404:
            self._log_failure(operation, attempt, status, "IntegrationNotFoundError", duration_ms)
            raise IntegrationNotFoundError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        if status == 429:
            self._log_failure(
                operation, attempt, status, "IntegrationRateLimitedError", duration_ms
            )
            raise IntegrationRateLimitedError(
                f"Request to {self.provider_name} was rate-limited after {attempt} attempt(s)",
                provider=self.provider_name,
                status_code=status,
            )
        if status >= 500:
            self._log_failure(operation, attempt, status, "IntegrationServerError", duration_ms)
            raise IntegrationServerError(
                f"Request to {self.provider_name} failed with HTTP {status} "
                f"after {attempt} attempt(s)",
                provider=self.provider_name,
                status_code=status,
            )
        if status >= 400:
            self._log_failure(operation, attempt, status, "IntegrationUnexpectedError", duration_ms)
            raise IntegrationUnexpectedError(
                f"Request to {self.provider_name} failed with HTTP {status}",
                provider=self.provider_name,
                status_code=status,
            )
        try:
            body: Any = response.json()
        except ValueError as exc:
            self._log_failure(operation, attempt, status, "IntegrationValidationError", duration_ms)
            raise IntegrationValidationError(
                f"{self.provider_name} returned a response that was not valid JSON",
                provider=self.provider_name,
                status_code=status,
            ) from exc
        if not isinstance(body, dict):
            self._log_failure(operation, attempt, status, "IntegrationValidationError", duration_ms)
            raise IntegrationValidationError(
                f"{self.provider_name} returned an unexpected JSON shape",
                provider=self.provider_name,
                status_code=status,
            )
        if attempt > 1:
            log_event(
                logger,
                logging.INFO,
                f"Request to {self.provider_name} succeeded after {attempt} attempt(s)",
                event="provider_recovered",
                provider=self.provider_name,
                operation=operation,
                attempt=attempt,
                status_code=status,
                duration_ms=duration_ms,
                retry=False,
            )
        return body

    def close(self) -> None:
        self._client.close()
