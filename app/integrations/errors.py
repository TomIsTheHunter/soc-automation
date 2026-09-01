"""Error model for external security-integration providers.

Every failure mode a provider client can hit is classified into one of
these distinct types, so callers (provider adapters, the workflow) can
react deliberately instead of catching a generic exception. Messages must
never include request/response headers, query strings, or credential
values - only safe, non-sensitive context (provider name, HTTP status).
"""


class IntegrationError(RuntimeError):
    """Base class for all security-integration failures."""

    def __init__(self, message: str, *, provider: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class IntegrationAuthError(IntegrationError):
    """Authentication or authorization was rejected by the provider (401/403)."""


class IntegrationNotFoundError(IntegrationError):
    """The requested resource does not exist at the provider (404)."""


class IntegrationValidationError(IntegrationError):
    """The provider's response body was not valid JSON or did not match its schema."""


class IntegrationServerError(IntegrationError):
    """The provider reported a server-side failure (5xx)."""


class IntegrationTimeoutError(IntegrationError):
    """The request to the provider timed out or the network was unreachable."""


class IntegrationUnexpectedError(IntegrationError):
    """An unexpected, otherwise-unclassified integration failure."""
