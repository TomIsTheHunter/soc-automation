"""Optional live AI provider (Anthropic).

NOT required for Stage 2. Never imported at module load time by the base
application; only constructed if AI_PROVIDER selects a live provider. The
anthropic SDK import happens lazily inside `__init__`, so the base install
and CI never need the optional `live-ai` extra, and a missing SDK or
missing credentials degrades safely to `InvestigationUnavailableError`
(the caller falls back to the mock provider; see app/main.py).

Retry policy (see docs/adr/001-failure-handling.md): the Anthropic SDK
already implements a bounded, exponential-backoff retry policy for
transient failures (connection errors, request timeouts, HTTP 429/5xx),
honoring `Retry-After` where the server sends one. Authentication (401),
authorization (403), and invalid-request (4xx other than 408/409/429)
errors are never retried by the SDK. Rather than re-implementing that
policy, this module makes the bound explicit via `max_retries` (configured
through `Settings.ai_live_max_retries`, see app/config.py) and classifies
the resulting exception for logging so operators can tell *why* a call
ultimately failed without leaking SDK-specific types into the rest of the
application - every failure still degrades to `InvestigationUnavailableError`.
"""

import asyncio
import json
import logging
from typing import Any

from app.investigation.assistant import InvestigationAssistant, InvestigationUnavailableError
from app.investigation.prompt import build_investigation_prompt
from app.models import InvestigationContext

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-3-5-haiku-latest"
LIVE_PROVIDER_NAME = "anthropic-live"
DEFAULT_MAX_RETRIES = 2


class AnthropicInvestigationAssistant(InvestigationAssistant):
    """Live provider behind the same bounded interface as the mock provider.

    Requires the optional `live-ai` extra and an API key, passed in
    explicitly by the caller (`app/main.py`, sourced from
    `app.config.Settings.anthropic_api_key`). This class never reads
    `os.environ` itself - the centralized `Settings` model is the single
    place credentials are read from.
    """

    def __init__(
        self, api_key: str | None, model: str | None = None, max_retries: int = DEFAULT_MAX_RETRIES
    ) -> None:
        if not api_key:
            raise InvestigationUnavailableError("ANTHROPIC_API_KEY is not configured")
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise InvestigationUnavailableError(
                "anthropic SDK is not installed; install the 'live-ai' extra"
            ) from exc
        self._anthropic = anthropic
        self._client = anthropic.AsyncAnthropic(api_key=api_key, max_retries=max_retries)
        self._model = model or DEFAULT_MODEL

    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        prompt = build_investigation_prompt(context)
        try:
            response = await asyncio.wait_for(
                self._client.messages.create(
                    model=self._model,
                    max_tokens=1024,
                    system=prompt.system_instruction,
                    messages=[{"role": "user", "content": prompt.untrusted_data}],
                ),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            raise
        except (self._anthropic.AuthenticationError, self._anthropic.PermissionDeniedError) as exc:
            # Never retried (by the SDK or by us): credentials/authorization problems
            # will not resolve themselves on a subsequent identical request.
            logger.warning("Live investigation provider auth/permission failure: %s", exc)
            raise InvestigationUnavailableError(
                f"live investigation provider auth/permission failure: {exc}"
            ) from exc
        except self._anthropic.RateLimitError as exc:
            # Already bounded-retried by the SDK (honoring Retry-After) before reaching here.
            logger.warning("Live investigation provider rate-limited: %s", exc)
            raise InvestigationUnavailableError(
                f"live investigation provider rate-limited: {exc}"
            ) from exc
        except (self._anthropic.APIConnectionError, self._anthropic.APIStatusError) as exc:
            # Connection failures and 5xx/408/409 are also already bounded-retried by
            # the SDK; other 4xx status errors (e.g. invalid request) are not retried.
            logger.warning("Live investigation provider request failed: %s", exc)
            raise InvestigationUnavailableError(
                f"live investigation provider request failed: {exc}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - any other SDK failure must degrade safely
            logger.exception("Unexpected live investigation provider failure")
            raise InvestigationUnavailableError(
                f"live investigation provider failed: {exc}"
            ) from exc

        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        try:
            return dict(json.loads(text))
        except (json.JSONDecodeError, TypeError) as exc:
            raise InvestigationUnavailableError(
                f"live provider returned non-JSON structured output: {exc}"
            ) from exc
