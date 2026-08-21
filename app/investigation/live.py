"""Optional live AI provider (Anthropic).

NOT required for Stage 2. Never imported at module load time by the base
application; only constructed if AI_PROVIDER selects a live provider. The
anthropic SDK import happens lazily inside `__init__`, so the base install
and CI never need the optional `live-ai` extra, and a missing SDK or
missing credentials degrades safely to `InvestigationUnavailableError`
(the caller falls back to the mock provider; see app/main.py).
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


class AnthropicInvestigationAssistant(InvestigationAssistant):
    """Live provider behind the same bounded interface as the mock provider.

    Requires the optional `live-ai` extra and an API key, passed in
    explicitly by the caller (`app/main.py`, sourced from
    `app.config.Settings.anthropic_api_key`). This class never reads
    `os.environ` itself - the centralized `Settings` model is the single
    place credentials are read from.
    """

    def __init__(self, api_key: str | None, model: str | None = None) -> None:
        if not api_key:
            raise InvestigationUnavailableError("ANTHROPIC_API_KEY is not configured")
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise InvestigationUnavailableError(
                "anthropic SDK is not installed; install the 'live-ai' extra"
            ) from exc
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
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
        except Exception as exc:  # noqa: BLE001 - any SDK failure must degrade safely
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
