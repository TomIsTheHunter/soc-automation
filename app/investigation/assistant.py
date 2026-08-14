"""The InvestigationAssistant abstraction.

The rest of the application depends on this abstraction, never on a
specific LLM SDK. Implementations must accept an explicit timeout at the
call signature and must not perform silent automatic retries.
"""

from abc import ABC, abstractmethod
from typing import Any

from app.models import InvestigationContext


class InvestigationUnavailableError(RuntimeError):
    """Raised when the AI investigation provider cannot produce a result."""


class InvestigationAssistant(ABC):
    @abstractmethod
    async def investigate(
        self, context: InvestigationContext, timeout_seconds: float
    ) -> dict[str, Any]:
        """Return raw, not-yet-validated structured output for the given context.

        Implementations must respect `timeout_seconds` and must not perform
        silent automatic retries. Callers additionally enforce the timeout
        with `asyncio.wait_for` as a call-site backstop.
        """
        raise NotImplementedError
