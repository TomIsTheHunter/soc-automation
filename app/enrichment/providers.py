from abc import ABC, abstractmethod

from app.enrichment.table import SYNTHETIC_LOOKUP_TABLE, LookupEntry
from app.models import Confidence, EnrichmentResult, Indicator, Reputation


class EnrichmentUnavailableError(RuntimeError):
    """Raised when enrichment cannot provide a trustworthy result."""


class EnrichmentProvider(ABC):
    @abstractmethod
    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        raise NotImplementedError


class MockEnrichmentProvider(EnrichmentProvider):
    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        entry: LookupEntry | None = SYNTHETIC_LOOKUP_TABLE.get(indicator.value)
        if entry is None:
            return EnrichmentResult(
                indicator=indicator,
                reputation=Reputation.UNKNOWN,
                confidence=Confidence.LOW,
            )
        return EnrichmentResult(
            indicator=indicator,
            reputation=entry.reputation,
            confidence=entry.confidence,
            category=entry.category,
        )


class FailingEnrichmentProvider(EnrichmentProvider):
    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        raise EnrichmentUnavailableError(f"synthetic enrichment unavailable for {indicator.value}")
