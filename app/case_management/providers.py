"""The CaseManagementProvider abstraction: create SOC cases, incidents, or tickets.

Mirrors `app/enrichment/providers.py` and `app/vulnerability/providers.py`.
Unlike those two read-only categories, case creation is a side-effecting
write: calling it twice creates two incidents, not the same one. Every
`create_case()` accepts an optional `idempotency_key` for exactly that
reason - see `app/integrations/case_management/incident_desk.py` and
docs/adr/003-idempotent-writes.md.
"""

from abc import ABC, abstractmethod

from app.models import CaseResult, CaseStatus


class CaseManagementUnavailableError(RuntimeError):
    """Raised when a case cannot be created."""


class CaseManagementProvider(ABC):
    @abstractmethod
    def create_case(
        self, *, alert_id: str, summary: str, idempotency_key: str | None = None
    ) -> CaseResult:
        raise NotImplementedError


class MockCaseManagementProvider(CaseManagementProvider):
    """In-memory deterministic mock.

    Idempotent by construction: repeating the same `idempotency_key`
    (default: the alert ID itself, since one alert should only ever
    produce one case) returns the same `CaseResult` instead of creating a
    second one - mirroring the HTTP-integration provider's contract even
    though there is no real network retry concern in-process.
    """

    def __init__(self) -> None:
        self._cases_by_key: dict[str, CaseResult] = {}
        self._next_id = 1

    def create_case(
        self, *, alert_id: str, summary: str, idempotency_key: str | None = None
    ) -> CaseResult:
        key = idempotency_key or alert_id
        existing = self._cases_by_key.get(key)
        if existing is not None:
            return existing
        case = CaseResult(case_id=f"CASE-{self._next_id}", status=CaseStatus.OPEN)
        self._next_id += 1
        self._cases_by_key[key] = case
        return case


class FailingCaseManagementProvider(CaseManagementProvider):
    def create_case(
        self, *, alert_id: str, summary: str, idempotency_key: str | None = None
    ) -> CaseResult:
        raise CaseManagementUnavailableError(
            f"synthetic case management unavailable for alert {alert_id}"
        )
