"""Schema and policy validation for AI investigation output.

Two independent layers of defense, applied in order:
1. Schema validation (Pydantic, `extra="forbid"`, controlled enums).
2. Policy validation: keyword denylist (defense-in-depth against a provider
   that ignores the vocabulary constraint) and evidence-grounding (a
   concrete, testable proxy for detecting fabricated evidence).

Rejection always records a specific, inspectable reason.
"""

from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from app.models import InvestigationContext, InvestigationResult

# Defense-in-depth keyword denylist. The vocabulary-constrained
# `recommended_actions` enum is the primary control; this scans free-text
# fields in case a provider ignores that constraint (relevant mainly for a
# live provider bypassing typed output).
POLICY_DENYLIST: tuple[str, ...] = (
    "isolate",
    "disable account",
    "delete",
    "execute",
    "close alert",
    "block",
    "remediate",
    "quarantine",
    "kill process",
    "revoke",
)


class InvestigationRejectionReason(StrEnum):
    SCHEMA_INVALID = "schema_invalid"
    POLICY_KEYWORD_MATCH = "policy_keyword_match"
    UNGROUNDED_EVIDENCE = "ungrounded_evidence"


class InvestigationValidationError(Exception):
    def __init__(self, reason: InvestigationRejectionReason, message: str) -> None:
        self.reason = reason
        super().__init__(message)


def validate_schema(raw: dict[str, Any]) -> InvestigationResult:
    try:
        return InvestigationResult.model_validate(raw)
    except ValidationError as exc:
        raise InvestigationValidationError(
            InvestigationRejectionReason.SCHEMA_INVALID, f"schema validation failed: {exc}"
        ) from exc


def validate_policy_keywords(result: InvestigationResult) -> None:
    haystack = " ".join(
        [
            result.summary,
            *result.key_evidence,
            *[action.value for action in result.recommended_actions],
        ]
    ).lower()
    for term in POLICY_DENYLIST:
        if term in haystack:
            raise InvestigationValidationError(
                InvestigationRejectionReason.POLICY_KEYWORD_MATCH,
                f"prohibited-action keyword matched: {term!r}",
            )


def _context_grounding_values(context: InvestigationContext) -> set[str]:
    values = {context.alert.hostname.lower(), context.alert.username.lower()}
    if context.alert.process_name:
        values.add(context.alert.process_name.lower())
    for indicator in context.indicators:
        values.add(indicator.value.lower())
    return values


def validate_evidence_grounding(result: InvestigationResult, context: InvestigationContext) -> None:
    grounding_values = _context_grounding_values(context)
    for evidence in result.key_evidence:
        lowered = evidence.lower()
        if not any(value in lowered for value in grounding_values):
            raise InvestigationValidationError(
                InvestigationRejectionReason.UNGROUNDED_EVIDENCE,
                "key_evidence entry references no value present in the investigation "
                f"context: {evidence!r}",
            )


def validate_investigation_result(
    raw: dict[str, Any], context: InvestigationContext
) -> InvestigationResult:
    """Full schema + policy pipeline. Raises `InvestigationValidationError` on rejection."""
    result = validate_schema(raw)
    validate_policy_keywords(result)
    validate_evidence_grounding(result, context)
    return result
