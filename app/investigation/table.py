"""Fixed, documented lookup table driving the deterministic mock AI provider.

Keyed on (deterministic triage decision, severity bucket, enrichment
reputation bucket), in the same spirit as the Stage 1 mock enrichment table
in app/enrichment/table.py. This makes the mapping from triage outcome to
mock AI output traceable and reviewable without guessing, and is referenced
directly by tests.
"""

from dataclasses import dataclass

from app.models import AIConfidence, AIRiskAssessment, EnrichmentResult, Severity, TriageDecision
from app.models.alert import HIGH_RISK_SEVERITIES


@dataclass(frozen=True)
class MockInvestigationEntry:
    risk_assessment: AIRiskAssessment
    confidence: AIConfidence


# Documented rows (see docs/ai-security-design.md for the full rationale):
#
# | Triage decision  | Severity     | Enrichment reputation | risk_assessment | confidence |
# |-------------------|--------------|------------------------|------------------|------------|
# | ESCALATE          | HIGH/CRITICAL| malicious              | HIGH             | HIGH       |
# | ANALYST_REVIEW     | any          | unavailable            | UNCERTAIN        | LOW        |
# | LOW_RISK           | LOW/MEDIUM   | benign                 | LOW              | HIGH       |
# | (unmatched)        | -            | -                      | UNCERTAIN        | LOW        |
SEVERITY_HIGH = "high"
SEVERITY_LOW = "low"
REPUTATION_MALICIOUS = "malicious"
REPUTATION_BENIGN = "benign"
REPUTATION_UNKNOWN = "unknown"
REPUTATION_UNAVAILABLE = "unavailable"
ANY_SEVERITY = "any"

AI_INVESTIGATION_TABLE: dict[tuple[TriageDecision, str, str], MockInvestigationEntry] = {
    (TriageDecision.ESCALATE, SEVERITY_HIGH, REPUTATION_MALICIOUS): MockInvestigationEntry(
        AIRiskAssessment.HIGH, AIConfidence.HIGH
    ),
    (TriageDecision.ANALYST_REVIEW, ANY_SEVERITY, REPUTATION_UNAVAILABLE): MockInvestigationEntry(
        AIRiskAssessment.UNCERTAIN, AIConfidence.LOW
    ),
    (TriageDecision.LOW_RISK, SEVERITY_LOW, REPUTATION_BENIGN): MockInvestigationEntry(
        AIRiskAssessment.LOW, AIConfidence.HIGH
    ),
}

UNMATCHED_ENTRY = MockInvestigationEntry(AIRiskAssessment.UNCERTAIN, AIConfidence.LOW)


def severity_bucket(severity: Severity) -> str:
    return SEVERITY_HIGH if severity in HIGH_RISK_SEVERITIES else SEVERITY_LOW


def reputation_bucket(enrichment: list[EnrichmentResult]) -> str:
    if not enrichment or any(not item.available for item in enrichment):
        return REPUTATION_UNAVAILABLE
    reputations = {item.reputation.value for item in enrichment}
    if REPUTATION_MALICIOUS in reputations:
        return REPUTATION_MALICIOUS
    # Mirrors the deterministic Rule C definition of "safe-looking" evidence:
    # benign, or unknown-with-low-confidence (i.e. nothing meaningful found).
    if all(
        item.reputation.value == REPUTATION_BENIGN
        or (item.reputation.value == REPUTATION_UNKNOWN and item.confidence.value == "low")
        for item in enrichment
    ):
        return REPUTATION_BENIGN
    return REPUTATION_UNKNOWN


def lookup_mock_entry(
    decision: TriageDecision, severity: Severity, enrichment: list[EnrichmentResult]
) -> MockInvestigationEntry:
    rep_bucket = reputation_bucket(enrichment)
    if rep_bucket == REPUTATION_UNAVAILABLE:
        wildcard_key = (decision, ANY_SEVERITY, REPUTATION_UNAVAILABLE)
        if wildcard_key in AI_INVESTIGATION_TABLE:
            return AI_INVESTIGATION_TABLE[wildcard_key]
    key = (decision, severity_bucket(severity), rep_bucket)
    return AI_INVESTIGATION_TABLE.get(key, UNMATCHED_ENTRY)
