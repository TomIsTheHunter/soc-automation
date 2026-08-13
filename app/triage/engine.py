from app.models import (
    HIGH_RISK_SEVERITIES,
    Confidence,
    EnrichmentResult,
    NormalizedAlert,
    Reputation,
    Severity,
    TriageDecision,
    TriageResult,
)

RULE_ENRICHMENT_UNAVAILABLE = "RULE_B_ENRICHMENT_UNAVAILABLE"
RULE_HIGH_RISK_MALICIOUS = "RULE_A_HIGH_RISK_MALICIOUS"
RULE_LOW_RISK_BENIGN_OR_UNKNOWN = "RULE_C_LOW_RISK_BENIGN_OR_UNKNOWN"
RULE_AMBIGUOUS_CATCH_ALL = "RULE_D_AMBIGUOUS_CATCH_ALL"


def triage_alert(
    alert: NormalizedAlert, enrichment: list[EnrichmentResult], enrichment_available: bool
) -> TriageResult:
    reputations = {item.reputation for item in enrichment}
    if not enrichment_available:
        return TriageResult(
            decision=TriageDecision.ANALYST_REVIEW,
            rules_triggered=[RULE_ENRICHMENT_UNAVAILABLE],
            reason=(
                "Enrichment was unavailable; the alert is routed to analyst review "
                "without assuming safety."
            ),
            evidence={"severity": alert.severity, "enrichment_available": False},
        )

    if alert.severity in HIGH_RISK_SEVERITIES and Reputation.MALICIOUS in reputations:
        return TriageResult(
            decision=TriageDecision.ESCALATE,
            rules_triggered=[RULE_HIGH_RISK_MALICIOUS],
            reason="High-risk severity is supported by malicious enrichment evidence.",
            evidence={"severity": alert.severity, "reputations": sorted(reputations)},
        )

    if (
        alert.severity in {Severity.LOW, Severity.MEDIUM}
        and reputations
        <= {
            Reputation.BENIGN,
            Reputation.UNKNOWN,
        }
        and all(
            item.reputation == Reputation.BENIGN or item.confidence == Confidence.LOW
            for item in enrichment
        )
    ):
        return TriageResult(
            decision=TriageDecision.LOW_RISK,
            rules_triggered=[RULE_LOW_RISK_BENIGN_OR_UNKNOWN],
            reason="Low or medium severity has only benign or low-confidence unknown enrichment.",
            evidence={"severity": alert.severity, "reputations": sorted(reputations)},
        )

    return TriageResult(
        decision=TriageDecision.ANALYST_REVIEW,
        rules_triggered=[RULE_AMBIGUOUS_CATCH_ALL],
        reason=(
            "Signals are conflicting or outside the deterministic low-risk and escalation rules."
        ),
        evidence={"severity": alert.severity, "reputations": sorted(reputations)},
    )
