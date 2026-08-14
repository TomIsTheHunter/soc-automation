from app.models import DeterministicTriageContext, EnrichmentResult, Indicator
from app.models.alert import NormalizedAlert
from app.models.investigation import InvestigationAlertContext, InvestigationContext
from app.models.workflow import TriageResult


def build_investigation_context(
    alert: NormalizedAlert,
    indicators: list[Indicator],
    enrichment: list[EnrichmentResult],
    triage: TriageResult,
) -> InvestigationContext:
    """Build the minimized, explicitly allowlisted AI input.

    Only the fields documented in docs/ai-security-design.md are included;
    everything else on `NormalizedAlert` (e.g. raw source metadata) is
    deliberately excluded.
    """
    alert_context = InvestigationAlertContext(
        internal_alert_id=alert.internal_alert_id,
        timestamp=alert.timestamp,
        hostname=alert.hostname,
        username=alert.username,
        severity=alert.severity,
        detection_description=alert.detection_description,
        process_name=alert.process_name,
        command_line=alert.command_line,
    )
    triage_context = DeterministicTriageContext(
        decision=triage.decision,
        rules_triggered=triage.rules_triggered,
        reason=triage.reason,
    )
    return InvestigationContext(
        alert=alert_context,
        indicators=indicators,
        enrichment=enrichment,
        deterministic_triage=triage_context,
    )
