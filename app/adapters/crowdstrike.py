from uuid import uuid4

from app.models import CrowdStrikeStyleAlert, NormalizedAlert

SUPPORTED_SOURCE = "crowdstrike-style-synthetic"


class UnsupportedSourceError(ValueError):
    """Raised when a payload is not from the supported synthetic source."""


class CrowdStrikeStyleAlertAdapter:
    """Translate the synthetic vendor shape into the vendor-neutral model."""

    def adapt(self, payload: CrowdStrikeStyleAlert) -> NormalizedAlert:
        if payload.source != SUPPORTED_SOURCE:
            raise UnsupportedSourceError(f"unsupported source: {payload.source}")
        return NormalizedAlert(
            source_alert_id=payload.alert_id,
            timestamp=payload.timestamp,
            hostname=payload.hostname,
            username=payload.username,
            severity=payload.severity,
            detection_description=payload.detection_description,
            process_name=payload.process_name,
            command_line=payload.command_line,
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            file_hash=payload.file_hash,
            source_metadata={"vendor": "synthetic-crowdstrike-style", "source": payload.source},
            internal_alert_id=uuid4(),
        )
