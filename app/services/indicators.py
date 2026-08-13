from app.models import Indicator, IndicatorType, NormalizedAlert


def extract_indicators(alert: NormalizedAlert) -> list[Indicator]:
    indicators: list[Indicator] = []
    if alert.source_ip is not None:
        indicators.append(
            Indicator(type=IndicatorType.IP, value=str(alert.source_ip), source="source_ip")
        )
    if alert.destination_ip is not None:
        indicators.append(
            Indicator(
                type=IndicatorType.IP, value=str(alert.destination_ip), source="destination_ip"
            )
        )
    if alert.file_hash is not None:
        indicators.append(
            Indicator(type=IndicatorType.HASH, value=alert.file_hash.lower(), source="file_hash")
        )
    return indicators
