from dataclasses import dataclass

from app.models import Confidence, IndicatorType, Reputation


@dataclass(frozen=True)
class LookupEntry:
    indicator_type: IndicatorType
    reputation: Reputation
    confidence: Confidence
    category: str | None


SYNTHETIC_HASH_MALICIOUS = "a" * 64
SYNTHETIC_HASH_BENIGN = "b" * 64

# Deliberately fixed and reviewable: this is synthetic evidence, not live TI.
SYNTHETIC_LOOKUP_TABLE: dict[str, LookupEntry] = {
    "198.51.100.10": LookupEntry(
        IndicatorType.IP, Reputation.MALICIOUS, Confidence.HIGH, "command-and-control"
    ),
    "203.0.113.10": LookupEntry(IndicatorType.IP, Reputation.BENIGN, Confidence.HIGH, None),
    SYNTHETIC_HASH_MALICIOUS: LookupEntry(
        IndicatorType.HASH, Reputation.MALICIOUS, Confidence.HIGH, "trojan"
    ),
    SYNTHETIC_HASH_BENIGN: LookupEntry(
        IndicatorType.HASH, Reputation.BENIGN, Confidence.HIGH, None
    ),
}
