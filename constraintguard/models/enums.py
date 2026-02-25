from enum import Enum

CRITICAL_THRESHOLD = 85
HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40


class SeverityTier(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ConstraintSourceType(Enum):
    YAML = "yaml"
    LINKER_SCRIPT = "ld"
    DEFAULT = "default"
    UNKNOWN = "unknown"


def score_to_tier(score: int) -> SeverityTier:
    if score >= CRITICAL_THRESHOLD:
        return SeverityTier.CRITICAL
    if score >= HIGH_THRESHOLD:
        return SeverityTier.HIGH
    if score >= MEDIUM_THRESHOLD:
        return SeverityTier.MEDIUM
    return SeverityTier.LOW
