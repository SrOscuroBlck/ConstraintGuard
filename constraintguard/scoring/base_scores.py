from constraintguard.models.enums import VulnerabilityCategory

CATEGORY_BASE_SCORES: dict[VulnerabilityCategory, int] = {
    VulnerabilityCategory.USE_AFTER_FREE: 65,
    VulnerabilityCategory.BUFFER_OVERFLOW: 60,
    VulnerabilityCategory.FORMAT_STRING: 55,
    VulnerabilityCategory.NULL_DEREF: 50,
    VulnerabilityCategory.INTEGER_OVERFLOW: 50,
    VulnerabilityCategory.LEAK: 45,
    VulnerabilityCategory.DEADLOCK: 45,
    VulnerabilityCategory.DIVIDE_BY_ZERO: 40,
    VulnerabilityCategory.UNINITIALIZED: 40,
    VulnerabilityCategory.UNKNOWN: 35,
}

DEFAULT_BASE_SCORE = 35


def base_score_for_category(category: VulnerabilityCategory) -> int:
    return CATEGORY_BASE_SCORES.get(category, DEFAULT_BASE_SCORE)
