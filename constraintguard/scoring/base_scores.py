from constraintguard.models.enums import VulnerabilityCategory

CATEGORY_BASE_SCORES: dict[str, int] = {
    VulnerabilityCategory.USE_AFTER_FREE.value: 65,
    VulnerabilityCategory.BUFFER_OVERFLOW.value: 60,
    VulnerabilityCategory.FORMAT_STRING.value: 55,
    VulnerabilityCategory.NULL_DEREF.value: 50,
    VulnerabilityCategory.INTEGER_OVERFLOW.value: 50,
    VulnerabilityCategory.LEAK.value: 45,
    VulnerabilityCategory.DEADLOCK.value: 45,
    VulnerabilityCategory.DIVIDE_BY_ZERO.value: 40,
    VulnerabilityCategory.UNINITIALIZED.value: 40,
    VulnerabilityCategory.UNKNOWN.value: 35,
}

DEFAULT_BASE_SCORE = 35


def base_score_for_category(category: str) -> int:
    return CATEGORY_BASE_SCORES.get(category, DEFAULT_BASE_SCORE)
