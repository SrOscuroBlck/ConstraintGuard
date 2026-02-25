from constraintguard.models.enums import score_to_tier
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem, RuleFiring
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.scoring.base_scores import base_score_for_category
from constraintguard.scoring.rules import RULE_REGISTRY

_SCORE_MIN = 0
_SCORE_MAX = 100

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "buffer_overflow": (
        "Replace unsafe string/memory operations with size-bounded equivalents "
        "(e.g., strncpy, snprintf, memcpy with explicit length checks). "
        "Validate all input lengths before copying into fixed-size buffers."
    ),
    "null_deref": (
        "Add null-pointer guards before every pointer dereference. "
        "Use assertion macros in debug builds and explicit error-return paths in production."
    ),
    "leak": (
        "Ensure every allocation has a corresponding free on all exit paths. "
        "Consider RAII patterns (C++) or ownership-tracking macros (C) to make lifetime explicit."
    ),
    "use_after_free": (
        "Set pointers to NULL immediately after freeing. "
        "Audit all pointer copies and lifetime boundaries; prefer single-owner allocation patterns."
    ),
    "integer_overflow": (
        "Validate arithmetic operands against their type bounds before computation. "
        "Use compiler sanitizers (UBSan) during testing and consider safe-integer wrappers."
    ),
    "format_string": (
        "Replace user-controlled format strings with a fixed format literal. "
        "Always pass a format string explicitly: printf(\"%s\", user_input)."
    ),
    "divide_by_zero": (
        "Guard all divisors with an explicit non-zero check before division. "
        "Return an error or safe default value when the divisor is zero."
    ),
    "uninitialized": (
        "Initialize all variables at declaration. "
        "Enable -Wuninitialized/-Wmaybe-uninitialized compiler warnings and treat them as errors."
    ),
    "deadlock": (
        "Enforce a consistent global lock-acquisition ordering across all execution paths. "
        "Avoid holding locks while calling functions that may acquire additional locks."
    ),
    "unknown": (
        "Review the finding manually and apply the principle of least privilege. "
        "Consult the tool documentation for the specific rule that triggered this finding."
    ),
}

_DEFAULT_REMEDIATION = _REMEDIATION_TEMPLATES["unknown"]


def _apply_rules(vuln: Vulnerability, spec: HardwareSpec) -> list[RuleFiring]:
    firings: list[RuleFiring] = []
    for rule_fn in RULE_REGISTRY:
        firing = rule_fn(vuln, spec)
        if firing is not None:
            firings.append(firing)
    return firings


def _clip_score(score: int) -> int:
    return max(_SCORE_MIN, min(_SCORE_MAX, score))


def _build_explanation(
    vuln: Vulnerability,
    base_score: int,
    final_score: int,
    firings: list[RuleFiring],
) -> str:
    if not firings:
        return (
            f"Base {vuln.category} finding (base score {base_score}). "
            "No constraint-specific escalations applied."
        )

    rule_rationales = " ".join(f"{f.rationale}" for f in firings)
    return (
        f"Base {vuln.category} finding (base score {base_score}). "
        f"Constraint escalations applied: {rule_rationales} "
        f"Final score: {final_score}."
    )


def _build_remediation(category: str) -> str:
    return _REMEDIATION_TEMPLATES.get(category, _DEFAULT_REMEDIATION)


def score_vulnerability(vuln: Vulnerability, spec: HardwareSpec) -> RiskItem:
    base_score = base_score_for_category(vuln.category)
    firings = _apply_rules(vuln, spec)
    raw_final = base_score + sum(f.delta for f in firings)
    final_score = _clip_score(raw_final)
    tier = score_to_tier(final_score)
    explanation = _build_explanation(vuln, base_score, final_score, firings)
    remediation = _build_remediation(vuln.category)

    return RiskItem(
        vulnerability=vuln,
        base_score=base_score,
        final_score=final_score,
        tier=tier,
        rule_firings=firings,
        explanation=explanation,
        remediation=remediation,
    )


def score_all(vulns: list[Vulnerability], spec: HardwareSpec) -> list[RiskItem]:
    items = [score_vulnerability(vuln, spec) for vuln in vulns]
    return sorted(
        items,
        key=lambda item: (
            -item.final_score,
            item.vulnerability.path,
            item.vulnerability.start_line or 0,
        ),
    )
