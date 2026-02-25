from constraintguard.models.enums import score_to_tier
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem, RuleFiring
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.reporting.explanation import build_explanation
from constraintguard.reporting.remediation import build_remediation
from constraintguard.scoring.base_scores import base_score_for_category
from constraintguard.scoring.rules import RULE_REGISTRY

_SCORE_MIN = 0
_SCORE_MAX = 100


def _apply_rules(vuln: Vulnerability, spec: HardwareSpec) -> list[RuleFiring]:
    firings: list[RuleFiring] = []
    for rule_fn in RULE_REGISTRY:
        firing = rule_fn(vuln, spec)
        if firing is not None:
            firings.append(firing)
    return firings


def _clip_score(score: int) -> int:
    return max(_SCORE_MIN, min(_SCORE_MAX, score))


def score_vulnerability(vuln: Vulnerability, spec: HardwareSpec) -> RiskItem:
    base_score = base_score_for_category(vuln.category)
    firings = _apply_rules(vuln, spec)
    raw_final = base_score + sum(f.delta for f in firings)
    final_score = _clip_score(raw_final)
    tier = score_to_tier(final_score)
    explanation = build_explanation(vuln, spec, base_score, final_score, firings)
    remediation = build_remediation(vuln.category, spec)

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
