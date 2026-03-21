"""Rule family ablation for Experiment 7.

For each rule family, score vulnerabilities with that family excluded,
then compute the mean absolute score delta vs. the full scoring.
This tells us how much each family contributes to the final rankings.
"""

from __future__ import annotations

from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem, RuleFiring
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.scoring.base_scores import base_score_for_category
from constraintguard.scoring.engine import _clip_score, score_vulnerability
from constraintguard.scoring.rules import RULE_REGISTRY
from constraintguard.reporting.explanation import build_explanation
from constraintguard.reporting.remediation import build_remediation
from constraintguard.models.enums import score_to_tier

from eval.harness.metrics import vuln_key

# Rule families: maps family name → list of rule function names to EXCLUDE when ablating
RULE_FAMILIES: dict[str, list[str]] = {
    "Memory": [
        "_rule_mem_stack_tight",
        "_rule_mem_heap_tight",
        "_rule_mem_ram_tight",
        "_rule_mem_no_dynamic",
    ],
    "ISR": [
        "_rule_isr_func_name",
        "_rule_isr_latency_overflow",
        "_rule_isr_deadlock",
    ],
    "Safety": [
        "_rule_safety_asil_strict",
        "_rule_safety_functional",
        "_rule_safety_int_overflow",
    ],
    "RT-Hazard": [
        "_rule_time_ultra_tight",
        "_rule_latency_deadlock",
    ],
    "Lifetime": [
        "_rule_lifetime_leak_accumulate",
    ],
}


def _score_with_subset(
    vuln: Vulnerability,
    spec: HardwareSpec,
    rule_subset: list,
) -> RiskItem:
    """Score a single vulnerability using only rules in rule_subset."""
    base_score = base_score_for_category(vuln.category)
    firings: list[RuleFiring] = []
    for rule_fn in rule_subset:
        firing = rule_fn(vuln, spec)
        if firing is not None:
            firings.append(firing)
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


def score_with_family_excluded(
    vulns: list[Vulnerability],
    spec: HardwareSpec,
    excluded_family: str,
) -> list[RiskItem]:
    """Score all vulnerabilities excluding one rule family."""
    excluded_names = set(RULE_FAMILIES[excluded_family])
    subset = [r for r in RULE_REGISTRY if r.__name__ not in excluded_names]
    items = [_score_with_subset(v, spec, subset) for v in vulns]
    return sorted(
        items,
        key=lambda i: (-i.final_score, i.vulnerability.path, i.vulnerability.start_line or 0),
    )


def family_contribution(
    full_items: list[RiskItem],
    ablated_items: list[RiskItem],
) -> float:
    """Mean absolute score delta when a family is excluded.

    Higher = that family contributed more to the scoring.
    """
    full_map = {vuln_key(i): i.final_score for i in full_items}
    ablated_map = {vuln_key(i): i.final_score for i in ablated_items}
    common_keys = set(full_map) & set(ablated_map)
    if not common_keys:
        return 0.0
    deltas = [abs(full_map[k] - ablated_map[k]) for k in common_keys]
    return sum(deltas) / len(deltas)


def compute_all_family_contributions(
    vulns: list[Vulnerability],
    full_items: list[RiskItem],
    spec: HardwareSpec,
) -> dict[str, float]:
    """Compute contribution % for each rule family.

    Returns a dict mapping family name → contribution % (normalized, sums to ~100).
    """
    raw: dict[str, float] = {}
    for family in RULE_FAMILIES:
        ablated = score_with_family_excluded(vulns, spec, family)
        raw[family] = family_contribution(full_items, ablated)

    total = sum(raw.values())
    if total == 0:
        return {f: 0.0 for f in raw}
    return {f: (v / total) * 100 for f, v in raw.items()}
