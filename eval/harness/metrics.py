"""Evaluation metrics for ConstraintGuard experiments."""

from __future__ import annotations

from constraintguard.models.enums import SeverityTier
from constraintguard.models.risk_report import RiskItem


def vuln_key(item: RiskItem) -> str:
    """Stable key for a vulnerability: path:line:rule_id."""
    v = item.vulnerability
    return f"{v.path}:{v.start_line}:{v.rule_id}"


def precision_at_k(
    ranked: list[RiskItem],
    ground_truth: dict[str, bool],
    k: int,
) -> float:
    """Precision@K = (# true critical findings in top-K) / K."""
    if not ranked:
        return 0.0
    top_k = ranked[:k]
    hits = sum(1 for item in top_k if ground_truth.get(vuln_key(item), False))
    return hits / k


def demotion_rate(
    baseline: list[RiskItem],
    deterministic: list[RiskItem],
) -> float:
    """Fraction of baseline top-10 findings that fall below HIGH in deterministic ranking.

    'Below HIGH' means MEDIUM or LOW tier after constraint-aware scoring.
    """
    top10_keys = {vuln_key(i) for i in baseline[:10]}
    if not top10_keys:
        return 0.0
    det_tiers = {vuln_key(i): i.tier for i in deterministic}
    demoted = sum(
        1
        for k in top10_keys
        if det_tiers.get(k, SeverityTier.HIGH) in (SeverityTier.MEDIUM, SeverityTier.LOW)
    )
    return demoted / len(top10_keys)


def expert_agreement(
    deterministic: list[RiskItem],
    ground_truth: dict[str, bool],
) -> float:
    """% of expert labels matching ConstraintGuard tier assignment.

    A label is 'matching' if:
    - Expert says critical AND ConstraintGuard tier is CRITICAL or HIGH
    - Expert says not critical AND ConstraintGuard tier is MEDIUM or LOW
    """
    labeled = [(k, v) for k, v in ground_truth.items()]
    if not labeled:
        return 0.0

    det_tiers = {vuln_key(i): i.tier for i in deterministic}
    matches = 0
    for key, is_critical in labeled:
        tier = det_tiers.get(key)
        if tier is None:
            continue
        cg_critical = tier in (SeverityTier.CRITICAL, SeverityTier.HIGH)
        if is_critical == cg_critical:
            matches += 1

    return matches / len(labeled)
