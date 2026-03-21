"""Full system re-ranking using LLM confidence signal.

The 'full system' adds a bounded score adjustment on top of the deterministic
expert system score. The LLM layer provides a confidence signal:
  +10 if the LLM generated at least one concrete fix suggestion
  +5  if any tag contains 'confirmed'
  -5  if any tag contains 'false-positive'
  0   otherwise (including no enrichment)

Max adjustment: +15, min adjustment: -5.
"""

from __future__ import annotations

from constraintguard.models.risk_report import RiskItem


def llm_delta(item: RiskItem) -> int:
    """Compute bounded LLM confidence adjustment for a RiskItem."""
    if item.enrichment is None:
        return 0

    delta = 0

    if item.enrichment.fix_suggestions:
        delta += 10

    tags = [t.lower() for t in item.enrichment.tags]
    if any("confirmed" in t for t in tags):
        delta += 5
    if any("false-positive" in t for t in tags):
        delta -= 5

    return delta


def get_full_system_ranking(deterministic: list[RiskItem]) -> list[RiskItem]:
    """Re-sort deterministic items using LLM confidence adjustment.

    Items without enrichment retain their deterministic position relative
    to one another (delta=0 preserves original order among ties).
    """
    return sorted(
        deterministic,
        key=lambda i: (-(i.final_score + llm_delta(i)), i.vulnerability.path, i.vulnerability.start_line or 0),
    )


def adjusted_score(item: RiskItem) -> int:
    """Return the full-system adjusted score for an item."""
    return item.final_score + llm_delta(item)
