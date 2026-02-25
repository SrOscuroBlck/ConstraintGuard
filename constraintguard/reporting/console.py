import textwrap

from constraintguard.models.enums import SeverityTier
from constraintguard.models.risk_report import RiskItem, RiskReport
from constraintguard.reporting.constraints_summary import build_constraints_summary_lines

_SECTION_WIDTH = 72
_SECTION_LINE = "═" * _SECTION_WIDTH
_RULE_LINE = "─" * _SECTION_WIDTH
_INDENT = "  "
_BODY_INDENT = "    "
_WRAP_WIDTH = 68

_TIER_LABEL_WIDTH = 10

_TIER_DISPLAY: dict[SeverityTier, str] = {
    SeverityTier.CRITICAL: "CRITICAL",
    SeverityTier.HIGH: "HIGH",
    SeverityTier.MEDIUM: "MEDIUM",
    SeverityTier.LOW: "LOW",
}


def _tier_bar(count: int, max_count: int, bar_width: int = 20) -> str:
    if max_count == 0 or count == 0:
        return "░" * bar_width
    filled = max(1, round((count / max_count) * bar_width))
    return "█" * filled + "░" * (bar_width - filled)


def _fired_rules_line(item: RiskItem) -> str:
    if not item.rule_firings:
        return "none"
    parts = [f"{f.rule_id}({f.delta:+d})" for f in item.rule_firings]
    return ", ".join(parts)


def _print_section_header(title: str) -> None:
    print(_SECTION_LINE)
    print(f"{_INDENT}{title}")
    print(_SECTION_LINE)


def _print_rule_header(title: str) -> None:
    print(_RULE_LINE)
    print(f"{_INDENT}{title}")
    print(_RULE_LINE)


def _print_constraints_block(report: RiskReport) -> None:
    _print_rule_header("Constraint Profile")
    for line in build_constraints_summary_lines(report.hardware_spec, report.provenance):
        print(f"{_INDENT}{line}")
    print()


def _print_severity_distribution(report: RiskReport) -> None:
    counts = report.summary.tier_counts
    tier_values: dict[SeverityTier, int] = {
        SeverityTier.CRITICAL: counts.critical,
        SeverityTier.HIGH: counts.high,
        SeverityTier.MEDIUM: counts.medium,
        SeverityTier.LOW: counts.low,
    }
    max_count = max(tier_values.values(), default=1) or 1
    _print_rule_header("Severity Distribution")
    for tier, count in tier_values.items():
        label = _TIER_DISPLAY[tier].ljust(_TIER_LABEL_WIDTH)
        bar = _tier_bar(count, max_count)
        print(f"{_INDENT}{label}  {bar}  {count}")
    print(f"{_INDENT}{'Total:'.ljust(_TIER_LABEL_WIDTH)}  {' ' * 20}  {report.summary.total_findings}")
    print()


def _print_finding(rank: int, item: RiskItem) -> None:
    tier_label = _TIER_DISPLAY[item.tier]
    location = item.vulnerability.path
    if item.vulnerability.start_line:
        location = f"{location}:{item.vulnerability.start_line}"

    fn_part = f"  in {item.vulnerability.function}" if item.vulnerability.function else ""
    rule_part = f"  [{item.vulnerability.rule_id}]" if item.vulnerability.rule_id else ""

    print(f"{_INDENT}[{rank}] {tier_label}  score: {item.final_score}  category: {item.vulnerability.category}")
    print(f"{_BODY_INDENT}{location}{fn_part}{rule_part}")
    print()

    for line in textwrap.wrap(
        item.explanation,
        width=_WRAP_WIDTH,
        initial_indent=_BODY_INDENT,
        subsequent_indent=_BODY_INDENT,
    ):
        print(line)
    print()

    print(f"{_BODY_INDENT}Remediation:")
    for line in textwrap.wrap(
        item.remediation,
        width=_WRAP_WIDTH,
        initial_indent=_BODY_INDENT + "  ",
        subsequent_indent=_BODY_INDENT + "  ",
    ):
        print(line)
    print()

    print(f"{_BODY_INDENT}Fired rules: {_fired_rules_line(item)}")
    print()
    print(f"{_INDENT}{_RULE_LINE}")


def print_report_to_console(report: RiskReport, top_k: int = 10) -> None:
    platform = report.hardware_spec.platform or "embedded target"
    safety = (
        f" ({report.hardware_spec.safety_level})"
        if report.hardware_spec.safety_level
        else ""
    )
    timestamp = report.run_metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    print()
    _print_section_header(f"ConstraintGuard Risk Report — {platform}{safety}")
    print(f"{_INDENT}Run: {timestamp}")
    if report.run_metadata.source_path:
        print(f"{_INDENT}Source: {report.run_metadata.source_path}")
    if report.run_metadata.config_path:
        print(f"{_INDENT}Config: {report.run_metadata.config_path}")
    print()

    _print_constraints_block(report)
    _print_severity_distribution(report)

    top_items = report.items[:top_k]
    if not top_items:
        print(f"{_INDENT}No findings to display.")
        return

    _print_rule_header(f"Top {len(top_items)} Finding(s)")
    print()
    for rank, item in enumerate(top_items, start=1):
        _print_finding(rank, item)

    print()
