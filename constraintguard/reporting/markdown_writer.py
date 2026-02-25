from pathlib import Path

from constraintguard.models.enums import SeverityTier
from constraintguard.models.risk_report import RiskItem, RiskReport
from constraintguard.reporting.formatting import format_bytes, format_us

_REPORT_FILENAME = "report.md"
_JSON_REPORT_FILENAME = "report.json"

_TIER_ORDER = [SeverityTier.CRITICAL, SeverityTier.HIGH, SeverityTier.MEDIUM, SeverityTier.LOW]


def _header_section(report: RiskReport) -> list[str]:
    meta = report.run_metadata
    timestamp = meta.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# ConstraintGuard Risk Report",
        "",
        f"**Tool:** ConstraintGuard {meta.tool_version}  ",
        f"**Generated:** {timestamp}  ",
    ]
    if meta.source_path:
        lines.append(f"**Source:** {meta.source_path}  ")
    if meta.config_path:
        lines.append(f"**Config:** {meta.config_path}  ")
    if meta.command:
        lines += ["", f"```", f"{meta.command}", "```"]
    lines += ["", "---", ""]
    return lines


def _constraints_section(report: RiskReport) -> list[str]:
    spec = report.hardware_spec
    lines = ["## Constraint Profile", ""]

    if spec.platform:
        lines.append(f"- **Platform:** {spec.platform}  ")
    if spec.safety_level:
        lines.append(f"- **Safety Level:** {spec.safety_level}  ")

    mem_parts: list[str] = []
    if spec.ram_size_bytes is not None:
        mem_parts.append(f"RAM: {format_bytes(spec.ram_size_bytes)}")
    if spec.flash_size_bytes is not None:
        mem_parts.append(f"Flash: {format_bytes(spec.flash_size_bytes)}")
    if spec.stack_size_bytes is not None:
        mem_parts.append(f"Stack: {format_bytes(spec.stack_size_bytes)}")
    if spec.heap_size_bytes is not None:
        mem_parts.append(f"Heap: {format_bytes(spec.heap_size_bytes)}")
    if mem_parts:
        lines.append(f"- **Memory:** {'   '.join(mem_parts)}  ")

    if spec.max_interrupt_latency_us is not None:
        lines.append(f"- **Max IRQ Latency:** {format_us(spec.max_interrupt_latency_us)}  ")

    if spec.critical_functions:
        fn_list = ", ".join(f"`{fn}`" for fn in spec.critical_functions)
        lines.append(f"- **Critical Functions:** {fn_list}  ")

    prov = report.provenance
    if prov and prov.field_origins:
        sources = sorted({
            fp.source_path
            for fp in prov.field_origins.values()
            if fp.source_path
        })
        if sources:
            lines.append(f"- **Constraint Sources:** {', '.join(sources)}  ")

    lines += ["", "---", ""]
    return lines


def _distribution_section(report: RiskReport) -> list[str]:
    counts = report.summary.tier_counts
    tier_counts = {
        SeverityTier.CRITICAL: counts.critical,
        SeverityTier.HIGH: counts.high,
        SeverityTier.MEDIUM: counts.medium,
        SeverityTier.LOW: counts.low,
    }
    lines = [
        "## Severity Distribution",
        "",
        "| Tier | Count |",
        "|:-----|------:|",
    ]
    for tier in _TIER_ORDER:
        lines.append(f"| {tier.value} | {tier_counts[tier]} |")
    lines.append(f"| **Total** | **{report.summary.total_findings}** |")
    lines += ["", "---", ""]
    return lines


def _fired_rules_lines(item: RiskItem) -> list[str]:
    if not item.rule_firings:
        return []
    lines = ["**Fired rules:**  "]
    for firing in item.rule_firings:
        sign = "+" if firing.delta >= 0 else ""
        constraint_tags = ", ".join(f"`{c}`" for c in firing.constraints_used)
        constraint_str = f" — constraints: {constraint_tags}" if constraint_tags else ""
        lines.append(
            f"- `{firing.rule_id}` ({sign}{firing.delta}): {firing.rationale}{constraint_str}  "
        )
    return lines


def _finding_section(rank: int, item: RiskItem) -> list[str]:
    vuln = item.vulnerability
    location = vuln.path
    if vuln.start_line:
        location = f"{location}:{vuln.start_line}"

    lines = [f"### [{rank}] {item.tier.value} — score: {item.final_score} — `{vuln.category.value}`", ""]

    location_parts = [f"`{location}`"]
    if vuln.function:
        location_parts.append(f"in `{vuln.function}`")
    lines.append(f"**Location:** {' '.join(location_parts)}  ")

    meta_parts = [f"**Rule:** `{vuln.rule_id}`"]
    if vuln.cwe:
        meta_parts.append(f"**CWE:** {vuln.cwe}")
    lines.append("  ".join(meta_parts) + "  ")
    lines.append("")

    lines.append("**Why it's risky on this target:**  ")
    lines.append(item.explanation)
    lines.append("")

    lines.append("**Remediation:**  ")
    lines.append(item.remediation)
    lines.append("")

    fired_lines = _fired_rules_lines(item)
    if fired_lines:
        lines += fired_lines
        lines.append("")

    lines += ["---", ""]
    return lines


def _footer_section() -> list[str]:
    return [
        f"> Full structured details (scores, rule traces, provenance): [{_JSON_REPORT_FILENAME}]({_JSON_REPORT_FILENAME})",
        "",
    ]


def build_markdown_report(report: RiskReport, top_k: int = 10) -> str:
    sections: list[str] = []
    sections += _header_section(report)
    sections += _constraints_section(report)
    sections += _distribution_section(report)

    top_items = report.items[:top_k]
    if top_items:
        heading_suffix = f" (top {len(top_items)} of {report.summary.total_findings})" if report.summary.total_findings > top_k else ""
        sections += [f"## Findings{heading_suffix}", ""]
        for rank, item in enumerate(top_items, start=1):
            sections += _finding_section(rank, item)

    sections += _footer_section()
    return "\n".join(sections)


def write_markdown_report(report: RiskReport, out_dir: Path, top_k: int = 10) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / _REPORT_FILENAME
    report_path.write_text(build_markdown_report(report, top_k=top_k), encoding="utf-8")
    return report_path
