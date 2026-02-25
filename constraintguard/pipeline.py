from datetime import datetime, timezone
from pathlib import Path

from constraintguard import __version__
from constraintguard.models.enums import SeverityTier
from constraintguard.models.hardware_spec import ConstraintProvenance, HardwareSpec
from constraintguard.models.risk_report import (
    ReportSummary,
    RiskItem,
    RiskReport,
    RunMetadata,
    TierCounts,
)
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.parsers.constraint_loader import load_constraints
from constraintguard.parsers.sarif_parser import parse_sarif
from constraintguard.reporting.console import print_report_to_console
from constraintguard.reporting.json_writer import write_json_report
from constraintguard.reporting.markdown_writer import write_markdown_report
from constraintguard.scoring.engine import score_all


def _build_tier_counts(items: list[RiskItem]) -> TierCounts:
    counts = {tier: 0 for tier in SeverityTier}
    for item in items:
        counts[item.tier] += 1
    return TierCounts(
        critical=counts[SeverityTier.CRITICAL],
        high=counts[SeverityTier.HIGH],
        medium=counts[SeverityTier.MEDIUM],
        low=counts[SeverityTier.LOW],
    )


def _build_top_finding_labels(items: list[RiskItem], top_k: int) -> list[str]:
    labels: list[str] = []
    for item in items[:top_k]:
        vuln = item.vulnerability
        location = vuln.path
        if vuln.start_line:
            location = f"{location}:{vuln.start_line}"
        labels.append(f"{vuln.category.value} at {location} (score={item.final_score})")
    return labels


def build_risk_report(
    items: list[RiskItem],
    spec: HardwareSpec,
    provenance: ConstraintProvenance,
    command: str | None = None,
    source_path: str | None = None,
    config_path: str | None = None,
    top_k: int = 10,
) -> RiskReport:
    tier_counts = _build_tier_counts(items)
    top_labels = _build_top_finding_labels(items, top_k)

    return RiskReport(
        run_metadata=RunMetadata(
            tool_version=__version__,
            timestamp=datetime.now(timezone.utc),
            command=command,
            source_path=source_path,
            config_path=config_path,
        ),
        hardware_spec=spec,
        provenance=provenance,
        summary=ReportSummary(
            total_findings=len(items),
            tier_counts=tier_counts,
            top_findings=top_labels,
        ),
        items=items,
    )


def run_score_pipeline(
    sarif_paths: list[Path],
    config_path: Path | None,
    linker_script_path: Path | None,
    out_dir: Path,
    top_k: int = 10,
    command: str | None = None,
    source_path: str | None = None,
) -> RiskReport:
    spec, provenance = load_constraints(config_path, linker_script_path)

    vulnerabilities: list[Vulnerability] = []
    for sarif_path in sarif_paths:
        vulnerabilities.extend(parse_sarif(sarif_path))

    if not vulnerabilities:
        print("No findings parsed from SARIF input.")

    items = score_all(vulnerabilities, spec)

    config_label = str(config_path) if config_path else None

    report = build_risk_report(
        items=items,
        spec=spec,
        provenance=provenance,
        command=command,
        source_path=source_path,
        config_path=config_label,
        top_k=top_k,
    )

    json_path = write_json_report(report, out_dir)
    md_path = write_markdown_report(report, out_dir, top_k=top_k)
    print_report_to_console(report, top_k=top_k)

    print(f"\nReports written to:")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {md_path}")

    return report
