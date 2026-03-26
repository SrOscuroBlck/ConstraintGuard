import os
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
    mode: str = "expert",
    llm_model: str | None = None,
    llm_provider: str | None = None,
    llm_total_cost: float | None = None,
    llm_total_tokens: int | None = None,
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
            mode=mode,
            llm_model=llm_model,
            llm_provider=llm_provider,
            llm_total_cost=llm_total_cost,
            llm_total_tokens=llm_total_tokens,
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


def _run_enrichment(
    items: list[RiskItem],
    spec: HardwareSpec,
    source_path: str | None,
    llm_topk: int,
    llm_changed_files: bool,
    llm_discover: bool = False,
) -> tuple[list[RiskItem], str | None, str | None, float | None, int | None]:
    from constraintguard.enrichment.policy import (
        SelectionMode,
        SelectionPolicy,
        estimate_llm_cost,
        get_changed_files_from_git,
        select_for_enrichment,
    )
    from constraintguard.llm.models import LLMConfig, LLMProvider

    provider_str = os.environ.get("CONSTRAINTGUARD_LLM_PROVIDER")
    model_str = os.environ.get("CONSTRAINTGUARD_LLM_MODEL")
    api_key = os.environ.get("CONSTRAINTGUARD_LLM_API_KEY")

    if not provider_str or not model_str or not api_key:
        print("Warning: LLM environment variables not set. Falling back to expert-only mode.")
        return items, None, None, None, None

    max_retries = int(os.environ.get("CONSTRAINTGUARD_LLM_MAX_RETRIES", "1"))
    reasoning_effort = os.environ.get("CONSTRAINTGUARD_LLM_EFFORT", "low")

    try:
        config = LLMConfig(
            provider=LLMProvider(provider_str),
            model=model_str,
            api_key=api_key,
            max_retries=max_retries,
            reasoning_effort=reasoning_effort,
        )
    except (ValueError, KeyError) as exc:
        print(f"Warning: Invalid LLM configuration: {exc}. Falling back to expert-only mode.")
        return items, None, None, None, None

    from constraintguard.llm.client import create_llm_client
    from constraintguard.llm.cost import CostTracker

    client = create_llm_client(config)

    if llm_changed_files and source_path:
        changed = get_changed_files_from_git(Path(source_path))
        policy = SelectionPolicy(
            mode=SelectionMode.CHANGED_FILES,
            top_k=llm_topk,
            changed_files=changed,
        )
    else:
        policy = SelectionPolicy(mode=SelectionMode.TOPK, top_k=llm_topk)

    selection_result = select_for_enrichment(items, policy)
    print(selection_result.reason)

    if not selection_result.selected_items:
        return items, config.model, config.provider.value, None, None

    cost_estimate = estimate_llm_cost(len(selection_result.selected_items))
    print(cost_estimate)

    from constraintguard.evidence.extractor import extract_evidence_batch

    source_dir = Path(source_path) if source_path else Path(".")
    vulns = [item.vulnerability for item in selection_result.selected_items]
    evidence_bundles = extract_evidence_batch(vulns, source_dir, spec)

    from constraintguard.enrichment.analyzer import discover_file_vulnerabilities, enrich_items

    tracker = CostTracker()
    enrich_items(selection_result.selected_items, evidence_bundles, spec, client, tracker)

    if llm_discover and source_path:
        print("Running file-level vulnerability discovery...")
        new_findings = discover_file_vulnerabilities(
            seed_items=selection_result.selected_items,
            all_items=items,
            spec=spec,
            client=client,
            tracker=tracker,
            source_root=source_dir,
        )
        if new_findings:
            print(f"  LLM discovered {len(new_findings)} new candidate(s).")
            items = items + new_findings

    summary = tracker.summarize()
    llm_total_cost = float(summary.total_cost)
    llm_total_tokens = summary.total_input_tokens + summary.total_output_tokens

    return items, config.model, config.provider.value, llm_total_cost, llm_total_tokens


def run_score_pipeline(
    sarif_paths: list[Path],
    config_path: Path | None,
    linker_script_path: Path | None,
    out_dir: Path,
    top_k: int = 10,
    command: str | None = None,
    source_path: str | None = None,
    mode: str = "expert",
    llm_topk: int = 10,
    llm_changed_files: bool = False,
    llm_discover: bool = False,
) -> RiskReport:
    spec, provenance = load_constraints(config_path, linker_script_path)

    vulnerabilities: list[Vulnerability] = []
    for sarif_path in sarif_paths:
        vulnerabilities.extend(parse_sarif(sarif_path))

    if not vulnerabilities:
        print("No findings parsed from SARIF input.")

    items = score_all(vulnerabilities, spec)

    llm_model = None
    llm_provider = None
    llm_total_cost = None
    llm_total_tokens = None

    if mode in ("hybrid", "llm"):
        items, llm_model, llm_provider, llm_total_cost, llm_total_tokens = _run_enrichment(
            items=items,
            spec=spec,
            source_path=source_path,
            llm_topk=llm_topk,
            llm_changed_files=llm_changed_files,
            llm_discover=llm_discover,
        )

    config_label = str(config_path) if config_path else None

    report = build_risk_report(
        items=items,
        spec=spec,
        provenance=provenance,
        command=command,
        source_path=source_path,
        config_path=config_label,
        top_k=top_k,
        mode=mode,
        llm_model=llm_model,
        llm_provider=llm_provider,
        llm_total_cost=llm_total_cost,
        llm_total_tokens=llm_total_tokens,
    )

    json_path = write_json_report(report, out_dir)
    md_path = write_markdown_report(report, out_dir, top_k=top_k)
    print_report_to_console(report, top_k=top_k)

    print(f"\nReports written to:")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {md_path}")

    return report
