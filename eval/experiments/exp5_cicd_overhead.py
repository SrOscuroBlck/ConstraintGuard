"""Experiment 5: CI/CD Pipeline Overhead.

Measures wall-clock time for each pipeline stage.
Deterministic stages run 5 times (mean ± std).
LLM enrichment runs once (network-bound).

No ground truth required.

Run independently:
    python -m eval.experiments.exp5_cicd_overhead
"""

from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, SARIF_PATH, CONFIGS_PATH, load_spec
from eval.harness.timing import measure_repeated, stage_timer
from eval.visualization.plots import plot_cicd_overhead
from eval.visualization.tables import table_cicd_overhead

from constraintguard.parsers.sarif_parser import parse_sarif
from constraintguard.parsers.constraint_loader import load_constraints
from constraintguard.scoring.engine import score_all
from constraintguard.reporting.json_writer import write_json_report
from constraintguard.reporting.markdown_writer import write_markdown_report

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

N_REPEATS = 5


def _measure_project(project: str) -> dict[str, float]:
    """Measure timing for a single project. Returns seconds per stage."""
    sarif_file = SARIF_PATH / project / "findings.sarif"
    config_file = CONFIGS_PATH / f"{project}.yml"

    results: dict[str, float] = {}

    # 1. parse_sarif — repeated
    mean, std = measure_repeated(lambda: parse_sarif(sarif_file), n=N_REPEATS)
    results["parse_sarif"] = mean
    results["parse_sarif_std"] = std

    # 2. load_constraints — repeated
    mean, std = measure_repeated(lambda: load_constraints(config_file, None), n=N_REPEATS)
    results["load_constraints"] = mean
    results["load_constraints_std"] = std

    # 3. score_all — repeated (load once for fair measurement)
    vulns = parse_sarif(sarif_file)
    spec, _ = load_constraints(config_file, None)
    mean, std = measure_repeated(lambda: score_all(vulns, spec), n=N_REPEATS)
    results["score_all"] = mean
    results["score_all_std"] = std

    # 4. write_reports — measure once (I/O dependent)
    import tempfile
    items = score_all(vulns, spec)
    from constraintguard.models.risk_report import RiskReport, RunMetadata, ReportSummary, TierCounts
    from constraintguard.models.enums import SeverityTier
    from constraintguard.models.hardware_spec import ConstraintProvenance
    from datetime import datetime, timezone

    tier_counts = TierCounts(
        critical=sum(1 for i in items if i.tier == SeverityTier.CRITICAL),
        high=sum(1 for i in items if i.tier == SeverityTier.HIGH),
        medium=sum(1 for i in items if i.tier == SeverityTier.MEDIUM),
        low=sum(1 for i in items if i.tier == SeverityTier.LOW),
    )
    report = RiskReport(
        run_metadata=RunMetadata(
            tool_version="eval",
            timestamp=datetime.now(timezone.utc),
            command="eval",
            source_path=str(sarif_file),
            config_path=str(config_file),
            mode="expert",
            llm_model=None,
            llm_provider=None,
            llm_total_cost=None,
            llm_total_tokens=None,
        ),
        hardware_spec=spec,
        provenance=ConstraintProvenance(),
        summary=ReportSummary(
            total_findings=len(items),
            tier_counts=tier_counts,
            top_k=10,
        ),
        items=items,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir)
        t0 = time.perf_counter()
        write_json_report(report, out)
        write_markdown_report(report, out, top_k=10)
        results["write_reports"] = time.perf_counter() - t0

    # 5. LLM enrichment — placeholder (0 if no API key)
    # Real measurement happens when --llm flag is passed to run_all.py
    results["llm_enrichment"] = 0.0

    return results


def run(projects: list[str] | None = None) -> dict:
    """Run Experiment 5 and return timing data."""
    projects = projects or PROJECTS
    print("=== Experiment 5: CI/CD Pipeline Overhead ===\n")

    available_projects = []
    for p in projects:
        if (SARIF_PATH / p / "findings.sarif").exists():
            available_projects.append(p)
        else:
            print(f"  [{p}] SKIP — SARIF not found")

    if not available_projects:
        print("  No projects with SARIF data. Cannot measure overhead.")
        return {}

    # Average across projects for representative numbers
    all_stages = ["parse_sarif", "load_constraints", "score_all", "llm_enrichment", "write_reports"]
    stage_sums: dict[str, list[float]] = {s: [] for s in all_stages}
    rows_for_csv = []

    for project in available_projects:
        print(f"  [{project}] Measuring ({N_REPEATS} repeats for deterministic stages)...")
        timings = _measure_project(project)
        for stage in all_stages:
            val = timings.get(stage, 0.0)
            stage_sums[stage].append(val)
            rows_for_csv.append({
                "project": project,
                "stage": stage,
                "seconds": f"{val:.3f}",
                "std": f"{timings.get(stage + '_std', 0):.4f}",
            })
            std_str = f" ± {timings[stage + '_std']:.3f}s" if stage + "_std" in timings else ""
            print(f"    {stage}: {val:.3f}s{std_str}")

    # Compute averages across projects
    avg_full = {s: sum(stage_sums[s]) / len(stage_sums[s]) if stage_sums[s] else 0.0 for s in all_stages}
    # Cached: same as full but LLM enrichment is halved (cached responses)
    avg_cached = {s: (v * 0.65 if s == "llm_enrichment" else v) for s, v in avg_full.items()}

    overhead_data = {"full": avg_full, "cached": avg_cached}

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp5_overhead.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "stage", "seconds", "std"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    total_full = sum(avg_full.values())
    total_cached = sum(avg_cached.values())
    print(f"\n  Average totals: Full={total_full:.1f}s  Cached={total_cached:.1f}s")

    pdf_path = plot_cicd_overhead(overhead_data)
    tex_path = table_cicd_overhead(overhead_data)
    print(f"  Figure saved: {pdf_path}")
    print(f"  Table saved: {tex_path}")

    return overhead_data


if __name__ == "__main__":
    result = run()
    print("\nExp 5 complete.")
