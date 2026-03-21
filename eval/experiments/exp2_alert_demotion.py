"""Experiment 2: Alert Demotion Rate (Noise Reduction).

Measures what fraction of baseline top-10 findings fall below HIGH tier
after constraint-aware scoring. No ground truth required.

Run independently:
    python -m eval.experiments.exp2_alert_demotion
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, load_scored_items
from eval.harness.metrics import demotion_rate, vuln_key
from eval.visualization.plots import plot_demotion_rate

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)


def run(projects: list[str] | None = None) -> dict[str, float]:
    """Run Experiment 2 and return demotion rates per project."""
    projects = projects or PROJECTS
    print("=== Experiment 2: Alert Demotion Rate ===\n")

    results: dict[str, float] = {}
    rows_for_csv = []

    for project in projects:
        try:
            baseline, deterministic, spec = load_scored_items(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        rate = demotion_rate(baseline, deterministic)
        results[project] = rate

        # Detail: which baseline top-10 findings were demoted?
        from constraintguard.models.enums import SeverityTier
        top10_keys = {vuln_key(i): i for i in baseline[:10]}
        det_map = {vuln_key(i): i for i in deterministic}

        demoted_count = 0
        for key, b_item in top10_keys.items():
            d_item = det_map.get(key)
            d_tier = d_item.tier if d_item else SeverityTier.HIGH
            demoted = d_tier in (SeverityTier.MEDIUM, SeverityTier.LOW)
            if demoted:
                demoted_count += 1
            rows_for_csv.append({
                "project": project,
                "vuln_key": key,
                "baseline_score": b_item.base_score,
                "deterministic_score": d_item.final_score if d_item else "N/A",
                "deterministic_tier": d_tier.value if d_tier else "N/A",
                "demoted": demoted,
            })

        print(f"  [{project}] Demotion rate: {rate*100:.1f}%  ({demoted_count}/10 baseline top-10 demoted)")
        print(f"    Constraint profile: RAM={spec.ram_size_bytes}B, stack={spec.stack_size_bytes}B, ISR={spec.max_interrupt_latency_us}µs, safety={spec.safety_level}")

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp2_demotion_rate.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "vuln_key", "baseline_score", "deterministic_score", "deterministic_tier", "demoted"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    # Summary CSV
    summary_path = OUTPUTS_RAW / "exp2_demotion_summary.csv"
    with open(summary_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "demotion_rate_pct"])
        writer.writeheader()
        for project, rate in results.items():
            writer.writerow({"project": project, "demotion_rate_pct": f"{rate*100:.2f}"})

    if results:
        pdf_path = plot_demotion_rate(results)
        print(f"  Figure saved: {pdf_path}")
    else:
        print("  No projects with SARIF data — skipping figure.")

    return results


if __name__ == "__main__":
    result = run()
    print(f"\nExp 2 complete. Demotion rates: {result}")
