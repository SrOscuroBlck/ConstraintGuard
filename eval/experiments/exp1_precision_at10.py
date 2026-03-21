"""Experiment 1: Prioritization Accuracy (Precision@10 Comparison).

Compares Precision@10 across three configurations:
  - Baseline: category-only scoring (null HardwareSpec)
  - Deterministic: constraint-aware expert system
  - Full System: deterministic + LLM confidence re-ranking

Also computes demotion rate and expert agreement.
Requires SARIF files AND ground truth labels for meaningful results.
If ground truth is missing, precision metrics are reported as N/A.

Run independently:
    python -m eval.experiments.exp1_precision_at10
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, load_scored_items, load_ground_truth
from eval.harness.metrics import precision_at_k, demotion_rate, expert_agreement, vuln_key
from eval.harness.full_system import get_full_system_ranking
from eval.visualization.plots import plot_precision_at10
from eval.visualization.tables import table_precision_accuracy

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

K = 10


def run(projects: list[str] | None = None) -> dict[str, dict[str, float]]:
    """Run Experiment 1 and return precision metrics per project."""
    projects = projects or PROJECTS
    print("=== Experiment 1: Prioritization Accuracy (Precision@10) ===\n")

    all_results: dict[str, dict[str, float]] = {}
    rows_for_csv = []

    for project in projects:
        try:
            baseline, deterministic, spec = load_scored_items(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        gt = load_ground_truth(project)
        full_system = get_full_system_ranking(deterministic)

        has_gt = bool(gt)
        if not has_gt:
            print(f"  [{project}] WARNING: No ground truth labels found. Precision metrics will be 0.")

        b_p10 = precision_at_k(baseline, gt, K)
        d_p10 = precision_at_k(deterministic, gt, K)
        fs_p10 = precision_at_k(full_system, gt, K)
        demote = demotion_rate(baseline, deterministic)
        agree = expert_agreement(deterministic, gt) if has_gt else 0.0

        result = {
            "baseline_p10": b_p10,
            "deterministic_p10": d_p10,
            "full_system_p10": fs_p10,
            "demotion_rate": demote,
            "expert_agreement": agree,
        }
        all_results[project] = result

        print(f"  [{project}]")
        print(f"    Baseline P@10:      {b_p10*100:.1f}%")
        print(f"    Deterministic P@10: {d_p10*100:.1f}%")
        print(f"    Full System P@10:   {fs_p10*100:.1f}%")
        print(f"    Demotion Rate:      {demote*100:.1f}%")
        print(f"    Expert Agreement:   {agree*100:.1f}%")
        print()

        # Per-finding detail for CSV
        all_keys = {vuln_key(i) for i in baseline + deterministic + full_system}
        b_map = {vuln_key(i): i for i in baseline}
        d_map = {vuln_key(i): i for i in deterministic}
        fs_map = {vuln_key(i): i for i in full_system}
        b_rank = {vuln_key(i): rank for rank, i in enumerate(baseline, 1)}
        d_rank = {vuln_key(i): rank for rank, i in enumerate(deterministic, 1)}
        fs_rank = {vuln_key(i): rank for rank, i in enumerate(full_system, 1)}

        for key in all_keys:
            rows_for_csv.append({
                "project": project,
                "vuln_key": key,
                "is_critical": gt.get(key, "unknown"),
                "baseline_rank": b_rank.get(key, ""),
                "deterministic_rank": d_rank.get(key, ""),
                "full_system_rank": fs_rank.get(key, ""),
                "baseline_score": b_map[key].base_score if key in b_map else "",
                "deterministic_score": d_map[key].final_score if key in d_map else "",
                "deterministic_tier": d_map[key].tier.value if key in d_map else "",
            })

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp1_precision.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "project", "vuln_key", "is_critical",
            "baseline_rank", "deterministic_rank", "full_system_rank",
            "baseline_score", "deterministic_score", "deterministic_tier",
        ])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"  CSV saved: {csv_path}")

    # Save summary JSON
    summary_path = OUTPUTS_RAW / "exp1_summary.json"
    summary_path.write_text(json.dumps(all_results, indent=2))

    if all_results:
        pdf_path = plot_precision_at10(all_results)
        tex_path = table_precision_accuracy(all_results)
        print(f"  Figure saved: {pdf_path}")
        print(f"  Table saved: {tex_path}")

    return all_results


if __name__ == "__main__":
    result = run()
    print("\nExp 1 complete.")
    if result:
        avgs = {}
        for metric in ["baseline_p10", "deterministic_p10", "full_system_p10", "demotion_rate", "expert_agreement"]:
            vals = [v[metric] for v in result.values()]
            avgs[metric] = sum(vals) / len(vals)
        print(f"\nAverages across {len(result)} projects:")
        print(f"  Baseline P@10:      {avgs['baseline_p10']*100:.1f}%")
        print(f"  Deterministic P@10: {avgs['deterministic_p10']*100:.1f}%")
        print(f"  Full System P@10:   {avgs['full_system_p10']*100:.1f}%")
        print(f"  Demotion Rate:      {avgs['demotion_rate']*100:.1f}%")
        print(f"  Expert Agreement:   {avgs['expert_agreement']*100:.1f}%")
