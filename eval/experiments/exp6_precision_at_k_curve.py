"""Experiment 6: Precision@K Ranking Curve.

Computes Precision@K for K ∈ {1, 5, 10, 15, 20} across three configurations,
averaged across all projects.

Requires SARIF files and ground truth labels.

Run independently:
    python -m eval.experiments.exp6_precision_at_k_curve
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, load_scored_items, load_ground_truth
from eval.harness.metrics import precision_at_k
from eval.harness.full_system import get_full_system_ranking
from eval.visualization.plots import plot_precision_at_k_curve

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

K_VALUES = [1, 5, 10, 15, 20]


def run(projects: list[str] | None = None) -> dict[str, dict[int, float]]:
    """Run Experiment 6 and return averaged Precision@K per configuration."""
    projects = projects or PROJECTS
    print("=== Experiment 6: Precision@K Ranking Curve ===\n")

    # Accumulate per-project precision values
    config_k_vals: dict[str, dict[int, list[float]]] = {
        "baseline": {k: [] for k in K_VALUES},
        "deterministic": {k: [] for k in K_VALUES},
        "full_system": {k: [] for k in K_VALUES},
    }

    rows_for_csv = []
    projects_used = 0

    for project in projects:
        try:
            baseline, deterministic, spec = load_scored_items(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        gt = load_ground_truth(project)
        if not gt:
            print(f"  [{project}] WARNING: No ground truth — P@K will be 0 for all K")

        full_system = get_full_system_ranking(deterministic)
        projects_used += 1

        print(f"  [{project}]")
        for k in K_VALUES:
            b_pk = precision_at_k(baseline, gt, k)
            d_pk = precision_at_k(deterministic, gt, k)
            fs_pk = precision_at_k(full_system, gt, k)

            config_k_vals["baseline"][k].append(b_pk)
            config_k_vals["deterministic"][k].append(d_pk)
            config_k_vals["full_system"][k].append(fs_pk)

            print(f"    K={k:2d}: Baseline={b_pk*100:.0f}%  Deterministic={d_pk*100:.0f}%  Full={fs_pk*100:.0f}%")
            rows_for_csv.extend([
                {"project": project, "config": "baseline", "k": k, "precision": f"{b_pk:.4f}"},
                {"project": project, "config": "deterministic", "k": k, "precision": f"{d_pk:.4f}"},
                {"project": project, "config": "full_system", "k": k, "precision": f"{fs_pk:.4f}"},
            ])

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp6_precision_at_k.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "config", "k", "precision"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    if projects_used == 0:
        print("  No projects with SARIF — skipping figure.")
        return {}

    # Average across projects
    avg_data: dict[str, dict[int, float]] = {}
    for config in ["baseline", "deterministic", "full_system"]:
        avg_data[config] = {}
        for k in K_VALUES:
            vals = config_k_vals[config][k]
            avg_data[config][k] = sum(vals) / len(vals) if vals else 0.0

    print(f"\n  Averages across {projects_used} projects:")
    for config in ["baseline", "deterministic", "full_system"]:
        vals_str = "  ".join(f"K={k}:{avg_data[config][k]*100:.0f}%" for k in K_VALUES)
        print(f"    {config}: {vals_str}")

    pdf_path = plot_precision_at_k_curve(avg_data)
    print(f"  Figure saved: {pdf_path}")

    return avg_data


if __name__ == "__main__":
    result = run()
    print("\nExp 6 complete.")
