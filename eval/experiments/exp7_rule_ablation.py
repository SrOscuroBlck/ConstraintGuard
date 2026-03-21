"""Experiment 7: Rule Family Contribution (Ablation Study).

For each rule family, re-scores vulnerabilities with that family excluded,
then measures the mean absolute score delta. Normalized to percentages.

No ground truth required.

Run independently:
    python -m eval.experiments.exp7_rule_ablation
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.ablation import RULE_FAMILIES, compute_all_family_contributions
from eval.harness.loader import PROJECTS, load_scored_items, load_vulnerabilities, load_spec
from eval.visualization.plots import plot_rule_ablation

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)


def run(projects: list[str] | None = None) -> dict[str, dict[str, float]]:
    """Run Experiment 7 and return contribution % per project × family."""
    projects = projects or PROJECTS
    print("=== Experiment 7: Rule Family Ablation Study ===\n")

    all_results: dict[str, dict[str, float]] = {}
    rows_for_csv = []

    for project in projects:
        try:
            baseline, deterministic, spec = load_scored_items(project)
            vulns = load_vulnerabilities(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        print(f"  [{project}] Computing family contributions ({len(vulns)} vulnerabilities)...")
        contributions = compute_all_family_contributions(vulns, deterministic, spec)
        all_results[project] = contributions

        for family, pct in contributions.items():
            print(f"    {family}: {pct:.1f}%")
            rows_for_csv.append({
                "project": project,
                "family": family,
                "contribution_pct": f"{pct:.2f}",
            })

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp7_rule_ablation.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "family", "contribution_pct"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    if all_results:
        pdf_path = plot_rule_ablation(all_results)
        print(f"  Figure saved: {pdf_path}")
    else:
        print("  No projects with SARIF data — skipping figure.")

    return all_results


if __name__ == "__main__":
    result = run()
    print(f"\nExp 7 complete.")
    for project, contributions in result.items():
        dominant = max(contributions, key=contributions.get)
        print(f"  {project}: dominant family = {dominant} ({contributions[dominant]:.1f}%)")
