"""Exp 8: Empirical Constraint Sensitivity.

Addresses supervisor feedback: demonstrates that category-specific scoring rules
produce meaningfully different scores when given proper clang-analyzer findings
(vs. clang-tidy UNKNOWN findings used in the real-project evaluation).

Same 8 benchmark findings scored under 4 hardware profiles:
  - baseline:          null spec, no rules fire
  - benchmark_relaxed: 512KB RAM, 500µs ISR, no safety
  - benchmark_safety:  64KB RAM, 100µs ISR, IEC61508-SIL2
  - benchmark_tight:   20KB RAM, 2KB stack, 50µs ISR, ISO26262-ASIL-B

Key result: same vulnerability (e.g. strcpy/copy_input) scores 60 (MEDIUM) under
relaxed and 100 (CRITICAL) under tight — proving that constraint-aware scoring
differentiates where the baseline cannot.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Allow running as a script from repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import load_benchmark_items
from eval.harness.metrics import vuln_key
from eval.visualization.plots import plot_constraint_sensitivity
from eval.visualization.tables import table_constraint_sensitivity

RAW_DIR = Path(__file__).parent.parent / "outputs" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

CONFIGS = ["baseline", "benchmark_relaxed", "benchmark_safety", "benchmark_tight"]
CONFIG_SHORT = {
    "baseline": "baseline",
    "benchmark_relaxed": "relaxed",
    "benchmark_safety": "safety",
    "benchmark_tight": "tight",
}


def _short_label(item) -> str:
    """Compact label: function:category."""
    v = item.vulnerability
    func = v.function or Path(v.path or "").name.replace(".c", "")
    cat = v.category.value.replace("_", "-").lower()
    return f"{func}:{cat}"


def run_exp8() -> list[dict]:
    print("[exp8] Loading benchmark SARIF under 4 hardware profiles...")
    scored = load_benchmark_items(CONFIGS)

    # Build a stable ordering using tight profile (highest scores first)
    tight_items = scored["benchmark_tight"]
    key_order = [vuln_key(item) for item in sorted(tight_items, key=lambda i: -i.final_score)]

    # Map vuln_key → RiskItem per config
    item_maps: dict[str, dict[str, object]] = {}
    for config in CONFIGS:
        item_maps[config] = {vuln_key(i): i for i in scored[config]}

    rows = []
    for vk in key_order:
        tight_item = item_maps["benchmark_tight"].get(vk)
        if tight_item is None:
            continue
        v = tight_item.vulnerability
        row = {
            "finding_id": vk,
            "label": _short_label(tight_item),
            "function": v.function or "",
            "category": v.category.value,
            "rule_id": v.rule_id or "",
        }
        rules_fired = []
        for config in CONFIGS:
            item = item_maps[config].get(vk)
            score = item.final_score if item else 0
            short = CONFIG_SHORT[config]
            row[short] = score
            if config == "benchmark_tight" and item and item.rule_firings:
                rules_fired = [f.rule_id for f in item.rule_firings]
        row["rules_fired_tight"] = ", ".join(rules_fired)
        rows.append(row)

    # Write CSV
    csv_path = RAW_DIR / "exp8_constraint_sensitivity.csv"
    fieldnames = ["finding_id", "label", "function", "category", "rule_id",
                  "baseline", "relaxed", "safety", "tight", "rules_fired_tight"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[exp8] CSV written: {csv_path}")

    # Print summary table
    print(f"\n{'Finding':<35} {'Cat':<18} {'Base':>5} {'Relax':>6} {'Safety':>7} {'Tight':>6}  Rules fired (tight)")
    print("-" * 100)
    for row in rows:
        delta = row["tight"] - row["relaxed"]
        delta_str = f"Δ+{delta}" if delta > 0 else f"Δ{delta}"
        print(
            f"{row['label']:<35} {row['category']:<18} "
            f"{row['baseline']:>5} {row['relaxed']:>6} {row['safety']:>7} {row['tight']:>6}  "
            f"({delta_str})  {row['rules_fired_tight']}"
        )

    print(f"\n[exp8] Score differentiation (tight − relaxed):")
    max_delta = max(row["tight"] - row["relaxed"] for row in rows)
    min_delta = min(row["tight"] - row["relaxed"] for row in rows)
    print(f"  Max delta: +{max_delta} points")
    print(f"  Min delta: +{min_delta} points")
    changed = sum(1 for row in rows if row["tight"] != row["relaxed"])
    print(f"  Findings with score change: {changed}/{len(rows)}")

    return rows


def main() -> None:
    rows = run_exp8()

    print("\n[exp8] Generating figure...")
    plot_constraint_sensitivity(rows)

    print("[exp8] Generating LaTeX table...")
    table_constraint_sensitivity(rows)

    print("[exp8] Done.")


if __name__ == "__main__":
    main()
