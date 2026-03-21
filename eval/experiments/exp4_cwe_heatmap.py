"""Experiment 4: CWE-Constraint Interaction Heatmap.

Fully synthetic — no SARIF or ground truth required.
Creates synthetic Vulnerability objects scored against 5 HardwareSpec variants,
one per constraint dimension. Normalizes final_score to [0, 1] and plots a heatmap.

Run independently:
    python -m eval.experiments.exp4_cwe_heatmap
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Ensure project root is on path when run as script
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import numpy as np

from constraintguard.models.enums import VulnerabilityCategory
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.scoring.engine import score_vulnerability

from eval.visualization.plots import plot_cwe_heatmap

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

# CWE → VulnerabilityCategory mapping for synthetic vulnerabilities
# CWE-121: Stack-based Buffer Overflow
# CWE-122: Heap-based Buffer Overflow
# CWE-416: Use After Free
# CWE-401: Memory Leak
# CWE-362: Race Condition (mapped to DEADLOCK as closest category)
# CWE-476: NULL Pointer Dereference
CWE_MAPPING: list[tuple[str, VulnerabilityCategory]] = [
    ("CWE-121", VulnerabilityCategory.BUFFER_OVERFLOW),
    ("CWE-122", VulnerabilityCategory.BUFFER_OVERFLOW),
    ("CWE-416", VulnerabilityCategory.USE_AFTER_FREE),
    ("CWE-401", VulnerabilityCategory.LEAK),
    ("CWE-362", VulnerabilityCategory.DEADLOCK),
    ("CWE-476", VulnerabilityCategory.NULL_DEREF),
]

# Constraint dimensions: each HardwareSpec activates exactly one constraint
CONSTRAINT_SPECS: list[tuple[str, HardwareSpec]] = [
    ("Low Stack", HardwareSpec(stack_size_bytes=2048)),            # 2KB stack
    ("Low RAM", HardwareSpec(ram_size_bytes=32768)),               # 32KB RAM
    ("Tight ISR", HardwareSpec(max_interrupt_latency_us=50)),      # 50µs ISR
    ("Safety-Crit", HardwareSpec(safety_level="IEC61508-SIL2")),   # SIL2 safety
    ("Long Uptime", HardwareSpec(                                   # SIL2 proxy for lifetime
        safety_level="IEC61508-SIL2",
        heap_size_bytes=65536,
    )),
]


def _make_vuln(cwe: str, category: VulnerabilityCategory, suffix: str = "") -> Vulnerability:
    """Create a synthetic Vulnerability for scoring."""
    return Vulnerability(
        tool="synthetic",
        rule_id=f"synthetic.{cwe.lower().replace('-', '_')}",
        message=f"Synthetic {cwe} finding",
        path=f"src/synthetic_{cwe.lower()}{suffix}.c",
        start_line=10,
        start_col=1,
        function=None,
        cwe=cwe,
        category=category,
    )


def run() -> dict:
    """Run Experiment 4 and return the results dict."""
    print("=== Experiment 4: CWE-Constraint Interaction Heatmap ===")
    print("  (Fully synthetic — no SARIF needed)\n")

    cwe_labels = [cwe for cwe, _ in CWE_MAPPING]
    constraint_labels = [name for name, _ in CONSTRAINT_SPECS]

    matrix: list[list[float]] = []
    rows_for_csv = []

    for cwe, category in CWE_MAPPING:
        row_scores = []
        vuln = _make_vuln(cwe, category)
        for constraint_name, spec in CONSTRAINT_SPECS:
            item = score_vulnerability(vuln, spec)
            normalized = item.final_score / 100.0
            row_scores.append(normalized)
            fired = [f.rule_id for f in item.rule_firings]
            print(f"  {cwe} × {constraint_name}: score={item.final_score} ({normalized:.2f})  rules={fired}")
            rows_for_csv.append({
                "cwe": cwe,
                "category": category.value,
                "constraint": constraint_name,
                "raw_score": item.final_score,
                "normalized": normalized,
                "rules_fired": ";".join(fired),
            })
        matrix.append(row_scores)

    # Save CSV
    csv_path = OUTPUTS_RAW / "exp4_cwe_heatmap.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cwe", "category", "constraint", "raw_score", "normalized", "rules_fired"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    # Generate heatmap
    pdf_path = plot_cwe_heatmap(matrix, cwe_labels, constraint_labels)

    return {
        "matrix": matrix,
        "cwe_labels": cwe_labels,
        "constraint_labels": constraint_labels,
        "csv_path": str(csv_path),
        "pdf_path": str(pdf_path),
    }


if __name__ == "__main__":
    result = run()
    print(f"\nExp 4 complete. Figure: {result['pdf_path']}")
