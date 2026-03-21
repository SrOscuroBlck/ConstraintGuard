"""Interactive CLI ground truth labeler for ConstraintGuard evaluation.

Labels the top-30 findings per project as "truly critical" given the
hardware constraint context. Labels are saved as stable JSON keyed by
vuln_key = "{path}:{start_line}:{rule_id}".

Usage:
    python -m eval.ground_truth.labeler --project freertos
    python -m eval.ground_truth.labeler --project freertos --dry-run   # show top-5, no save
    python -m eval.ground_truth.labeler --project freertos --resume    # continue from saved labels
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import load_scored_items, load_ground_truth, GT_PATH, PROJECTS
from eval.harness.metrics import vuln_key

TOP_N = 30
DRY_RUN_N = 5


def _display_finding(rank: int, item, total: int) -> None:
    """Print a formatted finding for expert review."""
    v = item.vulnerability
    print(f"\n{'='*70}")
    print(f"Finding {rank}/{total}  |  Score: {item.final_score} ({item.tier.value})")
    print(f"{'='*70}")
    print(f"  File:     {v.path}")
    print(f"  Line:     {v.start_line}")
    print(f"  Function: {v.function or 'N/A'}")
    print(f"  Category: {v.category.value}")
    print(f"  CWE:      {v.cwe or 'N/A'}")
    print(f"  Rule ID:  {v.rule_id}")
    print()
    if item.rule_firings:
        print("  Constraint rules fired:")
        for f in item.rule_firings:
            print(f"    [{f.rule_id} +{f.delta}] {f.rationale[:120]}")
        print()
    print(f"  Expert assessment:")
    print(f"    {item.explanation[:300]}")
    print()


def _prompt_label() -> str | None:
    """Prompt for a label. Returns 'y', 'n', 'skip', or None (quit)."""
    while True:
        try:
            answer = input("  Critical given constraints? [y=yes / n=no / s=skip / q=quit]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Interrupted.")
            return None
        if answer in ("y", "yes"):
            return "y"
        if answer in ("n", "no"):
            return "n"
        if answer in ("s", "skip"):
            return "s"
        if answer in ("q", "quit"):
            return None
        print("  Please enter y, n, s, or q.")


def _prompt_confidence() -> str:
    """Prompt for confidence level."""
    while True:
        try:
            answer = input("  Confidence? [h=high / m=medium / l=low]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "medium"
        if answer in ("h", "high"):
            return "high"
        if answer in ("m", "medium", ""):
            return "medium"
        if answer in ("l", "low"):
            return "low"


def _prompt_notes() -> str:
    """Optional notes."""
    try:
        notes = input("  Notes (optional, press Enter to skip): ").strip()
        return notes
    except (EOFError, KeyboardInterrupt):
        return ""


def run_labeling(
    project: str,
    dry_run: bool = False,
    resume: bool = False,
    annotator: str = "",
) -> None:
    """Run interactive labeling session for a project."""
    print(f"\n{'#'*70}")
    print(f"  ConstraintGuard Ground Truth Labeler — {project.upper()}")
    print(f"  Top-{TOP_N} findings by deterministic score")
    if dry_run:
        print(f"  DRY RUN mode — showing top-{DRY_RUN_N}, nothing will be saved")
    print(f"{'#'*70}\n")

    # Load scored items
    try:
        baseline, deterministic, spec = load_scored_items(project)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # Load existing labels if resuming
    existing_labels: dict = {}
    if resume:
        existing_labels = {}
        gt_file = GT_PATH / f"{project}_labels.json"
        if gt_file.exists():
            data = json.loads(gt_file.read_text())
            existing_labels = data.get("labels", {})
            print(f"  Resuming: {len(existing_labels)} labels already saved.\n")

    # Print constraint context
    print(f"  Hardware constraint profile:")
    print(f"    Platform:  {spec.platform or 'N/A'}")
    print(f"    RAM:       {spec.ram_size_bytes}B" if spec.ram_size_bytes else "    RAM:       N/A")
    print(f"    Stack:     {spec.stack_size_bytes}B" if spec.stack_size_bytes else "    Stack:     N/A")
    print(f"    Heap:      {spec.heap_size_bytes}B" if spec.heap_size_bytes else "    Heap:      N/A")
    print(f"    ISR latency: {spec.max_interrupt_latency_us}µs" if spec.max_interrupt_latency_us else "    ISR latency: N/A")
    print(f"    Safety:    {spec.safety_level or 'None'}")
    print()
    print("  A finding is CRITICAL if BOTH:")
    print("  1. It is genuinely exploitable in this hardware constraint context.")
    print("  2. Exploitation would have high impact on system safety/reliability.\n")

    n = DRY_RUN_N if dry_run else TOP_N
    candidates = [i for i in deterministic[:n] if vuln_key(i) not in existing_labels]
    total = len(candidates)

    if total == 0:
        print("  All findings already labeled. Nothing to do.")
        return

    new_labels: dict[str, dict] = {}
    labeled_count = 0

    for rank, item in enumerate(candidates, 1):
        key = vuln_key(item)
        _display_finding(rank, item, total)

        answer = _prompt_label()
        if answer is None:
            print("\n  Quitting labeling session.")
            break
        if answer == "s":
            print("  Skipped.")
            continue

        is_critical = answer == "y"
        confidence = _prompt_confidence()
        notes = _prompt_notes()

        new_labels[key] = {
            "is_critical": is_critical,
            "confidence": confidence,
            "notes": notes,
            "vuln_path": item.vulnerability.path,
            "vuln_line": item.vulnerability.start_line,
            "rule_id": item.vulnerability.rule_id,
            "deterministic_score": item.final_score,
            "tier": item.tier.value,
        }
        labeled_count += 1
        print(f"  Labeled: {'CRITICAL' if is_critical else 'not critical'} ({confidence} confidence)")

    if dry_run:
        print(f"\n  DRY RUN complete. {labeled_count} items reviewed (not saved).")
        return

    # Merge with existing labels and save
    merged = {**existing_labels, **new_labels}
    if not annotator:
        try:
            annotator = input("\n  Your initials/name for the record: ").strip()
        except (EOFError, KeyboardInterrupt):
            annotator = "anonymous"

    output = {
        "project": project,
        "annotator": annotator,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_labeled": len(merged),
        "labels": merged,
    }

    GT_PATH.mkdir(parents=True, exist_ok=True)
    gt_file = GT_PATH / f"{project}_labels.json"
    gt_file.write_text(json.dumps(output, indent=2))
    print(f"\n  Labels saved: {gt_file}")
    print(f"  Total labels: {len(merged)} ({labeled_count} new this session)")
    print(f"  Critical: {sum(1 for v in merged.values() if v['is_critical'])}")
    print(f"  Not critical: {sum(1 for v in merged.values() if not v['is_critical'])}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ConstraintGuard ground truth labeler")
    parser.add_argument("--project", choices=PROJECTS, required=True, help="Project to label")
    parser.add_argument("--dry-run", action="store_true", help=f"Show top-{DRY_RUN_N} findings without saving")
    parser.add_argument("--resume", action="store_true", help="Continue from saved labels")
    parser.add_argument("--annotator", default="", help="Annotator name/initials")
    args = parser.parse_args()

    run_labeling(
        project=args.project,
        dry_run=args.dry_run,
        resume=args.resume,
        annotator=args.annotator,
    )
