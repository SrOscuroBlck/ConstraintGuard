"""Master orchestrator for ConstraintGuard evaluation harness.

Runs all 7 experiments in dependency order and generates all figures/tables.

Usage:
    python eval/run_all.py
    python eval/run_all.py --skip-llm              # skip LLM-dependent experiments
    python eval/run_all.py --skip-gt               # skip ground-truth-dependent experiments
    python eval/run_all.py --projects freertos     # single project
    python eval/run_all.py --projects freertos,zephyr,espfc
    python eval/run_all.py --exp 4,5,7             # run specific experiments only
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from eval.harness.loader import PROJECTS, SARIF_PATH


def _check_sarif(projects: list[str]) -> list[str]:
    """Return which projects have SARIF files available."""
    available = []
    missing = []
    for p in projects:
        sarif = SARIF_PATH / p / "findings.sarif"
        if sarif.exists():
            available.append(p)
        else:
            missing.append(p)
    if missing:
        print(f"  WARNING: SARIF missing for: {', '.join(missing)}")
        print(f"  Run sarif_acquisition/<project>/run_scan.sh to generate them.")
        print(f"  Continuing with available projects: {available or 'none'}\n")
    return available


def _run_exp(name: str, fn, *args, **kwargs):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    t0 = time.perf_counter()
    try:
        result = fn(*args, **kwargs)
        elapsed = time.perf_counter() - t0
        print(f"\n  [{name}] DONE in {elapsed:.1f}s")
        return result
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"\n  [{name}] FAILED in {elapsed:.1f}s: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(description="ConstraintGuard Evaluation Harness")
    parser.add_argument("--projects", default=",".join(PROJECTS),
                        help="Comma-separated list of projects (default: all)")
    parser.add_argument("--skip-llm", action="store_true",
                        help="Skip experiments requiring LLM API (Exp 1 full-system, Exp 3, Exp 5 LLM timing)")
    parser.add_argument("--skip-gt", action="store_true",
                        help="Skip experiments requiring ground truth labels (Exp 1, Exp 6)")
    parser.add_argument("--exp", default="",
                        help="Comma-separated experiment numbers to run (e.g. '4,5,7'). Default: all.")
    parser.add_argument("--llm-phase", choices=["generate", "compute"], default="generate",
                        help="Phase for Exp 3 (generate: produce rating sheet; compute: process completed ratings)")
    args = parser.parse_args()

    projects = [p.strip() for p in args.projects.split(",") if p.strip()]
    exp_filter = set(int(e) for e in args.exp.split(",") if e.strip()) if args.exp else None

    def should_run(n: int) -> bool:
        return exp_filter is None or n in exp_filter

    print("\n" + "="*60)
    print("  ConstraintGuard Evaluation Harness — EMSOFT 2026")
    print("="*60)
    print(f"\n  Projects:  {projects}")
    print(f"  Skip LLM:  {args.skip_llm}")
    print(f"  Skip GT:   {args.skip_gt}")
    if exp_filter:
        print(f"  Experiments: {sorted(exp_filter)}")
    print()

    total_t0 = time.perf_counter()

    # ─── Exp 8: Empirical Constraint Sensitivity (no deps — benchmark SARIF) ─
    if should_run(8):
        from eval.experiments.exp8_constraint_sensitivity import run_exp8, main as exp8_main
        _run_exp("Exp 8: Empirical Constraint Sensitivity (Benchmark)", exp8_main)

    # ─── Exp 4: CWE Heatmap (no deps — run first as smoke test) ────────────
    if should_run(4):
        from eval.experiments.exp4_cwe_heatmap import run as run_exp4
        _run_exp("Exp 4: CWE-Constraint Heatmap", run_exp4)

    # ─── Check SARIF availability ────────────────────────────────────────────
    available_projects = _check_sarif(projects)

    # ─── Exp 2: Alert Demotion Rate ─────────────────────────────────────────
    if should_run(2) and available_projects:
        from eval.experiments.exp2_alert_demotion import run as run_exp2
        _run_exp("Exp 2: Alert Demotion Rate", run_exp2, projects=available_projects)

    # ─── Exp 7: Rule Family Ablation ─────────────────────────────────────────
    if should_run(7) and available_projects:
        from eval.experiments.exp7_rule_ablation import run as run_exp7
        _run_exp("Exp 7: Rule Family Ablation", run_exp7, projects=available_projects)

    # ─── Exp 5: CI/CD Overhead ───────────────────────────────────────────────
    if should_run(5) and available_projects:
        from eval.experiments.exp5_cicd_overhead import run as run_exp5
        _run_exp("Exp 5: CI/CD Pipeline Overhead", run_exp5, projects=available_projects)

    # ─── Exp 1: Precision@10 (needs GT + optional LLM) ──────────────────────
    if should_run(1) and available_projects and not args.skip_gt:
        from eval.experiments.exp1_precision_at10 import run as run_exp1
        _run_exp("Exp 1: Precision@10 Comparison", run_exp1, projects=available_projects)
    elif should_run(1) and args.skip_gt:
        print("\n  [Exp 1] SKIPPED — requires ground truth (--skip-gt set)")

    # ─── Exp 6: Precision@K Curve (needs GT) ─────────────────────────────────
    if should_run(6) and available_projects and not args.skip_gt:
        from eval.experiments.exp6_precision_at_k_curve import run as run_exp6
        _run_exp("Exp 6: Precision@K Ranking Curve", run_exp6, projects=available_projects)
    elif should_run(6) and args.skip_gt:
        print("\n  [Exp 6] SKIPPED — requires ground truth (--skip-gt set)")

    # ─── Exp 3: LLM Quality (needs LLM, then human annotation) ──────────────
    if should_run(3) and available_projects and not args.skip_llm:
        from eval.experiments.exp3_llm_quality import run as run_exp3
        _run_exp(
            f"Exp 3: LLM Enrichment Quality (phase={args.llm_phase})",
            run_exp3,
            projects=available_projects,
            phase=args.llm_phase,
        )
    elif should_run(3) and args.skip_llm:
        print("\n  [Exp 3] SKIPPED — requires LLM API (--skip-llm set)")

    total_elapsed = time.perf_counter() - total_t0
    print(f"\n{'='*60}")
    print(f"  All experiments complete in {total_elapsed:.1f}s")
    print(f"  Outputs in: eval/outputs/")
    print(f"    Figures:  eval/outputs/figures/")
    print(f"    Tables:   eval/outputs/tables/")
    print(f"    Raw data: eval/outputs/raw/")
    print("="*60)


if __name__ == "__main__":
    main()
