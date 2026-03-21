# ConstraintGuard Evaluation Harness

Reproducible evaluation for the EMSOFT 2026 paper:
**"ConstraintGuard: Constraint-Aware Security Prioritization for Embedded Systems"**

## Quick Start

```bash
# 1. Install evaluation dependencies
pip install -r eval/requirements-eval.txt

# 2. Generate SARIF files (requires Docker, ~30 min first time)
docker build -t cg-scan-freertos eval/sarif_acquisition/freertos/
docker run --rm -v "$(pwd)/eval/data/sarif/freertos:/output" cg-scan-freertos

docker build -t cg-scan-zephyr eval/sarif_acquisition/zephyr/
docker run --rm -v "$(pwd)/eval/data/sarif/zephyr:/output" cg-scan-zephyr

docker build -t cg-scan-espfc eval/sarif_acquisition/espfc/
docker run --rm -v "$(pwd)/eval/data/sarif/espfc:/output" cg-scan-espfc

# 3. Run no-deps experiments immediately (Exp 4, 2, 5, 7)
python eval/run_all.py --skip-llm --skip-gt

# 4. Label ground truth (interactive, ~1h for all 3 projects)
python -m eval.ground_truth.labeler --project freertos
python -m eval.ground_truth.labeler --project zephyr
python -m eval.ground_truth.labeler --project espfc

# 5. Run ground-truth experiments (Exp 1, 6)
python eval/run_all.py --skip-llm

# 6. Run LLM enrichment (requires API key)
export CONSTRAINTGUARD_LLM_API_KEY="sk-..."
export CONSTRAINTGUARD_LLM_MODEL="gpt-5-mini"
python eval/run_all.py --exp 3 --llm-phase generate
# Fill in eval/outputs/raw/exp3_rating_sheet.md
# Save ratings as eval/outputs/raw/exp3_ratings_completed.json
python eval/run_all.py --exp 3 --llm-phase compute
```

## Experiment Overview

| # | Experiment | Needs SARIF | Needs GT | Needs LLM |
|---|-----------|:-----------:|:--------:|:---------:|
| 1 | Precision@10 Comparison | ✓ | ✓ | optional |
| 2 | Alert Demotion Rate | ✓ | | |
| 3 | LLM Enrichment Quality | ✓ | | ✓ + human |
| 4 | CWE-Constraint Heatmap | | | |
| 5 | CI/CD Pipeline Overhead | ✓ | | |
| 6 | Precision@K Curve | ✓ | ✓ | |
| 7 | Rule Family Ablation | ✓ | | |

**Exp 4 requires nothing** — run it first as a smoke test.

## Output Structure

```
eval/outputs/
├── raw/          # CSV data files (one per experiment)
├── figures/      # PDF figures at 300 DPI
└── tables/       # LaTeX .tex fragments (booktabs style)
```

## Reproducing Individual Experiments

Each experiment is independently runnable:

```bash
python -m eval.experiments.exp4_cwe_heatmap   # always works
python -m eval.experiments.exp2_alert_demotion
python -m eval.experiments.exp7_rule_ablation
python -m eval.experiments.exp5_cicd_overhead
python -m eval.experiments.exp1_precision_at10
python -m eval.experiments.exp6_precision_at_k_curve
python -m eval.experiments.exp3_llm_quality --phase generate
python -m eval.experiments.exp3_llm_quality --phase compute
```

## Ground Truth Labeling

```bash
# Interactive session (labels top-30 per project)
python -m eval.ground_truth.labeler --project freertos
python -m eval.ground_truth.labeler --project freertos --resume  # continue
python -m eval.ground_truth.labeler --project freertos --dry-run # preview top-5
```

Labels are saved to `eval/data/ground_truth/<project>_labels.json`.

A finding is labeled **critical** if BOTH:
1. It is genuinely exploitable in the target's constraint context
2. Exploitation would have high impact on system safety/reliability

## LLM Configuration

```bash
export CONSTRAINTGUARD_LLM_PROVIDER=openai      # or: anthropic
export CONSTRAINTGUARD_LLM_MODEL=gpt-5-mini     # model for paper
export CONSTRAINTGUARD_LLM_API_KEY=sk-...
```

Expected cost: <$1 for all 30 enrichment calls (3 projects × 10 findings).

## Invalidating Cache

Scored items are cached in `eval/outputs/raw/<project>_scored.pkl`.
After modifying rules, invalidate the cache:

```bash
python -c "from eval.harness.loader import invalidate_cache; invalidate_cache()"
```

## Environment

- Python 3.10+
- ConstraintGuard installed: `pip install -e .`
- Evaluation deps: `pip install -r eval/requirements-eval.txt`
- Docker (for SARIF generation only)
