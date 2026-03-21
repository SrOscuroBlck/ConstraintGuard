"""Experiment 3: Agentic AI Enrichment Quality.

Two-phase experiment:
  Phase A: Run LLM enrichment on top-10 findings per project.
           Generate a human-readable rating sheet (Markdown).
  Phase B: Read completed rating sheet with expert scores.
           Compute average metrics and generate table/chart.

Requires SARIF files and an LLM API key.
Expert annotation is required before Phase B can run.

Run independently:
    # Phase A (generate rating sheet):
    python -m eval.experiments.exp3_llm_quality --phase generate

    # Phase B (compute metrics from completed ratings):
    python -m eval.experiments.exp3_llm_quality --phase compute
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, load_scored_items, load_spec, load_vulnerabilities, SARIF_PATH
from eval.visualization.plots import plot_llm_quality
from eval.visualization.tables import table_llm_quality

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

RATING_SHEET_PATH = OUTPUTS_RAW / "exp3_rating_sheet.md"
RATINGS_INPUT_PATH = OUTPUTS_RAW / "exp3_ratings_completed.json"

SOURCE_ROOT = Path(__file__).parent.parent / "data" / "source"

LLM_TOP_K = 10


def _run_enrichment(project: str, top_k_items, spec, source_root: Path | None = None):
    """Run LLM enrichment on top-K items and return (enriched_items, new_discoveries)."""
    from constraintguard.enrichment.analyzer import enrich_items
    from constraintguard.enrichment.policy import SelectionMode, SelectionPolicy, select_for_enrichment
    from constraintguard.evidence.extractor import extract_evidence_batch
    from constraintguard.llm.models import LLMConfig, LLMProvider
    from constraintguard.llm.cost import CostTracker

    provider_str = os.environ.get("CONSTRAINTGUARD_LLM_PROVIDER", "openai")
    model = os.environ.get("CONSTRAINTGUARD_LLM_MODEL", "gpt-5-mini")
    api_key = os.environ.get("CONSTRAINTGUARD_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY", "")

    if not api_key:
        raise ValueError(
            "No LLM API key found. Set CONSTRAINTGUARD_LLM_API_KEY or OPENAI_API_KEY."
        )

    provider = LLMProvider.ANTHROPIC if "anthropic" in provider_str.lower() else LLMProvider.OPENAI
    config = LLMConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        timeout=120,
        max_retries=2,
    )

    if provider == LLMProvider.ANTHROPIC:
        from constraintguard.llm.client import AnthropicClient
        client = AnthropicClient(config)
    else:
        from constraintguard.llm.client import OpenAIClient
        client = OpenAIClient(config)

    policy = SelectionPolicy(mode=SelectionMode.TOPK, top_k=LLM_TOP_K)
    result = select_for_enrichment(top_k_items, policy)
    candidates = result.selected_items

    source_path = source_root or Path(".")
    bundles = extract_evidence_batch(
        [item.vulnerability for item in candidates], source_path, spec
    )

    tracker = CostTracker()
    all_items = enrich_items(candidates, bundles, spec, client, tracker)

    # enrich_items returns selected_items (enriched in-place) + new_discoveries
    enriched_items = all_items[:len(candidates)]
    new_discoveries = all_items[len(candidates):]

    summary = tracker.summarize()
    print(f"    LLM cost: ${float(summary.total_cost):.4f}  tokens: {summary.total_input_tokens}in/{summary.total_output_tokens}out")

    return enriched_items, new_discoveries


def generate_rating_sheet(projects: list[str]) -> Path:
    """Phase A: Generate Markdown rating sheet for expert annotation."""
    print("=== Experiment 3 Phase A: Generating LLM Rating Sheet ===\n")

    lines = [
        "# ConstraintGuard LLM Enrichment Quality — Expert Rating Sheet",
        f"\nGenerated: {datetime.now(timezone.utc).isoformat()}",
        "\n## Instructions",
        "\nFor each finding below, rate the LLM output on THREE dimensions:",
        "1. **Usefulness** (1-5): Is the explanation actionable? (1=useless, 5=highly actionable)",
        "2. **Evidence Correctness** (0-100%): Do the cited line numbers / code facts match the actual source?",
        "3. **Tag Accuracy** (0-100%): Are the contextual tags (ISR-reachable, blocking-call, etc.) correct?",
        "\nFill in the `RATING:` fields. Do not modify anything else.",
        "\n---\n",
    ]

    all_enriched_data = {}

    for project in projects:
        try:
            baseline, deterministic, spec = load_scored_items(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        print(f"  [{project}] Running LLM enrichment on top-{LLM_TOP_K} findings...")
        try:
            enriched_items, new_discoveries = _run_enrichment(project, deterministic, spec, source_root=SOURCE_ROOT)
        except Exception as e:
            print(f"  [{project}] LLM enrichment failed: {e}")
            print("  Generating placeholder entries...")
            enriched_items = deterministic[:LLM_TOP_K]
            new_discoveries = []

        all_enriched_data[project] = {
            "enriched": [(i.vulnerability.path, i.vulnerability.start_line, i.enrichment) for i in enriched_items],
        }

        lines.append(f"## Project: {project.upper()}\n")

        for rank, item in enumerate(enriched_items, 1):
            v = item.vulnerability
            enr = item.enrichment

            lines.append(f"### Finding {rank}: {v.path}:{v.start_line}")
            lines.append(f"- **Category**: {v.category.value}")
            lines.append(f"- **Rule ID**: {v.rule_id}")
            lines.append(f"- **CWE**: {v.cwe or 'N/A'}")
            lines.append(f"- **Function**: {v.function or 'N/A'}")
            lines.append(f"- **Expert Score**: {item.final_score} ({item.tier.value})")
            lines.append(f"- **Rules Fired**: {', '.join(f.rule_id for f in item.rule_firings)}")
            lines.append("")

            if enr:
                lines.append("**LLM Explanation:**")
                lines.append(f"> {enr.llm_explanation or 'N/A'}")
                lines.append("")
                lines.append(f"**LLM Tags**: {', '.join(enr.tags) if enr.tags else 'None'}")
                lines.append("")
                if enr.fix_suggestions:
                    lines.append("**Fix Suggestions:**")
                    for fix in enr.fix_suggestions:
                        lines.append(f"- Line {fix.line}: `{fix.proposed_code[:80]}`")
                    lines.append("")
                if enr.evidence_citations:
                    lines.append("**Evidence Citations:**")
                    for cite in enr.evidence_citations:
                        lines.append(f"- {cite.file_path}:{cite.start_line}-{cite.end_line}")
                    lines.append("")
            else:
                lines.append("**LLM Explanation**: *No enrichment available*\n")

            lines.append("**RATING** (fill in below):")
            lines.append(f"- Usefulness: <!-- 1-5 -->")
            lines.append(f"- Evidence Correctness: <!-- 0-100 -->")
            lines.append(f"- Tag Accuracy: <!-- 0-100 -->")
            lines.append(f"- Notes: <!-- optional -->")
            lines.append("\n---\n")

    RATING_SHEET_PATH.write_text("\n".join(lines))
    print(f"\n  Rating sheet saved: {RATING_SHEET_PATH}")
    print("  Fill in the RATING fields and then run Phase B.")
    return RATING_SHEET_PATH


def compute_metrics_from_ratings(projects: list[str]) -> dict[str, dict[str, float]]:
    """Phase B: Read completed JSON ratings and compute metrics."""
    print("=== Experiment 3 Phase B: Computing LLM Quality Metrics ===\n")

    if not RATINGS_INPUT_PATH.exists():
        print(f"  ERROR: Ratings file not found: {RATINGS_INPUT_PATH}")
        print("  Complete the rating sheet and save ratings as JSON:")
        print('  {"freertos": {"usefulness": 4.2, "evidence_correctness": 94, "tag_accuracy": 89}, ...}')
        return {}

    ratings = json.loads(RATINGS_INPUT_PATH.read_text())
    results: dict[str, dict[str, float]] = {}
    rows_for_csv = []

    for project, data in ratings.items():
        results[project] = {
            "usefulness": data.get("usefulness", 0),
            "evidence_correctness": data.get("evidence_correctness", 0),
            "tag_accuracy": data.get("tag_accuracy", 0),
        }
        rows_for_csv.append({
            "project": project,
            "usefulness": data.get("usefulness", 0),
            "evidence_correctness": data.get("evidence_correctness", 0),
            "tag_accuracy": data.get("tag_accuracy", 0),
        })
        print(f"  [{project}]")
        print(f"    Usefulness:           {data.get('usefulness', 0):.1f}/5")
        print(f"    Evidence Correctness: {data.get('evidence_correctness', 0):.0f}%")
        print(f"    Tag Accuracy:         {data.get('tag_accuracy', 0):.0f}%")

    csv_path = OUTPUTS_RAW / "exp3_llm_quality.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "usefulness", "evidence_correctness", "tag_accuracy"])
        writer.writeheader()
        writer.writerows(rows_for_csv)
    print(f"\n  CSV saved: {csv_path}")

    if results:
        pdf_path = plot_llm_quality(results)
        tex_path = table_llm_quality(results)
        print(f"  Figure saved: {pdf_path}")
        print(f"  Table saved: {tex_path}")

    return results


def run(projects: list[str] | None = None, phase: str = "generate") -> dict:
    projects = projects or PROJECTS
    if phase == "generate":
        path = generate_rating_sheet(projects)
        return {"rating_sheet": str(path)}
    elif phase == "compute":
        return compute_metrics_from_ratings(projects)
    else:
        raise ValueError(f"Unknown phase: {phase}. Use 'generate' or 'compute'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment 3: LLM Enrichment Quality")
    parser.add_argument("--phase", choices=["generate", "compute"], default="generate",
                        help="generate: run LLM enrichment + rating sheet; compute: process completed ratings")
    args = parser.parse_args()

    result = run(phase=args.phase)
    print(f"\nExp 3 Phase '{args.phase}' complete.")
