"""Experiment 9: LLM Category and Base Score Suggestion for Unknown Findings.

For each project, identifies findings classified as 'unknown', runs LLM enrichment
to obtain a suggested category and base score, then rescores them with the full
deterministic rule engine. Measures the impact on scores and severity tiers.

Run:
    python -m eval.experiments.exp9_unknown_reclassification
    python -m eval.experiments.exp9_unknown_reclassification --projects espfc
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, load_scored_items, load_spec, SARIF_PATH
from eval.visualization.plots import plot_reclassification_paired_bars
from eval.visualization.tables import table_unknown_reclassification

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

SOURCE_ROOT = Path(__file__).parent.parent / "data" / "source"

BATCH_SIZE = 15  # findings per LLM call

# Predefined base score table for lookup when LLM doesn't suggest a score
_PREDEFINED_BASE_SCORES: dict[str, int] = {
    "use_after_free": 65,
    "buffer_overflow": 60,
    "format_string": 55,
    "null_deref": 50,
    "integer_overflow": 50,
    "leak": 45,
    "deadlock": 45,
    "divide_by_zero": 40,
    "uninitialized": 40,
}

_NOVEL_DEFAULT_BASE_SCORE = 50

_BATCH_SYSTEM_PROMPT = (
    "You are an embedded systems security expert. "
    "You will receive a batch of vulnerability findings, all currently classified as 'unknown'. "
    "For each finding, determine the vulnerability category and an appropriate base severity score.\n\n"
    "Predefined categories (use these when they fit): "
    "buffer_overflow, null_deref, leak, use_after_free, integer_overflow, "
    "format_string, divide_by_zero, uninitialized, deadlock.\n"
    "Novel categories are allowed (e.g. race_condition, toctou, logic_error, priority_inversion). "
    'Use "unknown" only if truly indeterminate.\n\n'
    "Base score guidance (0-65, leave room for constraint rules to add 0-35 more):\n"
    "  Memory corruption (use_after_free, buffer_overflow): 55-65\n"
    "  Format/injection (format_string): 50-55\n"
    "  Null/integer issues: 45-50\n"
    "  Leaks, deadlocks: 40-45\n"
    "  Logic/uninitialized: 30-45\n\n"
    "Return a JSON array with one object per finding, in the same order received:\n"
    '[{"id": 0, "category": "string", "base_score": int, "reasoning": "string"}, ...]\n'
    "Use EXACTLY these field names. No extra fields."
)


def _build_batch_prompt(items) -> str:
    lines = ["Classify each of these unknown vulnerability findings:\n"]
    for i, item in enumerate(items):
        v = item.vulnerability
        lines.append(f"[{i}] File: {v.path}:{v.start_line}")
        lines.append(f"    Rule: {v.rule_id}")
        lines.append(f"    Message: {v.message}")
        if v.function:
            lines.append(f"    Function: {v.function}")
        if v.cwe:
            lines.append(f"    CWE: {v.cwe}")
        lines.append("")
    lines.append(
        "Return a JSON array with one entry per finding (indices 0 to "
        f"{len(items) - 1})."
    )
    return "\n".join(lines)


def _batch_categorize_unknowns(unknown_items, client, tracker) -> dict[int, dict]:
    """Send findings in batches to the LLM. Returns {original_index: result_dict}."""
    from constraintguard.llm.models import LLMRequest

    results: dict[int, dict] = {}
    total = len(unknown_items)
    num_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

    for batch_num in range(num_batches):
        start = batch_num * BATCH_SIZE
        end = min(start + BATCH_SIZE, total)
        batch = unknown_items[start:end]

        print(f"    Batch {batch_num + 1}/{num_batches} "
              f"({len(batch)} findings, indices {start}-{end - 1})...")

        request = LLMRequest(
            system_prompt=_BATCH_SYSTEM_PROMPT,
            user_prompt=_build_batch_prompt(batch),
            response_schema=None,  # plain JSON array — no Pydantic schema
        )

        response = client.analyze(request)
        tracker.record(response)

        # Parse the response
        parsed = response.parsed_content
        if not parsed and response.raw_content:
            raw = response.raw_content.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:])
                raw = raw.rstrip("`").strip()
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as e:
                print(f"    WARNING: Could not parse batch {batch_num + 1} response: {e}")
                continue

        # parsed may be a list directly or wrapped in a dict
        if isinstance(parsed, dict):
            # Some models wrap in {"results": [...]} or similar
            for v in parsed.values():
                if isinstance(v, list):
                    parsed = v
                    break

        if not isinstance(parsed, list):
            print(f"    WARNING: Unexpected response format for batch {batch_num + 1}")
            continue

        for entry in parsed:
            try:
                local_idx = int(entry["id"])
                global_idx = start + local_idx
                results[global_idx] = {
                    "suggested_category": entry.get("category"),
                    "suggested_base_score": entry.get("base_score"),
                    "category_reasoning": entry.get("reasoning"),
                }
            except (KeyError, TypeError, ValueError):
                continue

    return results


def _make_client(provider_str: str, model: str, api_key: str):
    from constraintguard.llm.models import LLMConfig, LLMProvider
    from constraintguard.llm.client import AnthropicClient, OpenAIClient

    provider = LLMProvider.ANTHROPIC if "anthropic" in provider_str.lower() else LLMProvider.OPENAI
    config = LLMConfig(provider=provider, model=model, api_key=api_key, timeout=120, max_retries=2)
    return (AnthropicClient(config) if provider == LLMProvider.ANTHROPIC else OpenAIClient(config))


def _run_batch_categorization(unknown_items):
    """Batch-categorize all unknown items; attach results to item.enrichment."""
    from constraintguard.llm.cost import CostTracker
    from constraintguard.models.risk_report import EnrichmentOutput

    provider_str = os.environ.get("CONSTRAINTGUARD_LLM_PROVIDER", "openai")
    model = os.environ.get("CONSTRAINTGUARD_LLM_MODEL", "gpt-4o-mini")
    api_key = os.environ.get("CONSTRAINTGUARD_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY", "")

    if not api_key:
        raise ValueError("No LLM API key found. Set CONSTRAINTGUARD_LLM_API_KEY or OPENAI_API_KEY.")

    client = _make_client(provider_str, model, api_key)
    tracker = CostTracker()

    llm_results = _batch_categorize_unknowns(unknown_items, client, tracker)

    # Attach results to items as EnrichmentOutput
    for idx, item in enumerate(unknown_items):
        data = llm_results.get(idx, {})
        item.enrichment = EnrichmentOutput(
            suggested_category=data.get("suggested_category"),
            suggested_base_score=data.get("suggested_base_score"),
            category_suggestion_reasoning=data.get("category_reasoning"),
        )

    summary = tracker.summarize()
    num_batches = (len(unknown_items) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"    {num_batches} API calls total — "
          f"cost: ${float(summary.total_cost):.4f}  "
          f"tokens: {summary.total_input_tokens}in/{summary.total_output_tokens}out")

    return unknown_items


def _determine_category_type(suggested_category: str | None, resolved_cat) -> str:
    """Determine the classification outcome type."""
    from constraintguard.models.enums import VulnerabilityCategory
    if suggested_category is None or suggested_category.lower() == "unknown":
        return "unknown"
    if resolved_cat is not None and resolved_cat != VulnerabilityCategory.UNKNOWN:
        return "predefined"
    return "novel_llm"  # novel category; score source determined separately


def _rescore_item(item, spec) -> dict:
    """Rescore a single unknown item using its LLM enrichment suggestion.

    Returns a result dict with original/new scores, category info, and outcome.
    """
    from constraintguard.enrichment.analyzer import resolve_suggested_category
    from constraintguard.models.enums import VulnerabilityCategory
    from constraintguard.scoring.base_scores import base_score_for_category
    from constraintguard.scoring.engine import score_vulnerability_with_override

    vuln = item.vulnerability
    enr = item.enrichment

    original_score = item.final_score
    original_tier = item.tier.value
    original_base = item.base_score

    if enr is None or (enr.suggested_category is None and enr.suggested_base_score is None):
        return {
            "status": "no_suggestion",
            "original_item": item,
            "new_item": None,
            "category_type": "unknown",
            "suggested_category": None,
            "suggested_base_score": None,
            "effective_base_score": original_base,
            "original_score": original_score,
            "new_score": original_score,
            "original_tier": original_tier,
            "new_tier": original_tier,
            "score_delta": 0,
            "tier_changed": False,
        }

    suggested = enr.suggested_category
    llm_base = enr.suggested_base_score

    # Resolve suggested category string → enum (None for novel)
    resolved_cat = resolve_suggested_category(suggested)

    from constraintguard.models.enums import VulnerabilityCategory
    is_predefined = (
        resolved_cat is not None
        and resolved_cat != VulnerabilityCategory.UNKNOWN
    )
    is_remained_unknown = (
        suggested is None
        or suggested.lower() == "unknown"
        or (resolved_cat == VulnerabilityCategory.UNKNOWN and llm_base is None)
    )

    if is_remained_unknown:
        return {
            "status": "remained_unknown",
            "original_item": item,
            "new_item": None,
            "category_type": "unknown",
            "suggested_category": suggested,
            "suggested_base_score": llm_base,
            "effective_base_score": original_base,
            "original_score": original_score,
            "new_score": original_score,
            "original_tier": original_tier,
            "new_tier": original_tier,
            "score_delta": 0,
            "tier_changed": False,
        }

    # Determine effective base score
    if llm_base is not None:
        effective_base = llm_base
        if is_predefined:
            category_type = "predefined"
            score_source = "llm"
        else:
            category_type = "novel_llm"
            score_source = "llm"
    elif is_predefined:
        predefined_score = _PREDEFINED_BASE_SCORES.get(resolved_cat.value, 40)
        effective_base = predefined_score
        category_type = "predefined"
        score_source = "predefined"
    else:
        # Novel category, no LLM score
        effective_base = _NOVEL_DEFAULT_BASE_SCORE
        category_type = "novel_default"
        score_source = "default"

    new_item = score_vulnerability_with_override(
        vuln, spec,
        base_score_override=effective_base,
        category_override=resolved_cat if is_predefined else None,
    )
    new_item.enrichment = item.enrichment

    tier_changed = new_item.tier.value != original_tier
    score_delta = new_item.final_score - original_score

    return {
        "status": "reclassified",
        "original_item": item,
        "new_item": new_item,
        "category_type": category_type,
        "score_source": score_source,
        "suggested_category": suggested,
        "suggested_base_score": llm_base,
        "effective_base_score": effective_base,
        "original_score": original_score,
        "new_score": new_item.final_score,
        "original_tier": original_tier,
        "new_tier": new_item.tier.value,
        "score_delta": score_delta,
        "tier_changed": tier_changed,
    }


def _generate_text_examples(results_by_project: dict[str, list[dict]], n: int = 5) -> str:
    """Generate formatted before/after examples for the paper."""
    lines = ["LLM Scoring Decision Examples — ConstraintGuard Exp 9", "=" * 60, ""]

    count = 0
    for project, results in results_by_project.items():
        # Prefer examples where tier changed
        interesting = sorted(
            [r for r in results if r.get("tier_changed")],
            key=lambda r: abs(r.get("score_delta", 0)),
            reverse=True,
        )
        if not interesting:
            interesting = sorted(
                [r for r in results if r.get("status") == "reclassified"],
                key=lambda r: abs(r.get("score_delta", 0)),
                reverse=True,
            )

        for result in interesting[:2]:
            if count >= n:
                break
            item = result["original_item"]
            vuln = item.vulnerability
            enr = item.enrichment

            lines.append(f"Finding: {vuln.path}:{vuln.start_line}")
            lines.append(f"Project: {project}")
            lines.append(
                f"Original: category=unknown, base={result['original_item'].base_score}, "
                f"final={result['original_score']} ({result['original_tier']})"
            )
            lines.append("")
            if enr:
                lines.append("LLM Analysis:")
                lines.append(f"  - Category: \"{result['suggested_category']}\"")
                lines.append(f"  - Base Score: {result['suggested_base_score']}")
                lines.append(f"  - Score Source: {result.get('score_source', 'N/A')}")
                if enr.category_suggestion_reasoning:
                    lines.append(f"  - Reasoning: \"{enr.category_suggestion_reasoning}\"")
            lines.append("")
            new_item = result.get("new_item")
            if new_item:
                rule_summary = " + ".join(
                    f"{rf.rule_id}({rf.delta:+d})" for rf in new_item.rule_firings
                ) or "no rules fired"
                lines.append(
                    f"New Score: base={result['effective_base_score']} + [{rule_summary}] "
                    f"= {result['new_score']} ({result['new_tier']})"
                )
            lines.append(f"Result: {result['original_tier']} → {result['new_tier']}")
            lines.append("-" * 60)
            lines.append("")
            count += 1

        if count >= n:
            break

    return "\n".join(lines)


def run(projects: list[str] | None = None) -> dict:
    """Run Experiment 9 across all specified projects."""
    projects = projects or PROJECTS

    print("=== Experiment 9: LLM Unknown Finding Reclassification ===\n")

    all_detail_rows: list[dict] = []
    all_category_data: dict[str, dict] = {}  # category -> {type, base_score, count, source}
    summary_data: dict[str, dict] = {}
    results_by_project: dict[str, list[dict]] = {}
    espfc_paired: list[dict] = []
    novel_categories_detail: list[dict] = []

    for project in projects:
        sarif_file = SARIF_PATH / project / "findings.sarif"
        if not sarif_file.exists():
            print(f"  [{project}] SKIP — SARIF not found: {sarif_file}")
            continue

        print(f"  [{project}] Loading scored items...")
        try:
            baseline, deterministic, spec = load_scored_items(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        from constraintguard.models.enums import VulnerabilityCategory
        unknown_items = [
            item for item in deterministic
            if item.vulnerability.category == VulnerabilityCategory.UNKNOWN
        ]

        print(f"  [{project}] Found {len(unknown_items)} unknown-category findings.")

        if not unknown_items:
            summary_data[project] = {
                "total_unknown": 0, "predefined_count": 0, "novel_llm_count": 0,
                "novel_default_count": 0, "remained_unknown_count": 0,
                "avg_base_score_change": 0.0, "avg_final_score_change": 0.0,
                "tier_change_count": 0,
            }
            results_by_project[project] = []
            continue

        # Run LLM enrichment
        num_batches = (len(unknown_items) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"  [{project}] Batch-categorizing {len(unknown_items)} findings "
              f"in {num_batches} LLM call(s) (batch size={BATCH_SIZE})...")
        try:
            enriched_items = _run_batch_categorization(unknown_items)
        except Exception as e:
            print(f"  [{project}] LLM batch categorization failed: {e}")
            print("  Using placeholder results (no reclassification)...")
            enriched_items = unknown_items

        # Rescore each item
        results: list[dict] = []
        for item in enriched_items:
            result = _rescore_item(item, spec)
            results.append(result)

        results_by_project[project] = results

        # Aggregate metrics
        predefined_count = sum(1 for r in results if r["category_type"] == "predefined")
        novel_llm_count = sum(1 for r in results if r["category_type"] == "novel_llm")
        novel_default_count = sum(1 for r in results if r["category_type"] == "novel_default")
        remained_unknown = sum(1 for r in results if r["category_type"] == "unknown")
        tier_changes = sum(1 for r in results if r.get("tier_changed", False))

        base_deltas = [
            r["effective_base_score"] - r["original_item"].base_score
            for r in results
        ]
        final_deltas = [r["score_delta"] for r in results]
        avg_base_delta = sum(base_deltas) / len(base_deltas) if base_deltas else 0.0
        avg_final_delta = sum(final_deltas) / len(final_deltas) if final_deltas else 0.0

        summary_data[project] = {
            "total_unknown": len(results),
            "predefined_count": predefined_count,
            "novel_llm_count": novel_llm_count,
            "novel_default_count": novel_default_count,
            "remained_unknown_count": remained_unknown,
            "avg_base_score_change": avg_base_delta,
            "avg_final_score_change": avg_final_delta,
            "tier_change_count": tier_changes,
        }

        print(f"  [{project}] Reclassified: predefined={predefined_count}, "
              f"novel_llm={novel_llm_count}, novel_default={novel_default_count}, "
              f"remained_unknown={remained_unknown}, tier_changes={tier_changes}")

        # Collect per-finding rows
        for i, result in enumerate(results):
            item = result["original_item"]
            vuln = item.vulnerability
            row = {
                "project": project,
                "path": vuln.path,
                "line": vuln.start_line or "",
                "rule_id": vuln.rule_id,
                "original_base_score": result["original_item"].base_score,
                "original_score": result["original_score"],
                "original_tier": result["original_tier"],
                "suggested_category": result.get("suggested_category") or "",
                "suggested_base_score": result.get("suggested_base_score") or "",
                "effective_base_score": result["effective_base_score"],
                "new_score": result["new_score"],
                "new_tier": result["new_tier"],
                "score_delta": result["score_delta"],
                "tier_changed": result.get("tier_changed", False),
                "category_type": result["category_type"],
                "score_source": result.get("score_source", ""),
            }
            all_detail_rows.append(row)

            # Collect for esp-fc paired figure
            if project == "espfc":
                espfc_paired.append({
                    "finding_id": f"{Path(vuln.path).name}:{vuln.start_line}",
                    "original_score": result["original_score"],
                    "new_score": result["new_score"],
                    "new_category": result.get("suggested_category") or "unknown",
                    "new_base_score": result["effective_base_score"],
                    "category_type": result["category_type"],
                })

        # Collect category distribution data
        for result in results:
            cat = result.get("suggested_category") or "unknown"
            cat_type = result["category_type"]
            base = result["effective_base_score"]
            source = result.get("score_source", "")

            key = cat.lower().strip()
            if key not in all_category_data:
                all_category_data[key] = {
                    "category": cat,
                    "type": cat_type,
                    "base_score": base,
                    "count": 0,
                    "score_source": source,
                }
            all_category_data[key]["count"] += 1

            # Collect novel category details
            if cat_type in ("novel_llm", "novel_default"):
                enr = result["original_item"].enrichment
                novel_categories_detail.append({
                    "project": project,
                    "category": cat,
                    "category_type": cat_type,
                    "base_score": base,
                    "score_source": source,
                    "path": result["original_item"].vulnerability.path,
                    "line": result["original_item"].vulnerability.start_line,
                    "reasoning": enr.category_suggestion_reasoning if enr else None,
                })

    # Write all output files
    _write_outputs(
        all_detail_rows, summary_data, all_category_data,
        espfc_paired, novel_categories_detail, results_by_project
    )

    return {"summary": summary_data, "total_findings": len(all_detail_rows)}


def _write_outputs(
    detail_rows: list[dict],
    summary_data: dict[str, dict],
    category_data: dict[str, dict],
    espfc_paired: list[dict],
    novel_categories_detail: list[dict],
    results_by_project: dict[str, list[dict]],
) -> None:
    """Write all CSV, JSON, and text output files."""

    # 1. Per-finding reclassification detail
    detail_path = OUTPUTS_RAW / "exp9_reclassification_detail.csv"
    fieldnames = [
        "project", "path", "line", "rule_id",
        "original_base_score", "original_score", "original_tier",
        "suggested_category", "suggested_base_score", "effective_base_score",
        "new_score", "new_tier", "score_delta", "tier_changed",
        "category_type", "score_source",
    ]
    with open(detail_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(detail_rows)
    print(f"  CSV saved: {detail_path}")

    # 2. Per-project summary
    summary_path = OUTPUTS_RAW / "exp9_summary.csv"
    summary_fieldnames = [
        "project", "total_unknown", "predefined_count", "novel_llm_count",
        "novel_default_count", "remained_unknown_count",
        "avg_base_score_change", "avg_final_score_change", "tier_change_count",
    ]
    with open(summary_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fieldnames)
        writer.writeheader()
        for project, d in summary_data.items():
            writer.writerow({"project": project, **d})
    print(f"  CSV saved: {summary_path}")

    # 3. Category score distribution
    cat_path = OUTPUTS_RAW / "exp9_category_scores.csv"
    cat_fieldnames = ["category", "type", "base_score", "count", "score_source"]
    with open(cat_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cat_fieldnames)
        writer.writeheader()
        for row in sorted(category_data.values(), key=lambda x: -x["count"]):
            writer.writerow({k: row.get(k, "") for k in cat_fieldnames})
    print(f"  CSV saved: {cat_path}")

    # 4. Tier changes per project
    tier_path = OUTPUTS_RAW / "exp9_tier_changes.csv"
    tier_rows = []
    for project, results in results_by_project.items():
        transitions: dict[str, int] = defaultdict(int)
        for r in results:
            if r.get("tier_changed"):
                key = f"{r['original_tier']}→{r['new_tier']}"
                transitions[key] += 1
        for transition, count in sorted(transitions.items()):
            tier_rows.append({"project": project, "transition": transition, "count": count})
    with open(tier_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "transition", "count"])
        writer.writeheader()
        writer.writerows(tier_rows)
    print(f"  CSV saved: {tier_path}")

    # 5. esp-fc paired scores for Figure 1
    paired_path = OUTPUTS_RAW / "exp9_paired_scores_espfc.csv"
    paired_fieldnames = [
        "finding_id", "original_score", "new_score",
        "new_category", "new_base_score", "category_type",
    ]
    with open(paired_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=paired_fieldnames)
        writer.writeheader()
        writer.writerows(espfc_paired)
    print(f"  CSV saved: {paired_path}")

    # 6. Base score distribution (for histogram figure)
    dist_path = OUTPUTS_RAW / "exp9_base_score_distribution.csv"
    dist_rows = [
        {"base_score": r["effective_base_score"], "category_type": r["category_type"]}
        for r in detail_rows if r["category_type"] != "unknown"
    ]
    with open(dist_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["base_score", "category_type"])
        writer.writeheader()
        writer.writerows(dist_rows)
    print(f"  CSV saved: {dist_path}")

    # 7. Scoring examples text file
    examples_path = OUTPUTS_RAW / "exp9_scoring_examples.txt"
    examples_text = _generate_text_examples(results_by_project, n=5)
    examples_path.write_text(examples_text)
    print(f"  TXT saved: {examples_path}")

    # 8. Novel categories detail JSON
    novel_path = OUTPUTS_RAW / "exp9_novel_categories_detail.json"
    novel_path.write_text(json.dumps(novel_categories_detail, indent=2, default=str))
    print(f"  JSON saved: {novel_path}")

    # 9. Figure: paired bar chart (esp-fc) — reviewer-requested deliverable
    if detail_rows:
        pdf_path = plot_reclassification_paired_bars(detail_rows, project="espfc")
        print(f"  Figure saved: {pdf_path}")

    # 10. LaTeX table — Project | Findings Reclassified | Category Distribution | Tier Changes
    if summary_data:
        tex_path = table_unknown_reclassification(summary_data, detail_rows)
        print(f"  Table saved: {tex_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Experiment 9: LLM Unknown Finding Reclassification"
    )
    parser.add_argument(
        "--projects",
        default=",".join(PROJECTS),
        help="Comma-separated project list (default: all)",
    )
    args = parser.parse_args()

    project_list = [p.strip() for p in args.projects.split(",") if p.strip()]
    result = run(projects=project_list)
    print(f"\nExp 9 complete. Processed {result.get('total_findings', 0)} unknown findings.")
