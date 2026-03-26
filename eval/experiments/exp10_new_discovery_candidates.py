"""Experiment 10: LLM New Discovery Candidates.

Reads pre-computed discoveries.json files produced by the Docker scan
containers (eval/data/sarif/{project}/discoveries.json), classifies each
candidate as CONFIRMED or DUPLICATE against the original SARIF, and
generates output files for the paper.

The LLM runs INSIDE Docker during the scan step — this experiment is
purely analytical and requires no API key or source code on the host.

Regenerate discoveries.json (rebuild + rerun Docker containers):
    docker build -t cg-scan-freertos -f eval/sarif_acquisition/freertos/Dockerfile eval/sarif_acquisition/
    docker run --rm \\
      -v "$(pwd)/eval/data/sarif/freertos:/output" \\
      -e CONSTRAINTGUARD_LLM_API_KEY \\
      -e CONSTRAINTGUARD_LLM_MODEL \\
      -e CONSTRAINTGUARD_LLM_PROVIDER \\
      cg-scan-freertos

Run this experiment:
    python -m eval.experiments.exp10_new_discovery_candidates
    python -m eval.experiments.exp10_new_discovery_candidates --projects espfc
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from eval.harness.loader import PROJECTS, SARIF_PATH, load_scored_items, load_vulnerabilities
from constraintguard.enrichment.analyzer import create_new_findings_from_discoveries

OUTPUTS_RAW = Path(__file__).parent.parent / "outputs" / "raw"
OUTPUTS_RAW.mkdir(parents=True, exist_ok=True)

LINE_TOLERANCE = 5

_WHY_MISSED = {
    "race_condition":           "Requires inter-thread path-sensitive analysis beyond Clang SA's intra-procedural scope.",
    "toctou":                   "TOCTOU detection requires modeling concurrent access patterns across separate code paths.",
    "timing_side_channel":      "Timing side-channel analysis requires execution-time modeling unavailable in static analysis.",
    "blocking_call_in_isr":     "ISR context tracking across call boundaries is not modeled by Clang SA.",
    "priority_inversion":       "Priority inversion requires RTOS-aware scheduling model not present in Clang SA.",
    "incorrect_volatile":       "Volatile correctness for concurrent embedded patterns requires aliasing + concurrency analysis.",
    "unprotected_shared_state": "Concurrency-aware alias analysis for shared state is outside Clang SA's scope.",
    "stack_vla":                "VLA stack usage analysis in constrained contexts requires hardware profile knowledge.",
    "logic_error":              "Logic errors require semantic understanding of intended behavior beyond syntactic analysis.",
}
_WHY_MISSED_DEFAULT = "The vulnerability type falls outside the static analyzer's built-in checkers."


def _load_discoveries(project: str) -> list[dict]:
    """Read discoveries.json produced by the Docker scan container."""
    path = SARIF_PATH / project / "discoveries.json"
    if not path.exists():
        print(f"  [{project}] No discoveries.json found at {path}")
        print(f"  [{project}] Rebuild and rerun the Docker container with LLM env vars to generate it.")
        return []
    data = json.loads(path.read_text())
    print(f"  [{project}] Loaded {len(data)} raw candidate(s) from {path.name}")
    return data


def _paths_match(path_a: str, path_b: str) -> bool:
    if not path_a or not path_b:
        return False
    a, b = Path(path_a), Path(path_b)
    if a == b:
        return True
    parts_a, parts_b = a.parts, b.parts
    min_len = min(len(parts_a), len(parts_b))
    if min_len == 0:
        return False
    return parts_a[-min_len:] == parts_b[-min_len:]


def _classify_candidate(candidate_path: str, candidate_line: int | None, sarif_vulns) -> str:
    if candidate_line is None:
        return "CONFIRMED"
    for vuln in sarif_vulns:
        if vuln.start_line is None:
            continue
        if not _paths_match(candidate_path, vuln.path):
            continue
        if abs(candidate_line - vuln.start_line) <= LINE_TOLERANCE:
            return "DUPLICATE"
    return "CONFIRMED"


def _classify_all_candidates(new_findings, sarif_vulns, project: str) -> list[dict]:
    results = []
    for item in new_findings:
        v = item.vulnerability
        classification = _classify_candidate(v.path, v.start_line, sarif_vulns)
        results.append({
            "project": project,
            "file_path": v.path,
            "start_line": v.start_line,
            "vuln_type": v.rule_id,
            "message": v.message,
            "category": v.category.value,
            "classification": classification,
            "final_score": item.final_score,
            "tier": item.tier.value,
        })
    return results


def _generate_examples_text(confirmed: list[dict], n: int = 3) -> str:
    if not confirmed:
        return "No CONFIRMED new discovery candidates found across all projects.\n"

    selected: list[dict] = []
    projects_seen: set[str] = set()
    for c in confirmed:
        if len(selected) >= n:
            break
        if c["project"] not in projects_seen or len(selected) < n:
            selected.append(c)
            projects_seen.add(c["project"])

    project_display = {"freertos": "FreeRTOS", "zephyr": "Zephyr", "espfc": "esp-fc"}
    lines = ["LLM New Discovery Candidates — Concrete Examples", "=" * 50, ""]
    for i, c in enumerate(selected, 1):
        raw_type = c["vuln_type"].replace("LLM-", "").lower().replace("-", "_")
        why_missed = _WHY_MISSED.get(raw_type, _WHY_MISSED_DEFAULT)
        lines += [
            f"Example {i}: {project_display.get(c['project'], c['project'])} — "
            f"{raw_type.replace('_', ' ').title()}",
            f"Location: {c['file_path']}:{c['start_line']}",
            f"Vulnerability Type: {raw_type.replace('_', ' ')}",
            f"LLM Description: {c['message']}",
            f"Risk Score: {c['final_score']} ({c['tier']})",
            f"Why Static Analyzer Missed It: {why_missed}",
            "",
        ]
    return "\n".join(lines)


def _write_outputs(all_candidates: list[dict], summary: dict[str, dict]) -> None:
    json_path = OUTPUTS_RAW / "exp10_llm_candidates_all.json"
    json_path.write_text(json.dumps(all_candidates, indent=2))
    print(f"  Saved: {json_path}")

    table_path = OUTPUTS_RAW / "exp10_llm_candidates_table.csv"
    with open(table_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["project", "total_candidates", "confirmed_new", "duplicate", "precision_pct"],
        )
        writer.writeheader()
        for project, d in summary.items():
            writer.writerow({"project": project, **d})
    print(f"  Saved: {table_path}")

    figure_path = OUTPUTS_RAW / "exp10_llm_candidates_figure.csv"
    with open(figure_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project", "confirmed", "duplicate"])
        writer.writeheader()
        for project, d in summary.items():
            writer.writerow({"project": project, "confirmed": d["confirmed_new"], "duplicate": d["duplicate"]})
    print(f"  Saved: {figure_path}")

    confirmed = [c for c in all_candidates if c["classification"] == "CONFIRMED"]
    examples_path = OUTPUTS_RAW / "exp10_llm_candidates_examples.txt"
    examples_path.write_text(_generate_examples_text(confirmed))
    print(f"  Saved: {examples_path}")


def run(projects: list[str] | None = None) -> dict:
    """Main entry point. Reads discoveries.json per project, classifies, generates outputs."""
    projects = projects or PROJECTS
    print("=== Experiment 10: LLM New Discovery Candidates ===\n")

    all_candidates: list[dict] = []
    summary: dict[str, dict] = {}

    for project in projects:
        print(f"  [{project}] Loading scored items...")
        try:
            _baseline, deterministic, spec = load_scored_items(project)
            sarif_vulns = load_vulnerabilities(project)
        except FileNotFoundError as e:
            print(f"  [{project}] SKIP — {e}")
            continue

        raw_discoveries = _load_discoveries(project)
        if not raw_discoveries:
            summary[project] = {"total_candidates": 0, "confirmed_new": 0, "duplicate": 0, "precision_pct": 0.0}
            continue

        # Convert raw dicts → scored RiskItems (reuses production code)
        new_findings = create_new_findings_from_discoveries(raw_discoveries, spec, deterministic)

        candidates = _classify_all_candidates(new_findings, sarif_vulns, project)
        all_candidates.extend(candidates)

        total = len(candidates)
        confirmed = sum(1 for c in candidates if c["classification"] == "CONFIRMED")
        duplicate = total - confirmed
        precision = (confirmed / total * 100) if total > 0 else 0.0

        summary[project] = {
            "total_candidates": total,
            "confirmed_new": confirmed,
            "duplicate": duplicate,
            "precision_pct": round(precision, 1),
        }
        print(
            f"  [{project}] total={total}  confirmed={confirmed}  "
            f"duplicate={duplicate}  precision={precision:.1f}%"
        )

    _write_outputs(all_candidates, summary)

    if summary:
        try:
            from eval.visualization.plots import plot_new_discovery_candidates
            from eval.visualization.tables import table_new_discovery_candidates
            pdf_path = plot_new_discovery_candidates(summary)
            tex_path = table_new_discovery_candidates(summary)
            print(f"  Figure: {pdf_path}")
            print(f"  Table:  {tex_path}")
        except Exception as e:
            print(f"  Visualization failed: {e}")

    return {"summary": summary, "total_candidates": len(all_candidates)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment 10: LLM New Discovery Candidates")
    parser.add_argument("--projects", default=",".join(PROJECTS))
    args = parser.parse_args()
    project_list = [p.strip() for p in args.projects.split(",") if p.strip()]
    result = run(projects=project_list)
    print(f"\nExp 10 complete. Total candidates: {result.get('total_candidates', 0)}")
