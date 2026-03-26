"""LaTeX booktabs table generators for ConstraintGuard evaluation."""

from __future__ import annotations

from pathlib import Path

TABLES_DIR = Path(__file__).parent.parent / "outputs" / "tables"
TABLES_DIR.mkdir(parents=True, exist_ok=True)

PROJECTS_DISPLAY = {"freertos": "FreeRTOS", "zephyr": "Zephyr", "espfc": "esp-fc"}


def _bold_max(values: list[float], fmt: str = ".1f") -> list[str]:
    """Return formatted strings, bolding the maximum value."""
    if not values:
        return []
    max_val = max(values)
    return [
        f"\\textbf{{{v:{fmt}}}}" if v == max_val else f"{v:{fmt}}"
        for v in values
    ]


def _save_tex(content: str, name: str) -> Path:
    path = TABLES_DIR / f"{name}.tex"
    path.write_text(content)
    print(f"  Saved: {path}")
    return path


def table_precision_accuracy(
    data: dict[str, dict[str, float]],
    filename: str = "exp1_precision_accuracy",
) -> Path:
    """LaTeX table: Prioritization accuracy (Exp 1).

    data: {project: {baseline_p10, deterministic_p10, full_system_p10, demotion_rate, expert_agreement}}
    """
    projects = list(data.keys())
    columns = ["baseline_p10", "deterministic_p10", "full_system_p10", "demotion_rate", "expert_agreement"]

    # Bold best in each column
    col_vals = {c: [data[p].get(c, 0) * 100 for p in projects] for c in columns}
    col_bold = {c: _bold_max(col_vals[c]) for c in columns}

    rows = []
    for i, project in enumerate(projects):
        name = PROJECTS_DISPLAY.get(project, project)
        row = " & ".join([name] + [col_bold[c][i] for c in columns]) + r" \\"
        rows.append(row)

    # Average row
    avgs = []
    for c in columns:
        vals = col_vals[c]
        avgs.append(f"{sum(vals)/len(vals):.2f}" if vals else "—")
    rows.append(r"\midrule")
    rows.append(r"\textbf{Average} & " + " & ".join(f"\\textbf{{{a}}}" for a in avgs) + r" \\")

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Prioritization accuracy across configurations and projects. "
        r"All values in \%. Bold indicates best per column.}",
        r"\label{tab:precision_accuracy}",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Project & Baseline P@10 & Determ.\ P@10 & Full P@10 & Demotion & Expert Agree. \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)


def table_llm_quality(
    data: dict[str, dict[str, float]],
    filename: str = "exp3_llm_quality",
) -> Path:
    """LaTeX table: LLM enrichment quality (Exp 3).

    data: {project: {usefulness: 0-5, evidence_correctness: 0-100, tag_accuracy: 0-100}}
    """
    projects = list(data.keys())
    metrics = ["usefulness", "evidence_correctness", "tag_accuracy"]
    metric_labels = ["Usefulness (1–5)", "Evidence Correctness (\\%)", "Tag Accuracy (\\%)"]

    rows = []
    for metric, label in zip(metrics, metric_labels):
        vals = [data[p].get(metric, 0) for p in projects]
        avg = sum(vals) / len(vals) if vals else 0

        if metric == "usefulness":
            fmt_vals = [f"{v:.1f}" for v in vals]
            fmt_avg = f"{avg:.1f}"
        else:
            fmt_vals = [f"{v:.0f}\\%" for v in vals]
            fmt_avg = f"{avg:.0f}\\%"

        row = label + " & " + " & ".join(fmt_vals) + f" & \\textbf{{{fmt_avg}}}" + r" \\"
        rows.append(row)

    headers = " & ".join(
        [PROJECTS_DISPLAY.get(p, p) for p in projects] + ["Average"]
    )

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{LLM enrichment quality across projects.}",
        r"\label{tab:llm_quality}",
        r"\begin{tabular}{l" + "r" * (len(projects) + 1) + "}",
        r"\toprule",
        f"Metric & {headers} \\\\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)


def table_cicd_overhead(
    data: dict[str, dict[str, float]],
    filename: str = "exp5_cicd_overhead",
) -> Path:
    """LaTeX table: CI/CD pipeline overhead in seconds (Exp 5).

    data: {"full": {stage: seconds}, "cached": {stage: seconds}}
    """
    stage_keys = ["parse_sarif", "load_constraints", "score_all", "write_reports"]
    stage_labels = ["Static Analysis", "Constraint Extraction", "Deterministic Scoring", "Reporting"]

    rows = []
    for key, label in zip(stage_keys, stage_labels):
        full = data.get("full", {}).get(key, 0) * 1000
        cached = data.get("cached", {}).get(key, 0) * 1000
        rows.append(f"{label} & {full:.2f} & {cached:.2f} \\\\")

    full_total = sum(data.get("full", {}).get(k, 0) for k in stage_keys) * 1000
    cached_total = sum(data.get("cached", {}).get(k, 0) for k in stage_keys) * 1000
    rows.append(r"\midrule")
    rows.append(f"\\textbf{{Total}} & \\textbf{{{full_total:.2f}}} & \\textbf{{{cached_total:.2f}}} \\\\")

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{CI/CD pipeline overhead (ms) per stage. LLM enrichment runs asynchronously and is excluded.}",
        r"\label{tab:cicd_overhead}",
        r"\begin{tabular}{lrr}",
        r"\toprule",
        r"Stage & Full (ms) & Cached (ms) \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)


def table_unknown_reclassification(
    summary_data: dict[str, dict],
    detail_rows: list[dict],
    filename: str = "exp9_reclassification_summary",
) -> Path:
    """LaTeX table: LLM-Assisted Category Reclassification (Exp 9).

    Columns: Project | Findings Reclassified | Category Distribution | Tier Changes After Rescoring

    summary_data: {project: {total_unknown, remained_unknown_count, tier_change_count}}
    detail_rows: per-finding rows with project, suggested_category, category_type fields
    """
    from collections import Counter, defaultdict

    # Build per-project category counts (exclude "unknown" / empty)
    per_project_cats: dict[str, Counter] = defaultdict(Counter)
    for r in detail_rows:
        cat = (r.get("suggested_category") or "").strip().lower()
        if cat and cat != "unknown" and r.get("category_type") != "unknown":
            per_project_cats[r["project"]][cat] += 1

    projects = list(summary_data.keys())
    rows = []
    for project in projects:
        d = summary_data[project]
        name = PROJECTS_DISPLAY.get(project, project)
        reclassified = int(d.get("total_unknown", 0)) - int(d.get("remained_unknown_count", 0))
        tier_changes = int(d.get("tier_change_count", 0))

        top_cats = per_project_cats[project].most_common(3)
        cat_str = ", ".join(
            f"{cat.replace('_', r'\_')} ({cnt})" for cat, cnt in top_cats
        ) or "---"

        rows.append(f"{name} & {reclassified} & {cat_str} & {tier_changes} \\\\")

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        r"\caption{LLM-assisted reclassification of \textsc{unknown} findings. "
        r"Findings Reclassified excludes those the LLM could not categorize. "
        r"Category Distribution lists the top assigned categories (count). "
        r"Tier Changes reports findings that crossed a severity boundary after rescoring.}",
        r"\label{tab:unknown_reclassification}",
        r"\begin{tabular}{llrr}",
        r"\toprule",
        r"Project & Findings Reclassified & Category Distribution & Tier Changes After Rescoring \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)


def table_new_discovery_candidates(
    summary: dict[str, dict],
    filename: str = "exp10_new_discovery_candidates",
) -> Path:
    """LaTeX table: LLM new discovery candidates (Exp 10).

    summary: {project: {total_candidates, confirmed_new, duplicate, precision_pct}}
    """
    rows = []
    for project, d in summary.items():
        name = PROJECTS_DISPLAY.get(project, project)
        rows.append(
            f"{name} & {d['total_candidates']} & {d['confirmed_new']} "
            f"& {d['duplicate']} & {d['precision_pct']:.1f} \\\\"
        )

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        r"\caption{LLM new discovery candidates auto-classified against original SARIF findings. "
        r"Precision = Confirmed / Total $\times$ 100.}",
        r"\label{tab:new_discovery_candidates}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Project & Total Candidates & Confirmed New & Duplicate & Precision (\%) \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)


def table_constraint_sensitivity(
    data: list[dict],
    filename: str = "exp8_constraint_sensitivity",
) -> Path:
    """LaTeX table: per-finding scores and tiers under 4 hardware profiles (Exp 8).

    data: list of {
        "label": str,       # finding short label
        "category": str,    # vulnerability category
        "baseline": int,
        "relaxed": int,
        "safety": int,
        "tight": int,
    }
    """
    def score_tier(s: int) -> str:
        if s >= 85:
            return "C"
        if s >= 70:
            return "H"
        if s >= 40:
            return "M"
        return "L"

    def fmt_cell(s: int) -> str:
        tier = score_tier(s)
        if tier == "C":
            return f"\\textbf{{{s}}} (C)"
        return f"{s} ({tier})"

    rows = []
    for row in data:
        label = row["label"].replace("_", "\\_")
        cat = row["category"].replace("_", "\\_")
        cells = [label, cat] + [fmt_cell(row[p]) for p in ("baseline", "relaxed", "safety", "tight")]
        rows.append(" & ".join(cells) + r" \\")

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        r"\caption{Empirical constraint sensitivity: same benchmark findings scored under four hardware"
        r" profiles. \textbf{Bold}=CRITICAL ($\geq$85); C/H/M/L = tier label.}",
        r"\label{tab:constraint_sensitivity}",
        r"\begin{tabular}{llrrrr}",
        r"\toprule",
        r"Finding & Category & Baseline & Relaxed & Safety & Tight \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return _save_tex("\n".join(lines), filename)
