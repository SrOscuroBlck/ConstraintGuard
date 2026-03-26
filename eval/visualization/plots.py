"""Publication-quality figure generators for ConstraintGuard evaluation.

All figures are saved as PDF at 300 DPI with serif fonts and colorblind-safe palette.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

FIGURES_DIR = Path(__file__).parent.parent / "outputs" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Publication style
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 300,
})

PROJECTS_DISPLAY = {"freertos": "FreeRTOS", "zephyr": "Zephyr", "espfc": "esp-fc"}
COLORS = sns.color_palette("colorblind", 8)


def _save(fig: plt.Figure, name: str) -> Path:
    path = FIGURES_DIR / f"{name}.pdf"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {path}")
    return path


def plot_precision_at10(
    data: dict[str, dict[str, float]],
    filename: str = "exp1_precision_at10",
) -> Path:
    """Bar chart: Expert agreement (%) per project for deterministic ranking.

    data: {project: {"expert_agreement": float, ...}}
    """
    projects = list(data.keys())
    labels = [PROJECTS_DISPLAY.get(p, p) for p in projects]
    vals = [data[p].get("expert_agreement", 0) * 100 for p in projects]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(labels, vals, color=COLORS[0], zorder=3)
    for bar, v in zip(bars, vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.5,
            f"{v:.1f}%",
            ha="center", va="bottom", fontsize=9,
        )

    ax.set_xlabel("Project")
    ax.set_ylabel("Expert Agreement (%)")
    ax.set_title("Constraint-Aware Ranking vs. Expert Judgment")
    ax.set_ylim(0, 105)
    ax.yaxis.grid(True, linestyle="--", alpha=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_demotion_rate(
    data: dict[str, float],
    filename: str = "exp2_demotion_rate",
) -> Path:
    """Bar chart: Alert demotion rate (%) per project."""
    projects = list(data.keys())
    labels = [PROJECTS_DISPLAY.get(p, p) for p in projects]
    vals = [data[p] * 100 for p in projects]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(labels, vals, color=COLORS[0], zorder=3)
    for bar, v in zip(bars, vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.5,
            f"{v:.1f}%",
            ha="center", va="bottom", fontsize=9,
        )
    ax.set_xlabel("Project")
    ax.set_ylabel("Demotion Rate (%)")
    ax.set_title("Low-Actionability Alert Demotion")
    ax.set_ylim(0, max(vals) * 1.2 + 5 if vals else 50)
    ax.yaxis.grid(True, linestyle="--", alpha=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_llm_quality(
    data: dict[str, dict[str, float]],
    filename: str = "exp3_llm_quality",
) -> Path:
    """Line chart: LLM enrichment quality metrics across projects.

    data: {project: {"usefulness": 0-5, "evidence_correctness": 0-100, "tag_accuracy": 0-100}}
    """
    projects = list(data.keys())
    labels = [PROJECTS_DISPLAY.get(p, p) for p in projects]

    # Normalize usefulness to 0-100 for same-axis display
    usefulness = [data[p].get("usefulness", 0) / 5 * 100 for p in projects]
    evidence = [data[p].get("evidence_correctness", 0) for p in projects]
    tag_acc = [data[p].get("tag_accuracy", 0) for p in projects]

    fig, ax = plt.subplots(figsize=(6, 4))
    x = range(len(projects))
    ax.plot(labels, usefulness, "o-", color=COLORS[0], label="Usefulness (1–5, scaled)", linewidth=2)
    ax.plot(labels, evidence, "s-", color=COLORS[1], label="Evidence Correctness (%)", linewidth=2)
    ax.plot(labels, tag_acc, "^-", color=COLORS[2], label="Tag Accuracy (%)", linewidth=2)
    ax.set_xlabel("Project")
    ax.set_ylabel("Score / Percentage")
    ax.set_title("LLM Enrichment Quality")
    ax.set_ylim(0, 110)
    ax.legend()
    ax.yaxis.grid(True, linestyle="--", alpha=0.7)
    fig.tight_layout()
    return _save(fig, filename)


def plot_cwe_heatmap(
    matrix: list[list[float]],
    cwe_labels: list[str],
    constraint_labels: list[str],
    filename: str = "exp4_cwe_heatmap",
) -> Path:
    """Heatmap: CWE × Constraint severity matrix."""
    import numpy as np

    data = np.array(matrix)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        data,
        ax=ax,
        xticklabels=constraint_labels,
        yticklabels=cwe_labels,
        annot=True,
        fmt=".2f",
        cmap="viridis",
        vmin=0.0,
        vmax=1.0,
        linewidths=0.5,
        linecolor="white",
        cbar_kws={"label": "Normalized Severity (0=benign, 1=critical)"},
    )
    ax.set_xlabel("Hardware Constraints")
    ax.set_ylabel("Vulnerability Types (CWE)")
    ax.set_title("CWE–Constraint Interaction Heatmap")
    plt.xticks(rotation=20, ha="right")
    plt.yticks(rotation=0)
    fig.tight_layout()
    return _save(fig, filename)


def plot_cicd_overhead(
    data: dict[str, dict[str, float]],
    filename: str = "exp5_cicd_overhead",
) -> Path:
    """Bar chart: CI/CD pipeline stage timing (mean seconds).

    data: {"full": {stage: seconds}, "cached": {stage: seconds}}
    """
    stages = ["Static Analysis", "Constraint Extraction", "Deterministic Scoring", "Reporting"]
    stage_keys = ["parse_sarif", "load_constraints", "score_all", "write_reports"]

    fig, ax = plt.subplots(figsize=(6, 4))
    x = np.arange(len(stages))
    width = 0.35

    # Convert to milliseconds for readability
    full_vals = [data.get("full", {}).get(k, 0) * 1000 for k in stage_keys]
    cached_vals = [data.get("cached", {}).get(k, 0) * 1000 for k in stage_keys]

    ax.bar(x - width / 2, full_vals, width, label="Full (no cache)", color=COLORS[0], zorder=3)
    ax.bar(x + width / 2, cached_vals, width, label="Cached", color=COLORS[2], zorder=3)

    ax.set_xlabel("Pipeline Stage")
    ax.set_ylabel("Runtime (ms)")
    ax.set_title("CI/CD Pipeline Overhead")
    ax.set_xticks(x)
    ax.set_xticklabels(stages, rotation=15, ha="right")
    ax.legend()
    ax.yaxis.grid(True, linestyle="--", alpha=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_precision_at_k_curve(
    data: dict[str, dict[int, float]],
    filename: str = "exp6_precision_at_k_curve",
) -> Path:
    """Line chart: Precision@K curves for 3 configurations.

    data: {"baseline": {k: precision}, "deterministic": {k: precision}, "full_system": {k: precision}}
    """
    k_values = sorted(set(k for cfg in data.values() for k in cfg))
    configs = ["baseline", "deterministic", "full_system"]
    labels = ["Baseline", "Deterministic", "Full System"]
    markers = ["o", "s", "^"]

    fig, ax = plt.subplots(figsize=(6, 4))
    for cfg, label, marker, color in zip(configs, labels, markers, COLORS):
        vals = [data.get(cfg, {}).get(k, 0) * 100 for k in k_values]
        ax.plot(k_values, vals, f"{marker}-", label=label, color=color, linewidth=2, markersize=6)

    ax.set_xlabel("Top-K Findings")
    ax.set_ylabel("Precision (%)")
    ax.set_title("Precision@K Ranking Quality")
    ax.set_xticks(k_values)
    ax.set_ylim(0, 105)
    ax.legend()
    ax.yaxis.grid(True, linestyle="--", alpha=0.7)
    fig.tight_layout()
    return _save(fig, filename)


def plot_constraint_sensitivity(
    data: list[dict],
    filename: str = "exp8_constraint_sensitivity",
) -> Path:
    """Grouped horizontal bar chart: per-finding scores under 4 hardware profiles.

    data: list of {
        "label": str,           # short finding label (function:category)
        "baseline": int,
        "relaxed": int,
        "safety": int,
        "tight": int,
    }
    Findings ordered by tight score descending.
    """
    profiles = ["baseline", "relaxed", "safety", "tight"]
    profile_labels = ["Baseline", "Relaxed", "Safety (SIL2)", "Tight (ASIL-B, 50µs)"]
    tier_colors = {
        "CRITICAL": "#d62728",
        "HIGH": "#ff7f0e",
        "MEDIUM": "#1f77b4",
        "LOW": "#2ca02c",
    }

    def score_to_tier(s: int) -> str:
        if s >= 85:
            return "CRITICAL"
        if s >= 70:
            return "HIGH"
        if s >= 40:
            return "MEDIUM"
        return "LOW"

    n = len(data)
    y = np.arange(n)
    height = 0.18
    offsets = [-1.5, -0.5, 0.5, 1.5]

    fig, ax = plt.subplots(figsize=(8, max(4, n * 0.6 + 1)))

    for idx, (profile, plabel, offset) in enumerate(zip(profiles, profile_labels, offsets)):
        scores = [row[profile] for row in data]
        colors = [tier_colors[score_to_tier(s)] for s in scores]
        bars = ax.barh(
            y + offset * height, scores, height,
            color=colors, zorder=3, alpha=0.85,
            label=plabel,
        )

    ax.set_yticks(y)
    ax.set_yticklabels([row["label"] for row in data], fontsize=11)
    ax.set_xlabel("Risk Score (0–100)", fontsize=12)
    ax.set_title("Empirical Constraint Sensitivity:\nSame Findings, Different Hardware Profiles", fontsize=12)
    ax.set_xlim(0, 110)
    ax.tick_params(axis="x", labelsize=11)

    # Tier threshold lines
    for score, tier in [(85, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM")]:
        ax.axvline(score, color="grey", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.text(score + 0.5, n - 0.3, tier, fontsize=11, color="grey", va="top")

    # Profile legend
    import matplotlib.patches as mpatches
    legend_handles = [
        mpatches.Patch(color=COLORS[i], label=pl)
        for i, pl in enumerate(profile_labels)
    ]
    ax.legend(handles=legend_handles, loc="lower right", fontsize=11)

    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_reclassification_paired_bars(
    detail_rows: list[dict],
    project: str = "espfc",
    filename: str = "exp9_reclassification_paired_bars",
) -> Path:
    """Paired grouped bar chart: findings per severity tier, before vs. after LLM reclassification.

    Shows how many findings moved from MEDIUM to HIGH after the LLM assigned a
    concrete vulnerability category. One bar-pair per tier; annotated with counts
    and percentage elevated. Standard comparison format for systems research papers.
    """
    from collections import Counter

    rows = [r for r in detail_rows if r["project"] == project]
    if not rows:
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.text(0.5, 0.5, f"No data for {project}", ha="center", va="center",
                transform=ax.transAxes)
        return _save(fig, filename)

    TIERS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    TIER_COLORS = {
        "LOW":      "#2ca02c",
        "MEDIUM":   "#1f77b4",
        "HIGH":     "#ff7f0e",
        "CRITICAL": "#d62728",
    }

    before_counts = Counter(r["original_tier"] for r in rows)
    after_counts  = Counter(r["new_tier"]      for r in rows)

    # Only show tiers that appear in before or after
    active_tiers = [t for t in TIERS if before_counts[t] or after_counts[t]]

    x = np.arange(len(active_tiers))
    w = 0.35

    fig, ax = plt.subplots(figsize=(5.5, 4))

    bars_before = ax.bar(
        x - w / 2,
        [before_counts[t] for t in active_tiers],
        width=w,
        color="#aaaaaa",
        label="Before (unknown)",
        zorder=3,
    )
    bars_after = ax.bar(
        x + w / 2,
        [after_counts[t] for t in active_tiers],
        width=w,
        color=[TIER_COLORS[t] for t in active_tiers],
        label="After (LLM reclassified)",
        zorder=3,
    )

    # Count labels on top of each bar
    for bar in bars_before:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1.5,
                    str(int(h)), ha="center", va="bottom", fontsize=8.5, color="#444444")

    for bar, tier in zip(bars_after, active_tiers):
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1.5,
                    str(int(h)), ha="center", va="bottom", fontsize=8.5,
                    color=TIER_COLORS[tier], fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(active_tiers, fontsize=10)
    ax.set_xlabel("Severity Tier", fontsize=10)
    ax.set_ylabel("Number of Findings", fontsize=10)
    ax.set_title(
        f"LLM-Assisted Reclassification — esp-fc ($n={len(rows)}$)",
        fontsize=11,
    )
    ax.set_ylim(0, max(before_counts[t] for t in active_tiers) * 1.35 + 10)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=9, framealpha=0.9)
    fig.tight_layout()
    return _save(fig, filename)


def _plot_tier_distribution_before_after(
    detail_rows: list[dict],
    filename: str = "exp9_tier_distribution",
) -> Path:
    """Grouped stacked bar: tier distribution before vs after reclassification per project.

    Shows clearly how many findings moved tiers after LLM reclassification.
    detail_rows: list of dicts with project, original_tier, new_tier.
    """
    from collections import Counter, defaultdict

    TIERS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    TIER_COLORS = {
        "LOW":      "#2ca02c",
        "MEDIUM":   "#1f77b4",
        "HIGH":     "#ff7f0e",
        "CRITICAL": "#d62728",
    }

    projects = list(dict.fromkeys(r["project"] for r in detail_rows))
    before: dict[str, Counter] = defaultdict(Counter)
    after:  dict[str, Counter] = defaultdict(Counter)
    for r in detail_rows:
        before[r["project"]][r["original_tier"]] += 1
        after[r["project"]][r["new_tier"]] += 1

    n_projects = len(projects)
    x = np.arange(n_projects)
    width = 0.35
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for col_idx, (counts, offset, label_suffix) in enumerate([
        (before, -width / 2, "Before"),
        (after,   width / 2, "After"),
    ]):
        bottoms = np.zeros(n_projects)
        for tier in TIERS:
            vals = np.array([counts[p][tier] for p in projects], dtype=float)
            bars = ax.bar(
                x + offset, vals, width,
                bottom=bottoms,
                color=TIER_COLORS[tier],
                label=f"{tier} ({label_suffix})" if col_idx == 1 else None,
                zorder=3,
                alpha=0.9 if label_suffix == "After" else 0.45,
                edgecolor="white", linewidth=0.4,
            )
            # Annotate non-zero segments on the "After" bars
            if label_suffix == "After":
                for bar, v in zip(bars, vals):
                    if v > 0:
                        ax.text(
                            bar.get_x() + bar.get_width() / 2,
                            bar.get_y() + bar.get_height() / 2,
                            str(int(v)),
                            ha="center", va="center", fontsize=7, color="white",
                            fontweight="bold",
                        )
            bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels([PROJECTS_DISPLAY.get(p, p) for p in projects])
    ax.set_ylabel("Number of Findings")
    ax.set_title("Severity Tier Distribution of Unknown Findings\nBefore (faded) vs. After LLM Reclassification")

    # Build a clean legend: one entry per tier (After colours)
    import matplotlib.patches as mpatches
    legend_handles = [
        mpatches.Patch(color=TIER_COLORS[t], label=t) for t in TIERS if t != "CRITICAL"
    ]
    ax.legend(handles=legend_handles, loc="upper right", fontsize=8, title="Severity Tier")
    ax.yaxis.grid(True, linestyle="--", alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def _plot_category_assignment(
    detail_rows: list[dict],
    filename: str = "exp9_category_assignment",
) -> Path:
    """Horizontal stacked bar: LLM-assigned categories per project.

    Shows what semantic categories the LLM identified from unknown findings,
    coloured by predefined vs novel. This is the core contribution figure.
    detail_rows: list of dicts with project, suggested_category, category_type.
    """
    from collections import Counter, defaultdict

    projects = list(dict.fromkeys(r["project"] for r in detail_rows))

    # Collect categories and their types
    cat_type_map: dict[str, str] = {}
    cat_counts: dict[str, Counter] = defaultdict(Counter)  # project -> {cat: count}
    for r in detail_rows:
        cat = (r.get("suggested_category") or "unknown").lower().strip() or "unknown"
        cat_type_map[cat] = r.get("category_type", "unknown")
        cat_counts[r["project"]][cat] += 1

    # Order categories by total count descending
    total_by_cat: Counter = Counter()
    for p_counts in cat_counts.values():
        total_by_cat.update(p_counts)
    categories = [c for c, _ in total_by_cat.most_common()]

    type_colors = {
        "predefined": COLORS[0],
        "novel_llm":  COLORS[2],
        "unknown":    COLORS[7],
    }

    y = np.arange(len(projects))
    height = 0.6
    fig, ax = plt.subplots(figsize=(8, max(3, len(projects) * 1.2 + 1.5)))

    seen_labels: set[str] = set()
    for p_idx, project in enumerate(projects):
        left = 0.0
        for cat in categories:
            count = cat_counts[project][cat]
            if count == 0:
                continue
            cat_type = cat_type_map.get(cat, "unknown")
            color = type_colors.get(cat_type, COLORS[4])
            type_label = {
                "predefined": "Predefined category",
                "novel_llm":  "Novel category (LLM)",
                "unknown":    "Remained unknown",
            }.get(cat_type, cat_type)
            bar_label = type_label if type_label not in seen_labels else None
            ax.barh(
                y[p_idx], count, height,
                left=left, color=color, zorder=3, alpha=0.85,
                edgecolor="white", linewidth=0.4, label=bar_label,
            )
            seen_labels.add(type_label)
            # Label the segment with category name if wide enough
            if count >= max(total_by_cat.values()) * 0.05:
                ax.text(
                    left + count / 2, y[p_idx],
                    cat.replace("_", " "),
                    ha="center", va="center", fontsize=7.5, color="white",
                    fontweight="bold",
                )
            left += count

    ax.set_yticks(y)
    ax.set_yticklabels([PROJECTS_DISPLAY.get(p, p) for p in projects])
    ax.set_xlabel("Number of Findings")
    ax.set_title("LLM-Assigned Vulnerability Categories\nfor Previously-Unknown Findings")
    ax.legend(loc="lower right", fontsize=8)
    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def _plot_score_delta_by_project(
    detail_rows: list[dict],
    filename: str = "exp9_score_delta",
) -> Path:
    """Box plot of score deltas (new - original) per project.

    Demonstrates that reclassification is directional and meaningful,
    not random noise. Positive delta = finding elevated in priority.
    detail_rows: list of dicts with project, score_delta.
    """
    from collections import defaultdict

    projects = list(dict.fromkeys(r["project"] for r in detail_rows))
    deltas_by_project = defaultdict(list)
    for r in detail_rows:
        deltas_by_project[r["project"]].append(int(r["score_delta"]))

    fig, ax = plt.subplots(figsize=(6, 4))

    data = [deltas_by_project[p] for p in projects]
    labels = [PROJECTS_DISPLAY.get(p, p) for p in projects]

    bp = ax.boxplot(
        data, labels=labels, patch_artist=True,
        medianprops=dict(color="black", linewidth=1.5),
        flierprops=dict(marker=".", markersize=3, alpha=0.5),
        zorder=3,
    )
    for patch, color in zip(bp["boxes"], COLORS):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.axhline(0, color="grey", linestyle="--", linewidth=1.0, alpha=0.7)
    ax.set_ylabel("Score Delta (After − Before)")
    ax.set_xlabel("Project")
    ax.set_title("Score Change from LLM Reclassification\n(positive = finding elevated in priority)")
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_new_discovery_candidates(
    summary: dict[str, dict],
    filename: str = "exp10_new_discovery_candidates",
) -> Path:
    """Stacked bar chart: LLM new discovery classifications per project.

    summary: {project: {confirmed_new: int, duplicate: int, ...}}
    """
    projects = list(summary.keys())
    labels = [PROJECTS_DISPLAY.get(p, p) for p in projects]
    confirmed = [summary[p]["confirmed_new"] for p in projects]
    duplicate = [summary[p]["duplicate"] for p in projects]

    x = np.arange(len(projects))
    fig, ax = plt.subplots(figsize=(5, 4))
    bars_c = ax.bar(x, confirmed, label="Confirmed New", color=COLORS[2], zorder=3)
    bars_d = ax.bar(x, duplicate, bottom=confirmed, label="Duplicate", color=COLORS[7], zorder=3)

    # Annotate total count above each bar
    for i, (c, d) in enumerate(zip(confirmed, duplicate)):
        total = c + d
        if total > 0:
            ax.text(x[i], total + 0.1, str(total), ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_xlabel("Project")
    ax.set_ylabel("Candidates")
    ax.set_title("LLM New Discovery Candidates")
    ax.legend()
    ax.yaxis.grid(True, linestyle="--", alpha=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)


def plot_rule_ablation(
    data: dict[str, dict[str, float]],
    filename: str = "exp7_rule_ablation",
) -> Path:
    """Horizontal grouped bar chart: Rule family contribution % per project.

    data: {project: {family: contribution_pct}}
    """
    all_families = ["Memory", "ISR", "Safety", "RT-Hazard", "Lifetime"]

    # Drop projects and families where all contributions are zero
    active_projects = [p for p in data if any(data[p].get(f, 0) > 0 for f in all_families)]
    active_families = [f for f in all_families if any(data[p].get(f, 0) > 0 for p in active_projects)]

    y = np.arange(len(active_families))
    height = 0.3

    fig, ax = plt.subplots(figsize=(6, max(3, len(active_families) * 0.9)))
    for i, (project, color) in enumerate(zip(active_projects, COLORS)):
        label = PROJECTS_DISPLAY.get(project, project)
        vals = [data[project].get(f, 0) for f in active_families]
        offset = (i - len(active_projects) / 2 + 0.5) * height
        ax.barh(y + offset, vals, height, label=label, color=color, zorder=3)

    ax.set_yticks(y)
    ax.set_yticklabels(active_families)
    ax.set_xlabel("Contribution to Score Adjustment (%)")
    ax.set_title("Rule Family Contribution to Score Adjustment (%)")
    ax.legend(loc="lower right")
    ax.xaxis.grid(True, linestyle="--", alpha=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, filename)
