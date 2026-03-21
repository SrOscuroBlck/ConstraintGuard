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
    ax.set_title("Agentic AI Enrichment Quality")
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
    ax.set_yticklabels([row["label"] for row in data], fontsize=8)
    ax.set_xlabel("Risk Score (0–100)")
    ax.set_title("Empirical Constraint Sensitivity:\nSame Findings, Different Hardware Profiles")
    ax.set_xlim(0, 110)

    # Tier threshold lines
    for score, tier in [(85, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM")]:
        ax.axvline(score, color="grey", linestyle="--", linewidth=0.8, alpha=0.6)
        ax.text(score + 0.5, n - 0.3, tier, fontsize=7, color="grey", va="top")

    # Profile legend
    import matplotlib.patches as mpatches
    legend_handles = [
        mpatches.Patch(color=COLORS[i], label=pl)
        for i, pl in enumerate(profile_labels)
    ]
    ax.legend(handles=legend_handles, loc="lower right", fontsize=8)

    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
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
