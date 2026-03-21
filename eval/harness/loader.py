"""Load scored items and ground truth for evaluation experiments."""

from __future__ import annotations

import json
import pickle
from pathlib import Path

from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem
from constraintguard.parsers.constraint_loader import load_constraints
from constraintguard.parsers.sarif_parser import parse_sarif
from constraintguard.scoring.engine import score_all

EVAL_ROOT = Path(__file__).parent.parent
SARIF_PATH = EVAL_ROOT / "data" / "sarif"
CONFIGS_PATH = EVAL_ROOT / "data" / "configs"
GT_PATH = EVAL_ROOT / "data" / "ground_truth"
CACHE_PATH = EVAL_ROOT / "outputs" / "raw"

PROJECTS = ["freertos", "zephyr", "espfc"]


def load_scored_items(
    project: str,
    use_cache: bool = True,
) -> tuple[list[RiskItem], list[RiskItem], HardwareSpec]:
    """Return (baseline_items, deterministic_items, spec).

    Baseline: null HardwareSpec — zero rules fire, ordered by base_score only.
    Deterministic: full constraint-aware scoring.
    """
    cache_file = CACHE_PATH / f"{project}_scored.pkl"
    if use_cache and cache_file.exists():
        with open(cache_file, "rb") as f:
            return pickle.load(f)

    sarif_file = SARIF_PATH / project / "findings.sarif"
    if not sarif_file.exists():
        raise FileNotFoundError(
            f"SARIF not found for {project}: {sarif_file}\n"
            f"Run sarif_acquisition/{project}/run_scan.sh to generate it."
        )

    config_file = CONFIGS_PATH / f"{project}.yml"
    vulns = parse_sarif(sarif_file)
    spec, _ = load_constraints(config_file, linker_script_path=None)

    # Baseline: no constraints applied — category-only ordering
    null_spec = HardwareSpec()
    baseline = score_all(vulns, null_spec)

    # Deterministic: full constraint-aware scoring
    deterministic = score_all(vulns, spec)

    result = (baseline, deterministic, spec)
    CACHE_PATH.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "wb") as f:
        pickle.dump(result, f)

    return result


def load_vulnerabilities(project: str):
    """Load raw Vulnerability list from SARIF (no scoring)."""
    sarif_file = SARIF_PATH / project / "findings.sarif"
    if not sarif_file.exists():
        raise FileNotFoundError(f"SARIF not found for {project}: {sarif_file}")
    return parse_sarif(sarif_file)


def load_spec(project: str) -> HardwareSpec:
    """Load the HardwareSpec for a project."""
    config_file = CONFIGS_PATH / f"{project}.yml"
    spec, _ = load_constraints(config_file, linker_script_path=None)
    return spec


def load_ground_truth(project: str) -> dict[str, bool]:
    """Load ground truth labels for a project.

    Returns a dict mapping vuln_key → is_critical (bool).
    """
    gt_file = GT_PATH / f"{project}_labels.json"
    if not gt_file.exists():
        return {}
    data = json.loads(gt_file.read_text())
    return {k: v["is_critical"] for k, v in data.get("labels", {}).items()}


def load_benchmark_items(
    configs: list[str] | None = None,
) -> dict[str, list]:
    """Load benchmark SARIF and score it under multiple hardware profiles.

    configs: list of config names (without .yml), e.g. ["benchmark_tight", "benchmark_relaxed"].
             Defaults to ["baseline", "benchmark_relaxed", "benchmark_safety", "benchmark_tight"].

    Returns: {config_name: list[RiskItem]}
    The "baseline" key uses a null HardwareSpec (no rules fire).
    """
    if configs is None:
        configs = ["baseline", "benchmark_relaxed", "benchmark_safety", "benchmark_tight"]

    sarif_file = SARIF_PATH / "benchmark" / "findings.sarif"
    if not sarif_file.exists():
        raise FileNotFoundError(
            f"Benchmark SARIF not found: {sarif_file}\n"
            "Copy examples/vuln_demo/findings.sarif to eval/data/sarif/benchmark/findings.sarif"
        )

    vulns = parse_sarif(sarif_file)
    results: dict[str, list] = {}

    for config_name in configs:
        if config_name == "baseline":
            spec = HardwareSpec()
        else:
            config_file = CONFIGS_PATH / f"{config_name}.yml"
            spec, _ = load_constraints(config_file, linker_script_path=None)
        results[config_name] = score_all(vulns, spec)

    return results


def invalidate_cache(project: str | None = None) -> None:
    """Remove cached scored items to force re-scoring."""
    if project:
        cache_file = CACHE_PATH / f"{project}_scored.pkl"
        cache_file.unlink(missing_ok=True)
    else:
        for p in PROJECTS:
            (CACHE_PATH / f"{p}_scored.pkl").unlink(missing_ok=True)
