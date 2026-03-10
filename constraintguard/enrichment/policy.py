import subprocess
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from constraintguard.models.risk_report import RiskItem


class SelectionMode(Enum):
    TOPK = "topk"
    CHANGED_FILES = "changed_files"
    ALL = "all"


class SelectionPolicy(BaseModel):
    mode: SelectionMode
    top_k: int = 10
    changed_files: list[str] | None = None


class SelectionResult(BaseModel):
    selected_items: list[RiskItem]
    total_items: int
    selection_mode: SelectionMode
    reason: str


def select_for_enrichment(items: list[RiskItem], policy: SelectionPolicy) -> SelectionResult:
    total = len(items)

    if policy.mode == SelectionMode.TOPK:
        selected = items[: policy.top_k]
    elif policy.mode == SelectionMode.CHANGED_FILES:
        changed = set(policy.changed_files or [])
        filtered = [item for item in items if item.vulnerability.path in changed]
        selected = filtered[: policy.top_k]
    elif policy.mode == SelectionMode.ALL:
        print(f"Warning: --llm-all selected. All {total} findings will be sent to LLM.")
        selected = list(items)
    else:
        selected = []

    if not selected:
        reason = "No findings selected for LLM analysis — skipping enrichment"
    else:
        reason = (
            f"Selected {len(selected)} of {total} findings for LLM analysis "
            f"(mode: {policy.mode.value}, top_k: {policy.top_k})"
        )

    return SelectionResult(
        selected_items=selected,
        total_items=total,
        selection_mode=policy.mode,
        reason=reason,
    )


def estimate_llm_cost(
    selected_count: int,
    avg_context_tokens: int = 2000,
    price_per_1k_input: float = 0.00015,
    price_per_1k_output: float = 0.0006,
) -> str:
    input_tokens = selected_count * (avg_context_tokens + 500)
    output_tokens = selected_count * 800
    cost = (input_tokens / 1000) * price_per_1k_input + (output_tokens / 1000) * price_per_1k_output
    return (
        f"Estimated LLM cost: ~${cost:.2f} for {selected_count} findings "
        f"({input_tokens} input + {output_tokens} output tokens)"
    )


def get_changed_files_from_git(repo_path: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return [line for line in result.stdout.strip().splitlines() if line]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
