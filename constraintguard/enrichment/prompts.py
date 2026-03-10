import json

from constraintguard.evidence.models import CodeSnippet, EvidenceBundle
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem

SYSTEM_PROMPT = (
    "You are an embedded systems security expert specializing in C/C++ code "
    "running on resource-constrained devices.\n\n"
    "RULES:\n"
    "1. Cite specific line numbers and code snippets in ALL outputs.\n"
    "2. Clearly distinguish facts (what the code does) from inferences "
    "(what could happen at runtime).\n"
    "3. Return structured JSON matching the provided schema exactly.\n"
    "4. The expert system has already detected these categories: "
    "buffer_overflow, null_deref, leak, use_after_free, integer_overflow, "
    "format_string, divide_by_zero, uninitialized, deadlock. "
    "Do NOT re-report issues already covered by the expert assessment below.\n"
    "5. Focus on issues BEYOND the expert system: race conditions, TOCTOU bugs, "
    "timing side-channels, blocking calls inside ISRs, incorrect volatile usage, "
    "priority inversion, stack-allocated VLAs in constrained environments, "
    "unprotected shared state, and other embedded antipatterns.\n"
    "6. For fix suggestions, provide the exact original line and a corrected version "
    "with a rationale that references the hardware constraints.\n"
    "7. For new discoveries, specify the exact file path, line range, vulnerability "
    "type, and evidence citation from the source code."
)

_SNIPPET_TEMPLATE = "--- {label} ({path} L{start}-L{end}) ---\n{content}\n"

_USER_PROMPT_TEMPLATE = (
    "## Finding Under Analysis\n\n"
    "- **File:** {file_path}\n"
    "- **Line:** {line}\n"
    "- **Function:** {function}\n"
    "- **Category:** {category}\n"
    "- **Rule ID:** {rule_id}\n"
    "- **Message:** {message}\n\n"
    "## Expert Assessment\n\n"
    "- **Base Score:** {base_score}\n"
    "- **Final Score:** {final_score}\n"
    "- **Tier:** {tier}\n"
    "- **Rule Firings:** {rule_firings}\n"
    "- **Expert Explanation:** {explanation}\n\n"
    "## Hardware Constraints\n\n"
    "{constraint_context}\n\n"
    "## Source Code Evidence\n\n"
    "{code_evidence}\n\n"
    "Analyze the code above. Return JSON matching the provided schema."
)


def _format_snippet(snippet: CodeSnippet | None, label: str) -> str:
    if snippet is None:
        return ""
    return _SNIPPET_TEMPLATE.format(
        label=label,
        path=snippet.file_path,
        start=snippet.start_line,
        end=snippet.end_line,
        content=snippet.content,
    )


def _format_constraint_context(spec: HardwareSpec) -> str:
    fields = {
        "platform": spec.platform,
        "ram_size_bytes": spec.ram_size_bytes,
        "flash_size_bytes": spec.flash_size_bytes,
        "stack_size_bytes": spec.stack_size_bytes,
        "heap_size_bytes": spec.heap_size_bytes,
        "max_interrupt_latency_us": spec.max_interrupt_latency_us,
        "safety_level": spec.safety_level,
        "critical_functions": spec.critical_functions if spec.critical_functions else None,
    }
    lines = []
    for key, value in fields.items():
        if value is not None:
            lines.append(f"- **{key}:** {value}")
    return "\n".join(lines) if lines else "No hardware constraints provided."


def _format_rule_firings(item: RiskItem) -> str:
    if not item.rule_firings:
        return "None"
    parts = []
    for rf in item.rule_firings:
        parts.append(f"{rf.rule_id} ({rf.delta:+d}): {rf.rationale}")
    return "; ".join(parts)


def build_user_prompt(
    item: RiskItem,
    bundle: EvidenceBundle,
    spec: HardwareSpec,
) -> str:
    code_parts: list[str] = []
    code_parts.append(_format_snippet(bundle.function_body, "Function Body"))
    code_parts.append(_format_snippet(bundle.surrounding_context, "Surrounding Context"))
    for i, cs in enumerate(bundle.call_sites):
        code_parts.append(_format_snippet(cs, f"Call Site {i + 1}"))
    for i, ds in enumerate(bundle.data_structures):
        code_parts.append(_format_snippet(ds, f"Data Structure {i + 1}"))
    code_evidence = "\n".join(part for part in code_parts if part)
    if not code_evidence:
        code_evidence = "No source code evidence available."

    vuln = item.vulnerability
    return _USER_PROMPT_TEMPLATE.format(
        file_path=vuln.path,
        line=vuln.start_line or "unknown",
        function=vuln.function or "unknown",
        category=vuln.category.value,
        rule_id=vuln.rule_id,
        message=vuln.message,
        base_score=item.base_score,
        final_score=item.final_score,
        tier=item.tier.value,
        rule_firings=_format_rule_firings(item),
        explanation=item.explanation,
        constraint_context=_format_constraint_context(spec),
        code_evidence=code_evidence,
    )
