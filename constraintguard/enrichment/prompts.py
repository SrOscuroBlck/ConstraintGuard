import json

from constraintguard.evidence.models import CodeSnippet, EvidenceBundle
from constraintguard.models.enums import VulnerabilityCategory
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
    "type, and evidence citation from the source code.\n\n"
    "REQUIRED JSON SCHEMA for your response:\n"
    '{"tags": ["string"], "explanation": "string", '
    '"fix_suggestions": [{"line": int, "original_code": "string", '
    '"proposed_code": "string", "rationale": "string"}], '
    '"new_discoveries": [{"type": "string", "severity_rationale": "string", '
    '"file_path": "string", "start_line": int, "end_line": int, '
    '"evidence_citation": "string"}], '
    '"suggested_category": "string or null", '
    '"suggested_base_score": "int (0-65) or null", '
    '"category_reasoning": "string or null"}\n'
    "Use EXACTLY these field names. Do not rename or add fields. "
    "The suggested_category, suggested_base_score, and category_reasoning fields "
    "are only populated when the finding category is 'unknown' — otherwise set them to null."
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


DISCOVERY_SYSTEM_PROMPT = (
    "You are an expert embedded systems security auditor specializing in C/C++ code "
    "running on resource-constrained devices (ARM Cortex-M, RISC-V, etc.).\n\n"
    "TASK: Scan the provided source file for security vulnerabilities and bugs that a "
    "static analyzer (Clang Static Analyzer) would NOT detect.\n\n"
    "The static analyzer already covers these categories — DO NOT report them:\n"
    "  buffer_overflow, null_deref, leak, use_after_free, integer_overflow,\n"
    "  format_string, divide_by_zero, uninitialized, deadlock.\n\n"
    "FOCUS on issues the static analyzer CANNOT detect:\n"
    "  - race_condition: shared state accessed from multiple threads/ISRs without synchronization\n"
    "  - toctou: time-of-check to time-of-use races\n"
    "  - incorrect_volatile: shared variables between ISR and thread context missing volatile\n"
    "  - blocking_call_in_isr: blocking API called inside interrupt handler\n"
    "  - priority_inversion: lock ordering or ceiling protocol violations\n"
    "  - unprotected_shared_state: global/static variables modified without critical section\n"
    "  - stack_vla: variable-length arrays on stack in constrained environments\n"
    "  - timing_side_channel: data-dependent timing leakage\n"
    "  - logic_error: incorrect algorithm, wrong condition, swappable parameters\n\n"
    "RULES:\n"
    "1. Only report issues NOT already listed in the 'Known findings' section.\n"
    "2. Cite exact line numbers from the numbered source listing.\n"
    "3. Distinguish facts (what the code does) from inferences (what could happen).\n"
    "4. Return ONLY valid JSON matching this schema exactly:\n"
    '{"discoveries": [{"type": "string", "severity_rationale": "string", '
    '"file_path": "string", "start_line": int, "end_line": int, '
    '"evidence_citation": "string"}]}\n'
    "5. If no new issues are found, return: {\"discoveries\": []}\n"
    "6. Do not add any text outside the JSON object."
)

_DISCOVERY_USER_TEMPLATE = (
    "## File Under Audit\n\n"
    "**Path:** {file_path}\n\n"
    "## Hardware Constraints\n\n"
    "{constraint_context}\n\n"
    "## Known Findings (already reported by static analyzer — DO NOT re-report)\n\n"
    "{known_findings}\n\n"
    "## Source Code (line-numbered)\n\n"
    "```c\n"
    "{numbered_source}\n"
    "```\n\n"
    "Audit the code above. Return JSON with any NEW vulnerabilities not listed above."
)

_MAX_DISCOVERY_LINES = 3000


def build_discovery_prompt(
    file_path: str,
    file_content: str,
    existing_findings: list,
    spec: HardwareSpec,
) -> str:
    """Build a user prompt for file-level vulnerability discovery.

    existing_findings: list of RiskItem objects with findings already in this file.
    """
    lines = file_content.splitlines()
    if len(lines) > _MAX_DISCOVERY_LINES:
        lines = lines[:_MAX_DISCOVERY_LINES]
        truncation_note = f"\n[... truncated at {_MAX_DISCOVERY_LINES} lines ...]"
    else:
        truncation_note = ""

    numbered_source = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
    numbered_source += truncation_note

    if existing_findings:
        known_lines = []
        for item in existing_findings:
            v = item.vulnerability
            known_lines.append(
                f"- Line {v.start_line}: {v.category.value} ({v.rule_id}) — {v.message[:120]}"
            )
        known_findings = "\n".join(known_lines)
    else:
        known_findings = "(none — this file has no static analyzer findings)"

    constraint_context = _format_constraint_context(spec)

    return _DISCOVERY_USER_TEMPLATE.format(
        file_path=file_path,
        constraint_context=constraint_context,
        known_findings=known_findings,
        numbered_source=numbered_source,
    )


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
    base_prompt = _USER_PROMPT_TEMPLATE.format(
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

    if vuln.category == VulnerabilityCategory.UNKNOWN:
        base_prompt += (
            "\n\n## Category Classification Request\n\n"
            "This finding is currently classified as **unknown**. Based on the code "
            "evidence and finding details above, please also provide:\n\n"
            "- `suggested_category`: One of the predefined categories "
            "(buffer_overflow, null_deref, leak, use_after_free, integer_overflow, "
            "format_string, divide_by_zero, uninitialized, deadlock) OR a novel "
            "category name if none fit (e.g. race_condition, toctou, logic_error). "
            'Use "unknown" only if you truly cannot determine the category.\n'
            "- `suggested_base_score`: Integer 0-65 reflecting the inherent severity "
            "of this vulnerability type. Reference scores: use_after_free=65, "
            "buffer_overflow=60, format_string=55, null_deref=50, integer_overflow=50, "
            "leak=45, deadlock=45, divide_by_zero=40, uninitialized=40. "
            "Memory corruption is generally higher (55-65), logic errors lower (30-45). "
            "Leave room for constraint-aware rules to add 0-35 points.\n"
            "- `category_reasoning`: Brief explanation of why you chose this "
            "category and base score.\n\n"
            "Include these three fields in your JSON response."
        )

    return base_prompt
