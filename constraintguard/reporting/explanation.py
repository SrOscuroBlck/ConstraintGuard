from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RuleFiring
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.reporting.formatting import format_bytes, format_us

_CATEGORY_PLAIN_NAMES: dict[str, str] = {
    "buffer_overflow": "buffer overflow",
    "null_deref": "null pointer dereference",
    "leak": "memory leak",
    "use_after_free": "use-after-free",
    "integer_overflow": "integer overflow",
    "format_string": "format string vulnerability",
    "divide_by_zero": "division by zero",
    "uninitialized": "uninitialized memory read",
    "deadlock": "potential deadlock",
    "unknown": "static analysis finding",
}

_CATEGORY_EMBEDDED_CONSEQUENCE: dict[str, str] = {
    "buffer_overflow": (
        "corrupts adjacent memory, potentially overwriting stack frames, return addresses, "
        "or global state — on a resource-constrained embedded target, recovery may require a full device reset"
    ),
    "null_deref": (
        "triggers a processor fault (e.g., ARM HardFault) that halts execution immediately "
        "— on bare-metal or RTOS targets there is typically no OS-level exception handler to recover from this"
    ),
    "leak": (
        "permanently consumes heap or pool memory on each call path that reaches it "
        "— on embedded targets with kilobytes of RAM, repeated leaks exhaust available memory rapidly"
    ),
    "use_after_free": (
        "accesses freed memory that may have been reallocated, introducing non-deterministic behaviour "
        "— on embedded targets without full memory protection, this can silently corrupt live data structures"
    ),
    "integer_overflow": (
        "silently wraps arithmetic results, producing incorrect values that propagate through "
        "control, sensor, or actuator calculations without any runtime indication"
    ),
    "format_string": (
        "allows arbitrary memory reads and writes via format specifiers if user input reaches the format argument "
        "— on embedded targets, this can compromise the entire firmware image"
    ),
    "divide_by_zero": (
        "triggers a processor divide-by-zero fault that halts execution "
        "unless an explicit trap handler is installed and tested"
    ),
    "uninitialized": (
        "reads indeterminate stack or register values, producing device-specific non-deterministic behaviour "
        "that is difficult to reproduce and may differ between debug and release builds"
    ),
    "deadlock": (
        "permanently blocks one or more tasks from running "
        "— on an RTOS or bare-metal scheduler, this starves all dependent tasks and interrupts indefinitely"
    ),
    "unknown": (
        "produces undefined behaviour whose exact impact depends on the execution context and runtime state"
    ),
}


def _location_phrase(vuln: Vulnerability) -> str:
    if vuln.function and vuln.start_line:
        return f"in function '{vuln.function}' ({vuln.path}:{vuln.start_line})"
    if vuln.function:
        return f"in function '{vuln.function}' ({vuln.path})"
    if vuln.start_line:
        return f"at {vuln.path}:{vuln.start_line}"
    return f"in {vuln.path}"


def _profile_descriptor(spec: HardwareSpec) -> str:
    parts: list[str] = []
    if spec.platform:
        parts.append(spec.platform)
    if spec.safety_level:
        parts.append(spec.safety_level)
    if parts:
        return f"your {' / '.join(parts)} target"
    return "this embedded target"


def _build_no_constraint_context_sentence(spec: HardwareSpec) -> str:
    mem_parts: list[str] = []
    if spec.ram_size_bytes is not None:
        mem_parts.append(f"{format_bytes(spec.ram_size_bytes)} RAM")
    if spec.stack_size_bytes is not None:
        mem_parts.append(f"{format_bytes(spec.stack_size_bytes)} stack")
    if spec.heap_size_bytes is not None:
        mem_parts.append(f"{format_bytes(spec.heap_size_bytes)} heap")
    if spec.max_interrupt_latency_us is not None:
        mem_parts.append(f"{format_us(spec.max_interrupt_latency_us)} interrupt latency budget")
    if mem_parts:
        profile = _profile_descriptor(spec)
        return f"The constraint profile for {profile} declares {', '.join(mem_parts)}."
    return ""


def _combine_rationales(firings: list[RuleFiring]) -> str:
    rationales = [f.rationale.rstrip(".") for f in firings]
    if len(rationales) == 1:
        return rationales[0] + "."
    if len(rationales) == 2:
        return f"{rationales[0]}; and {rationales[1]}."
    body = "; ".join(rationales[:-1])
    return f"{body}; and {rationales[-1]}."


def build_explanation(
    vuln: Vulnerability,
    spec: HardwareSpec,
    base_score: int,
    final_score: int,
    firings: list[RuleFiring],
) -> str:
    plain_name = _CATEGORY_PLAIN_NAMES.get(vuln.category, vuln.category)
    location = _location_phrase(vuln)
    profile = _profile_descriptor(spec)
    consequence = _CATEGORY_EMBEDDED_CONSEQUENCE.get(
        vuln.category, _CATEGORY_EMBEDDED_CONSEQUENCE["unknown"]
    )

    opening = f"A {plain_name} was detected {location}."

    if not firings:
        ctx = _build_no_constraint_context_sentence(spec)
        ctx_part = f" {ctx}" if ctx else ""
        return (
            f"{opening}{ctx_part} "
            f"On {profile}, this {consequence}. "
            f"No constraint-specific escalations apply to this finding (base score: {base_score})."
        )

    rationale_sentence = _combine_rationales(firings)
    return (
        f"{opening} "
        f"On {profile}, this {consequence}. "
        f"This finding is escalated because: {rationale_sentence}"
    )
