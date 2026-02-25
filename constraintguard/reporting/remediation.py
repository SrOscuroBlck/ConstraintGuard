from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.reporting.formatting import format_bytes, format_us

_BASE_REMEDIATION_TEMPLATES: dict[str, str] = {
    "buffer_overflow": (
        "Replace unsafe memory operations with size-bounded equivalents "
        "(strncpy, snprintf, memcpy with explicit length). "
        "Validate all input lengths before copying into fixed-size buffers. "
        "On embedded targets, prefer statically-sized buffers with compile-time size assertions "
        "that enforce upper bounds."
    ),
    "null_deref": (
        "Add null-pointer guards before every pointer dereference. "
        "Use assertion macros in debug builds and explicit error-return paths in production. "
        "On bare-metal targets, a null dereference typically triggers a HardFault — "
        "ensure a fault handler is installed that logs diagnostics and performs a controlled reset."
    ),
    "leak": (
        "Ensure every allocation has a corresponding free on all exit paths, including error paths. "
        "On embedded targets, consider replacing dynamic allocation with a static memory pool "
        "or arena allocator, which eliminates fragmentation and removes leak risk entirely. "
        "MISRA C Rule 21.3 prohibits dynamic memory allocation in safety-critical code."
    ),
    "use_after_free": (
        "Set pointers to NULL immediately after freeing. "
        "Audit all pointer copies and lifetime boundaries; prefer single-owner allocation patterns. "
        "On embedded firmware, apply MPU read-after-free detection during testing "
        "if the hardware supports memory protection."
    ),
    "integer_overflow": (
        "Validate arithmetic operands against their type bounds before computation. "
        "Enable UBSan (undefined behaviour sanitizer) during testing. "
        "In safety-critical paths, use checked-arithmetic macros or a safe-integer library "
        "that returns an error on overflow instead of wrapping silently."
    ),
    "format_string": (
        "Replace any user-controlled format string argument with a fixed literal: "
        "use printf(\"%s\", user_input) rather than printf(user_input). "
        "On embedded targets, restrict or disable formatted I/O in production builds "
        "to reduce both attack surface and code size."
    ),
    "divide_by_zero": (
        "Guard all divisors with an explicit non-zero check before division. "
        "Return a safe default or error code when the divisor is zero. "
        "On embedded targets, install a divide-by-zero trap handler "
        "that logs a diagnostic and performs a controlled reset rather than leaving the system in an unknown state."
    ),
    "uninitialized": (
        "Initialize all variables at the point of declaration. "
        "Enable -Wuninitialized and -Wmaybe-uninitialized compiler warnings and treat them as errors. "
        "In safety-critical code, zero-initialize all buffers and structs explicitly "
        "and avoid relying on BSS initialization order across translation units."
    ),
    "deadlock": (
        "Enforce a consistent global lock-acquisition ordering across all execution paths. "
        "Avoid holding locks while calling functions that may acquire additional locks. "
        "On RTOS-based targets, use priority-ceiling or priority-inheritance mutexes "
        "to prevent priority inversion alongside deadlock risks."
    ),
    "unknown": (
        "Review the finding manually and apply the principle of least privilege. "
        "Consult the static analyzer's rule documentation for guidance specific to this rule. "
        "On embedded targets, treat any undefined behaviour conservatively — "
        "assume it can corrupt device state and require a hardware reset to recover."
    ),
}

_DEFAULT_REMEDIATION = _BASE_REMEDIATION_TEMPLATES["unknown"]


def _constraint_addendum(category: str, spec: HardwareSpec) -> str | None:
    if (
        category in ("buffer_overflow", "use_after_free")
        and spec.stack_size_bytes is not None
        and spec.stack_size_bytes <= 4096
    ):
        return (
            f"With only {format_bytes(spec.stack_size_bytes)} of stack on this target, "
            "overflows are more likely to silently corrupt adjacent frames; "
            "enable stack canaries (-fstack-protector-all) and MPU stack-guard regions if the hardware supports it."
        )

    if (
        category == "leak"
        and spec.heap_size_bytes is not None
        and spec.heap_size_bytes <= 8192
    ):
        return (
            f"With only {format_bytes(spec.heap_size_bytes)} of heap on this target, "
            "a single recurring leak path will exhaust memory quickly; "
            "replacing all dynamic allocation with a fixed-size pool allocator is strongly recommended."
        )

    if category == "null_deref" and spec.critical_functions:
        return (
            "In safety-critical functions, add both a pre-condition null check and a static assertion "
            "to document and enforce the non-null invariant at compile time."
        )

    if category == "integer_overflow" and spec.safety_level:
        return (
            f"Under {spec.safety_level}, apply a MISRA-compliant checked-arithmetic pattern "
            "for every arithmetic operation in the call path of this finding."
        )

    if category == "deadlock" and spec.max_interrupt_latency_us is not None:
        return (
            f"With a {format_us(spec.max_interrupt_latency_us)} interrupt latency budget, "
            "any deadlock that blocks interrupt servicing will immediately violate this budget; "
            "audit all lock acquisitions in interrupt-shared code paths."
        )

    if category == "uninitialized" and spec.safety_level:
        return (
            f"Under {spec.safety_level}, treat uninitialized reads as non-compliant by default and "
            "require zero-initialization of all local variables in safety-relevant translation units."
        )

    return None


def build_remediation(category: str, spec: HardwareSpec | None = None) -> str:
    base = _BASE_REMEDIATION_TEMPLATES.get(category, _DEFAULT_REMEDIATION)
    if spec is None:
        return base
    addendum = _constraint_addendum(category, spec)
    if addendum is None:
        return base
    return f"{base} {addendum}"
