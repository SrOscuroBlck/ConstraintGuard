import re
from typing import Callable

from constraintguard.models.enums import VulnerabilityCategory
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RuleFiring
from constraintguard.models.vulnerability import Vulnerability

RuleFunction = Callable[[Vulnerability, HardwareSpec], RuleFiring | None]

_MEMORY_SAFETY_CATEGORIES = {
    VulnerabilityCategory.BUFFER_OVERFLOW,
    VulnerabilityCategory.USE_AFTER_FREE,
    VulnerabilityCategory.NULL_DEREF,
}
_OVERFLOW_UAF_CATEGORIES = {
    VulnerabilityCategory.BUFFER_OVERFLOW,
    VulnerabilityCategory.USE_AFTER_FREE,
}
_LEAK_UAF_CATEGORIES = {
    VulnerabilityCategory.LEAK,
    VulnerabilityCategory.USE_AFTER_FREE,
}
_HIGH_IMPACT_CATEGORIES = {
    VulnerabilityCategory.BUFFER_OVERFLOW,
    VulnerabilityCategory.USE_AFTER_FREE,
    VulnerabilityCategory.NULL_DEREF,
    VulnerabilityCategory.FORMAT_STRING,
}
_ASIL_HIGH_LEVELS = {"asil-b", "asil-c", "asil-d"}
_FUNCTIONAL_SAFETY_PREFIXES = ("iso26262", "iec62443", "do-178", "iec61508", "misra")

_ISR_PREFIX_PATTERN = re.compile(r"^(isr_|ISR_)", re.ASCII)
_ISR_SUFFIX_PATTERN = re.compile(r"(_isr|_ISR|_irq|_IRQ|_IRQHandler)$", re.ASCII)
_ISR_CMSIS_PATTERN = re.compile(
    r"(SysTick_Handler|PendSV_Handler|HardFault_Handler|NMI_Handler|MemManage_Handler"
    r"|BusFault_Handler|UsageFault_Handler|DebugMon_Handler)",
    re.ASCII,
)


def _is_isr_function(name: str | None) -> bool:
    if not name:
        return False
    if _ISR_PREFIX_PATTERN.match(name):
        return True
    if _ISR_SUFFIX_PATTERN.search(name):
        return True
    if "interrupt" in name.lower():
        return True
    if _ISR_CMSIS_PATTERN.search(name):
        return True
    return False


def _is_high_asil(safety_level: str | None) -> bool:
    if not safety_level:
        return False
    normalized = safety_level.lower()
    return any(asil in normalized for asil in _ASIL_HIGH_LEVELS)


def _is_functional_safety(safety_level: str | None) -> bool:
    if not safety_level:
        return False
    normalized = safety_level.lower()
    return any(normalized.startswith(prefix) or prefix in normalized for prefix in _FUNCTIONAL_SAFETY_PREFIXES)


def _rule_mem_stack_tight(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.stack_size_bytes is None:
        return None
    if spec.stack_size_bytes > 4096:
        return None
    if vuln.category not in _OVERFLOW_UAF_CATEGORIES:
        return None
    return RuleFiring(
        rule_id="R-MEM-STACK-TIGHT",
        delta=20,
        rationale=(
            f"Stack is tightly constrained at {spec.stack_size_bytes}B (≤4096B); "
            f"{vuln.category.value} can overwrite stack frames and corrupt return addresses."
        ),
        constraints_used=["stack_size_bytes"],
    )


def _rule_mem_heap_tight(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.heap_size_bytes is None:
        return None
    if spec.heap_size_bytes > 8192:
        return None
    if vuln.category != VulnerabilityCategory.LEAK:
        return None
    return RuleFiring(
        rule_id="R-MEM-HEAP-TIGHT",
        delta=15,
        rationale=(
            f"Heap budget is only {spec.heap_size_bytes}B (≤8192B); "
            "repeated memory leaks rapidly exhaust the allocation pool and trigger undefined behaviour."
        ),
        constraints_used=["heap_size_bytes"],
    )


def _rule_mem_ram_tight(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.ram_size_bytes is None:
        return None
    if spec.ram_size_bytes > 65536:
        return None
    if vuln.category not in _MEMORY_SAFETY_CATEGORIES:
        return None
    return RuleFiring(
        rule_id="R-MEM-RAM-TIGHT",
        delta=15,
        rationale=(
            f"Total RAM is limited to {spec.ram_size_bytes}B (≤64KB); "
            f"{vuln.category.value} corrupts a significant fraction of addressable memory on this device."
        ),
        constraints_used=["ram_size_bytes"],
    )


def _rule_mem_no_dynamic(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.heap_size_bytes is not None:
        return None
    if vuln.category not in _LEAK_UAF_CATEGORIES:
        return None
    return RuleFiring(
        rule_id="R-MEM-NO-DYNAMIC",
        delta=10,
        rationale=(
            "No heap budget is declared in the constraint profile; "
            f"a {vuln.category.value} defect suggests untracked or unexpected dynamic allocation on this target."
        ),
        constraints_used=["heap_size_bytes"],
    )


def _rule_isr_func_name(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if not _is_isr_function(vuln.function):
        return None
    return RuleFiring(
        rule_id="R-ISR-FUNC-NAME",
        delta=25,
        rationale=(
            f"Function '{vuln.function}' matches interrupt service routine naming conventions; "
            "a fault in an ISR cannot be caught by normal exception handling and may lock the device."
        ),
        constraints_used=["function"],
    )


def _rule_isr_latency_overflow(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.max_interrupt_latency_us is None:
        return None
    if spec.max_interrupt_latency_us > 100:
        return None
    if vuln.category not in _MEMORY_SAFETY_CATEGORIES:
        return None
    return RuleFiring(
        rule_id="R-ISR-LATENCY-OVERFLOW",
        delta=15,
        rationale=(
            f"Maximum interrupt latency budget is {spec.max_interrupt_latency_us}µs (≤100µs); "
            f"a {vuln.category.value} in an interrupt-sensitive code path can cause a missed real-time deadline."
        ),
        constraints_used=["max_interrupt_latency_us"],
    )


def _rule_isr_deadlock(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if vuln.category != VulnerabilityCategory.DEADLOCK:
        return None
    if not _is_isr_function(vuln.function):
        return None
    function_label = vuln.function or "unknown ISR"
    return RuleFiring(
        rule_id="R-ISR-DEADLOCK",
        delta=30,
        rationale=(
            f"Deadlock detected in interrupt service routine '{function_label}'; "
            "interrupt starvation caused by a deadlock in an ISR requires a hardware reset to recover."
        ),
        constraints_used=["function"],
    )


def _rule_crit_func(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if not spec.critical_functions:
        return None
    if not vuln.function:
        return None
    if vuln.function not in spec.critical_functions:
        return None
    return RuleFiring(
        rule_id="R-CRIT-FUNC",
        delta=25,
        rationale=(
            f"Function '{vuln.function}' is designated safety-critical in the constraint profile; "
            "any defect in this function directly impacts controlled system operation."
        ),
        constraints_used=["critical_functions"],
    )


def _rule_safety_asil_strict(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if not _is_high_asil(spec.safety_level):
        return None
    if vuln.category not in _HIGH_IMPACT_CATEGORIES:
        return None
    return RuleFiring(
        rule_id="R-SAFETY-ASIL-STRICT",
        delta=15,
        rationale=(
            f"Safety integrity level '{spec.safety_level}' mandates deterministic memory-safe behaviour; "
            f"{vuln.category.value} directly violates ISO 26262 ASIL freedom-from-interference requirements."
        ),
        constraints_used=["safety_level"],
    )


def _rule_safety_functional(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if not _is_functional_safety(spec.safety_level):
        return None
    return RuleFiring(
        rule_id="R-SAFETY-FUNCTIONAL",
        delta=5,
        rationale=(
            f"Functional safety standard '{spec.safety_level}' is declared for this target; "
            "all findings are escalated to reflect stricter acceptance criteria."
        ),
        constraints_used=["safety_level"],
    )


def _rule_time_ultra_tight(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.max_interrupt_latency_us is None:
        return None
    if spec.max_interrupt_latency_us > 50:
        return None
    return RuleFiring(
        rule_id="R-TIME-ULTRA-TIGHT",
        delta=10,
        rationale=(
            f"Interrupt latency budget is extremely tight at {spec.max_interrupt_latency_us}µs (≤50µs); "
            "findings across any execution path are escalated due to near-zero timing slack."
        ),
        constraints_used=["max_interrupt_latency_us"],
    )


def _rule_latency_deadlock(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if spec.max_interrupt_latency_us is None:
        return None
    if vuln.category != VulnerabilityCategory.DEADLOCK:
        return None
    return RuleFiring(
        rule_id="R-LATENCY-DEADLOCK",
        delta=20,
        rationale=(
            f"Interrupt latency budget of {spec.max_interrupt_latency_us}µs is declared; "
            "a deadlock anywhere in the system can prevent interrupt servicing and violate this budget."
        ),
        constraints_used=["max_interrupt_latency_us"],
    )


def _rule_safety_int_overflow(vuln: Vulnerability, spec: HardwareSpec) -> RuleFiring | None:
    if not _is_functional_safety(spec.safety_level):
        return None
    if vuln.category != VulnerabilityCategory.INTEGER_OVERFLOW:
        return None
    return RuleFiring(
        rule_id="R-SAFETY-INT-OVF",
        delta=12,
        rationale=(
            f"Safety standard '{spec.safety_level}' is active; "
            "integer overflow can silently produce incorrect sensor or actuator values, "
            "violating numerical safety invariants."
        ),
        constraints_used=["safety_level"],
    )


RULE_REGISTRY: list[RuleFunction] = [
    _rule_mem_stack_tight,
    _rule_mem_heap_tight,
    _rule_mem_ram_tight,
    _rule_mem_no_dynamic,
    _rule_isr_func_name,
    _rule_isr_latency_overflow,
    _rule_isr_deadlock,
    _rule_crit_func,
    _rule_safety_asil_strict,
    _rule_safety_functional,
    _rule_time_ultra_tight,
    _rule_latency_deadlock,
    _rule_safety_int_overflow,
]
