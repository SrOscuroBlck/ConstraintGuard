from constraintguard.models.hardware_spec import ConstraintProvenance, HardwareSpec
from constraintguard.reporting.formatting import format_bytes, format_us


def build_constraints_summary_lines(
    spec: HardwareSpec,
    provenance: ConstraintProvenance | None = None,
) -> list[str]:
    lines: list[str] = []

    header_parts: list[str] = []
    if spec.platform:
        header_parts.append(spec.platform)
    if spec.safety_level:
        header_parts.append(spec.safety_level)
    label = " — ".join(header_parts) if header_parts else "(no profile specified)"
    lines.append(f"Constraint Profile: {label}")

    mem_fields: list[tuple[str, str]] = []
    if spec.ram_size_bytes is not None:
        mem_fields.append(("RAM", format_bytes(spec.ram_size_bytes)))
    if spec.flash_size_bytes is not None:
        mem_fields.append(("Flash", format_bytes(spec.flash_size_bytes)))
    if spec.stack_size_bytes is not None:
        mem_fields.append(("Stack", format_bytes(spec.stack_size_bytes)))
    if spec.heap_size_bytes is not None:
        mem_fields.append(("Heap", format_bytes(spec.heap_size_bytes)))
    if mem_fields:
        lines.append("  " + "   ".join(f"{k}: {v}" for k, v in mem_fields))

    if spec.max_interrupt_latency_us is not None:
        lines.append(f"  Max IRQ Latency: {format_us(spec.max_interrupt_latency_us)}")

    if spec.critical_functions:
        lines.append(f"  Critical Functions: {', '.join(spec.critical_functions)}")

    if provenance and provenance.field_origins:
        sources = sorted({
            fp.source_path
            for fp in provenance.field_origins.values()
            if fp.source_path
        })
        if sources:
            lines.append(f"  Sources: {', '.join(sources)}")

    return lines


def build_constraints_summary_text(
    spec: HardwareSpec,
    provenance: ConstraintProvenance | None = None,
) -> str:
    return "\n".join(build_constraints_summary_lines(spec, provenance))
