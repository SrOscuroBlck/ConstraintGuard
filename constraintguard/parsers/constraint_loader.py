from pathlib import Path

from constraintguard.models import ConstraintProvenance, HardwareSpec
from constraintguard.parsers.linker_script_parser import parse_linker_script
from constraintguard.parsers.yaml_parser import parse_yaml_constraints

_HARDWARE_SPEC_FIELDS: list[str] = [
    "platform",
    "ram_size_bytes",
    "flash_size_bytes",
    "stack_size_bytes",
    "heap_size_bytes",
    "max_interrupt_latency_us",
    "critical_functions",
    "safety_level",
]


def load_constraints(
    config_path: Path | None,
    linker_script_path: Path | None,
) -> tuple[HardwareSpec, ConstraintProvenance]:
    if config_path is None and linker_script_path is None:
        raise ValueError(
            "At least one constraint source is required: --config or a linker script path."
        )

    merged_spec_fields: dict[str, object] = {}
    merged_origins: dict[str, object] = {}

    if linker_script_path is not None:
        ld_spec, ld_provenance = parse_linker_script(linker_script_path)
        _apply_spec_fields(ld_spec, ld_provenance, merged_spec_fields, merged_origins)

    if config_path is not None:
        yaml_spec, yaml_provenance = parse_yaml_constraints(config_path)
        _apply_spec_fields(yaml_spec, yaml_provenance, merged_spec_fields, merged_origins)

    return (
        HardwareSpec(**merged_spec_fields),
        ConstraintProvenance(field_origins=merged_origins),
    )


def _apply_spec_fields(
    spec: HardwareSpec,
    provenance: ConstraintProvenance,
    target_fields: dict[str, object],
    target_origins: dict[str, object],
) -> None:
    for field in _HARDWARE_SPEC_FIELDS:
        value = getattr(spec, field)
        empty_list = isinstance(value, list) and len(value) == 0
        if value is not None and not empty_list:
            target_fields[field] = value
            if field in provenance.field_origins:
                target_origins[field] = provenance.field_origins[field]
