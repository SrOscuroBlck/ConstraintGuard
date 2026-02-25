from pathlib import Path

import yaml

from constraintguard.models import (
    ConstraintProvenance,
    ConstraintSourceType,
    FieldProvenance,
    HardwareSpec,
)
from constraintguard.parsers.normalization import parse_size_to_bytes, parse_time_to_us

_YAML_SIZE_FIELDS: dict[str, str] = {
    "ram_size": "ram_size_bytes",
    "flash_size": "flash_size_bytes",
    "stack_size": "stack_size_bytes",
    "heap_size": "heap_size_bytes",
}

_YAML_TIME_FIELDS: dict[str, str] = {
    "max_interrupt_latency": "max_interrupt_latency_us",
}

_YAML_SCALAR_FIELDS: list[str] = ["platform", "safety_level"]

_YAML_LIST_FIELDS: list[str] = ["critical_functions"]


def parse_yaml_constraints(config_path: Path) -> tuple[HardwareSpec, ConstraintProvenance]:
    if not config_path.exists():
        raise FileNotFoundError(f"Constraint config not found: {config_path}")

    raw = _load_yaml_file(config_path)
    source_path_str = str(config_path)
    field_origins: dict[str, FieldProvenance] = {}
    spec_fields: dict[str, object] = {}

    for yaml_key, spec_key in _YAML_SIZE_FIELDS.items():
        raw_value = raw.get(yaml_key)
        if raw_value is not None:
            spec_fields[spec_key] = _parse_size_field(yaml_key, raw_value)
            field_origins[spec_key] = FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path=source_path_str,
                extraction_note=f"Parsed from '{yaml_key}' field",
            )

    for yaml_key, spec_key in _YAML_TIME_FIELDS.items():
        raw_value = raw.get(yaml_key)
        if raw_value is not None:
            spec_fields[spec_key] = _parse_time_field(yaml_key, raw_value)
            field_origins[spec_key] = FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path=source_path_str,
                extraction_note=f"Parsed from '{yaml_key}' field",
            )

    for field in _YAML_SCALAR_FIELDS:
        raw_value = raw.get(field)
        if raw_value is not None:
            spec_fields[field] = str(raw_value)
            field_origins[field] = FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path=source_path_str,
            )

    for field in _YAML_LIST_FIELDS:
        raw_value = raw.get(field)
        if raw_value is not None:
            spec_fields[field] = _parse_string_list(field, raw_value)
            field_origins[field] = FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path=source_path_str,
            )

    return HardwareSpec(**spec_fields), ConstraintProvenance(field_origins=field_origins)


def _load_yaml_file(config_path: Path) -> dict:
    with config_path.open("r", encoding="utf-8") as fh:
        content = yaml.safe_load(fh)
    if not isinstance(content, dict):
        raise ValueError(
            f"Constraint config must be a YAML mapping at the top level: {config_path}"
        )
    return content


def _parse_size_field(field_name: str, raw_value: object) -> int:
    try:
        return parse_size_to_bytes(raw_value)  # type: ignore[arg-type]
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid value for '{field_name}': {raw_value!r}. {exc}"
        ) from exc


def _parse_time_field(field_name: str, raw_value: object) -> int:
    try:
        return parse_time_to_us(raw_value)  # type: ignore[arg-type]
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid value for '{field_name}': {raw_value!r}. {exc}"
        ) from exc


def _parse_string_list(field_name: str, raw_value: object) -> list[str]:
    if not isinstance(raw_value, list):
        raise ValueError(
            f"Field '{field_name}' must be a YAML list of strings, got: {type(raw_value).__name__}"
        )
    for item in raw_value:
        if not isinstance(item, str):
            raise ValueError(
                f"All entries in '{field_name}' must be strings, found: {item!r}"
            )
    return raw_value
