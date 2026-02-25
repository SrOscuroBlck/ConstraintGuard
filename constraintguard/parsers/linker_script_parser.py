import re
from pathlib import Path

from constraintguard.models import (
    ConstraintProvenance,
    ConstraintSourceType,
    FieldProvenance,
    HardwareSpec,
)
from constraintguard.parsers.normalization import parse_size_to_bytes

_MEMORY_BLOCK_PATTERN = re.compile(
    r"MEMORY\s*\{([^}]*)\}",
    re.IGNORECASE | re.DOTALL,
)

_MEMORY_REGION_PATTERN = re.compile(
    r"(\w+)\s*\([^)]*\)\s*:\s*ORIGIN\s*=\s*[^,]+,\s*LENGTH\s*=\s*(\S+)",
    re.IGNORECASE,
)

_STACK_SYMBOL_PATTERN = re.compile(
    r"(?:PROVIDE\s*\(\s*)?_+stack_size\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
    re.IGNORECASE,
)

_HEAP_SYMBOL_PATTERN = re.compile(
    r"(?:PROVIDE\s*\(\s*)?_+heap_size\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
    re.IGNORECASE,
)

_RAM_NAME_PATTERN = re.compile(r"ram|sram|dtcm|ccm", re.IGNORECASE)
_FLASH_NAME_PATTERN = re.compile(r"flash|rom|nor", re.IGNORECASE)


def parse_linker_script(ld_path: Path) -> tuple[HardwareSpec, ConstraintProvenance]:
    if not ld_path.exists():
        raise FileNotFoundError(f"Linker script not found: {ld_path}")

    source_content = _read_and_strip_comments(ld_path)
    source_path_str = str(ld_path)
    spec_fields: dict[str, object] = {}
    field_origins: dict[str, FieldProvenance] = {}

    ram_bytes, flash_bytes = _extract_memory_regions(source_content, ld_path)

    if ram_bytes is not None:
        spec_fields["ram_size_bytes"] = ram_bytes
        field_origins["ram_size_bytes"] = FieldProvenance(
            source_type=ConstraintSourceType.LINKER_SCRIPT,
            source_path=source_path_str,
            extraction_note="Extracted from MEMORY block RAM regions",
        )

    if flash_bytes is not None:
        spec_fields["flash_size_bytes"] = flash_bytes
        field_origins["flash_size_bytes"] = FieldProvenance(
            source_type=ConstraintSourceType.LINKER_SCRIPT,
            source_path=source_path_str,
            extraction_note="Extracted from MEMORY block FLASH regions",
        )

    stack_bytes = _extract_symbol_value(_STACK_SYMBOL_PATTERN, source_content)
    if stack_bytes is not None:
        spec_fields["stack_size_bytes"] = stack_bytes
        field_origins["stack_size_bytes"] = FieldProvenance(
            source_type=ConstraintSourceType.LINKER_SCRIPT,
            source_path=source_path_str,
            extraction_note="Extracted from _stack_size symbol",
        )

    heap_bytes = _extract_symbol_value(_HEAP_SYMBOL_PATTERN, source_content)
    if heap_bytes is not None:
        spec_fields["heap_size_bytes"] = heap_bytes
        field_origins["heap_size_bytes"] = FieldProvenance(
            source_type=ConstraintSourceType.LINKER_SCRIPT,
            source_path=source_path_str,
            extraction_note="Extracted from _heap_size symbol",
        )

    return HardwareSpec(**spec_fields), ConstraintProvenance(field_origins=field_origins)


def _read_and_strip_comments(ld_path: Path) -> str:
    raw = ld_path.read_text(encoding="utf-8")
    without_block_comments = re.sub(r"/\*.*?\*/", " ", raw, flags=re.DOTALL)
    without_line_comments = re.sub(r"//[^\n]*", " ", without_block_comments)
    return without_line_comments


def _extract_memory_regions(
    source: str, ld_path: Path
) -> tuple[int | None, int | None]:
    memory_block_match = _MEMORY_BLOCK_PATTERN.search(source)
    if not memory_block_match:
        return None, None

    block_content = memory_block_match.group(1)
    ram_total = 0
    flash_total = 0
    found_ram = False
    found_flash = False

    for region_match in _MEMORY_REGION_PATTERN.finditer(block_content):
        region_name = region_match.group(1)
        length_str = region_match.group(2).rstrip(",;")

        try:
            region_bytes = parse_size_to_bytes(length_str)
        except ValueError:
            continue

        if _RAM_NAME_PATTERN.search(region_name):
            ram_total += region_bytes
            found_ram = True
        elif _FLASH_NAME_PATTERN.search(region_name):
            flash_total += region_bytes
            found_flash = True

    return (ram_total if found_ram else None), (flash_total if found_flash else None)


def _extract_symbol_value(pattern: re.Pattern[str], source: str) -> int | None:
    match = pattern.search(source)
    if not match:
        return None
    raw_value = match.group(1)
    try:
        return parse_size_to_bytes(raw_value)
    except ValueError:
        return None
