import re
from pathlib import Path
from typing import Any

from constraintguard.evidence.models import CodeSnippet, EvidenceBundle, SnippetType
from constraintguard.models.enums import VulnerabilityCategory
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.vulnerability import Vulnerability

C_CPP_EXTENSIONS = {".c", ".cpp", ".h", ".hpp"}
HEADER_EXTENSIONS = {".h", ".hpp"}
STRUCT_CLASS_PATTERN = re.compile(
    r"\b(?:struct|class|typedef\s+struct)\s+(\w+)"
)


def _read_file_lines(file_path: Path) -> list[str] | None:
    try:
        return file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, PermissionError):
        return None


def _extract_surrounding_context(
    lines: list[str], vuln_line: int, context_lines: int, file_path: str
) -> CodeSnippet:
    start = max(0, vuln_line - 1 - context_lines)
    end = min(len(lines), vuln_line + context_lines)
    content = "\n".join(lines[start:end])
    return CodeSnippet(
        file_path=file_path,
        start_line=start + 1,
        end_line=end,
        content=content,
        snippet_type=SnippetType.SURROUNDING_CONTEXT,
    )


def _extract_function_body(
    lines: list[str], vuln_line: int, file_path: str
) -> CodeSnippet | None:
    if vuln_line < 1 or vuln_line > len(lines):
        return None

    brace_depth = 0
    opening_brace_line = None
    for i in range(vuln_line - 1, -1, -1):
        for ch in reversed(lines[i]):
            if ch == "}":
                brace_depth += 1
            elif ch == "{":
                if brace_depth == 0:
                    opening_brace_line = i
                    break
                brace_depth -= 1
        if opening_brace_line is not None:
            break

    if opening_brace_line is None:
        return None

    func_start = opening_brace_line
    for i in range(opening_brace_line, -1, -1):
        line_stripped = lines[i].strip()
        if not line_stripped or line_stripped == "{":
            continue
        if ")" in lines[i]:
            for j in range(i, -1, -1):
                if "(" in lines[j]:
                    func_start = j
                    break
            break
        func_start = i
        break

    brace_depth = 0
    brace_found = False
    func_end = None
    for i in range(opening_brace_line, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                brace_depth += 1
                brace_found = True
            elif ch == "}":
                brace_depth -= 1
        if brace_found and brace_depth == 0:
            func_end = i
            break

    if func_end is None:
        return None

    content = "\n".join(lines[func_start : func_end + 1])
    return CodeSnippet(
        file_path=file_path,
        start_line=func_start + 1,
        end_line=func_end + 1,
        content=content,
        snippet_type=SnippetType.FUNCTION_BODY,
    )


def _find_call_sites(
    function_name: str, source_dir: Path, exclude_file: str
) -> list[CodeSnippet]:
    call_pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    call_sites: list[CodeSnippet] = []

    try:
        source_files = [
            f
            for f in source_dir.rglob("*")
            if f.suffix in C_CPP_EXTENSIONS and f.is_file()
        ]
    except (OSError, PermissionError):
        return []

    for source_file in source_files:
        relative = str(source_file.relative_to(source_dir))
        if relative == exclude_file:
            continue

        lines = _read_file_lines(source_file)
        if lines is None:
            continue

        for line_idx, line in enumerate(lines):
            if call_pattern.search(line):
                ctx_start = max(0, line_idx - 3)
                ctx_end = min(len(lines), line_idx + 4)
                content = "\n".join(lines[ctx_start:ctx_end])
                call_sites.append(
                    CodeSnippet(
                        file_path=relative,
                        start_line=ctx_start + 1,
                        end_line=ctx_end,
                        content=content,
                        snippet_type=SnippetType.CALL_SITE,
                    )
                )
                if len(call_sites) >= 5:
                    return call_sites

    return call_sites


def _extract_data_structures(
    surrounding_content: str | None,
    function_content: str | None,
    source_dir: Path,
) -> list[CodeSnippet]:
    combined_text = ""
    if surrounding_content:
        combined_text += surrounding_content
    if function_content:
        combined_text += "\n" + function_content

    if not combined_text:
        return []

    type_names = set(STRUCT_CLASS_PATTERN.findall(combined_text))
    if not type_names:
        return []

    try:
        header_files = [
            f
            for f in source_dir.rglob("*")
            if f.suffix in HEADER_EXTENSIONS and f.is_file()
        ]
    except (OSError, PermissionError):
        return []

    data_structures: list[CodeSnippet] = []

    for header_file in header_files:
        lines = _read_file_lines(header_file)
        if lines is None:
            continue

        relative = str(header_file.relative_to(source_dir))

        for line_idx, line in enumerate(lines):
            for type_name in type_names:
                pattern = rf"\b(?:struct|class|typedef\s+struct)\s+{re.escape(type_name)}\b"
                if re.search(pattern, line):
                    def_start = line_idx
                    brace_depth = 0
                    brace_found = False
                    def_end = line_idx

                    for j in range(line_idx, min(line_idx + 100, len(lines))):
                        for ch in lines[j]:
                            if ch == "{":
                                brace_depth += 1
                                brace_found = True
                            elif ch == "}":
                                brace_depth -= 1
                        if brace_found and brace_depth == 0:
                            def_end = j
                            break

                    content = "\n".join(lines[def_start : def_end + 1])
                    data_structures.append(
                        CodeSnippet(
                            file_path=relative,
                            start_line=def_start + 1,
                            end_line=def_end + 1,
                            content=content,
                            snippet_type=SnippetType.DATA_STRUCTURE,
                        )
                    )

                    if len(data_structures) >= 3:
                        return data_structures

    return data_structures


def _build_constraint_context(
    category: VulnerabilityCategory, spec: HardwareSpec
) -> dict[str, Any]:
    context: dict[str, Any] = {}

    if category in (VulnerabilityCategory.BUFFER_OVERFLOW, VulnerabilityCategory.USE_AFTER_FREE):
        if spec.stack_size_bytes is not None:
            context["stack_size_bytes"] = spec.stack_size_bytes
        if spec.heap_size_bytes is not None:
            context["heap_size_bytes"] = spec.heap_size_bytes

    if category == VulnerabilityCategory.LEAK:
        if spec.heap_size_bytes is not None:
            context["heap_size_bytes"] = spec.heap_size_bytes
        if spec.ram_size_bytes is not None:
            context["ram_size_bytes"] = spec.ram_size_bytes

    if category == VulnerabilityCategory.DEADLOCK:
        if spec.max_interrupt_latency_us is not None:
            context["max_interrupt_latency_us"] = spec.max_interrupt_latency_us

    if spec.safety_level is not None:
        context["safety_level"] = spec.safety_level
    if spec.critical_functions:
        context["critical_functions"] = spec.critical_functions

    return context


def _compute_total_size(bundle: EvidenceBundle) -> int:
    total = 0
    if bundle.surrounding_context:
        total += len(bundle.surrounding_context.content.encode("utf-8"))
    if bundle.function_body:
        total += len(bundle.function_body.content.encode("utf-8"))
    for cs in bundle.call_sites:
        total += len(cs.content.encode("utf-8"))
    for ds in bundle.data_structures:
        total += len(ds.content.encode("utf-8"))
    return total


def extract_evidence(
    vuln: Vulnerability,
    source_dir: Path,
    spec: HardwareSpec,
    context_lines: int = 15,
) -> EvidenceBundle:
    bundle = EvidenceBundle(
        vulnerability_path=vuln.path,
        vulnerability_line=vuln.start_line,
    )

    if vuln.start_line is None:
        bundle.constraint_context = _build_constraint_context(vuln.category, spec)
        return bundle

    file_path = source_dir / vuln.path
    lines = _read_file_lines(file_path)

    if lines is None:
        bundle.constraint_context = _build_constraint_context(vuln.category, spec)
        return bundle

    bundle.surrounding_context = _extract_surrounding_context(
        lines, vuln.start_line, context_lines, vuln.path
    )

    bundle.function_body = _extract_function_body(lines, vuln.start_line, vuln.path)

    if vuln.function:
        bundle.call_sites = _find_call_sites(vuln.function, source_dir, vuln.path)

    surrounding_content = bundle.surrounding_context.content if bundle.surrounding_context else None
    function_content = bundle.function_body.content if bundle.function_body else None
    bundle.data_structures = _extract_data_structures(
        surrounding_content, function_content, source_dir
    )

    bundle.constraint_context = _build_constraint_context(vuln.category, spec)
    bundle.total_size_bytes = _compute_total_size(bundle)

    return bundle


def extract_evidence_batch(
    vulns: list[Vulnerability],
    source_dir: Path,
    spec: HardwareSpec,
    context_lines: int = 15,
) -> list[EvidenceBundle]:
    return [
        extract_evidence(vuln, source_dir, spec, context_lines) for vuln in vulns
    ]
