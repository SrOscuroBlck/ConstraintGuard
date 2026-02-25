import json
import logging
from pathlib import Path
from urllib.parse import unquote, urlparse

from constraintguard.models.vulnerability import Vulnerability
from constraintguard.parsers.sarif_rule_map import (
    VulnerabilityCategory,
    resolve_category,
    resolve_cwe,
)

logger = logging.getLogger(__name__)

_CWE_TAG_PREFIX = "CWE-"


def _normalize_file_path(raw_path: str) -> str:
    if raw_path.startswith("file:///"):
        parsed = urlparse(raw_path)
        return unquote(parsed.path)
    return unquote(raw_path)


def parse_sarif(sarif_path: Path) -> list[Vulnerability]:
    raw = _load_sarif(sarif_path)
    runs = raw.get("runs", [])

    vulnerabilities: list[Vulnerability] = []
    for run in runs:
        if not isinstance(run, dict):
            logger.warning("Skipping non-dict run entry in %s", sarif_path)
            continue
        tool_name = _extract_tool_name(run)
        rule_cwe_registry = _build_rule_cwe_registry(run)
        run_vulns = _parse_run(run, tool_name, rule_cwe_registry, sarif_path)
        vulnerabilities.extend(run_vulns)

    return vulnerabilities


def _load_sarif(sarif_path: Path) -> dict:
    if not sarif_path.exists():
        raise FileNotFoundError(f"SARIF file not found: {sarif_path}")
    with sarif_path.open("r", encoding="utf-8") as fh:
        content = json.load(fh)
    if not isinstance(content, dict):
        raise ValueError(f"SARIF file must contain a JSON object at the top level: {sarif_path}")
    return content


def _extract_tool_name(run: dict) -> str:
    try:
        return run["tool"]["driver"]["name"]
    except (KeyError, TypeError):
        return "unknown"


def _build_rule_cwe_registry(run: dict) -> dict[str, str]:
    registry: dict[str, str] = {}
    try:
        rules = run["tool"]["driver"].get("rules", [])
    except (KeyError, TypeError):
        return registry

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if not rule_id:
            continue
        cwe = _extract_cwe_from_rule_definition(rule)
        if cwe:
            registry[rule_id] = cwe

    return registry


def _extract_cwe_from_rule_definition(rule: dict) -> str | None:
    cwe_from_tags = _extract_cwe_from_tags(rule.get("properties", {}).get("tags", []))
    if cwe_from_tags:
        return cwe_from_tags

    for relationship in rule.get("relationships", []):
        try:
            component_name = relationship["target"]["toolComponent"]["name"]
            if component_name.upper() == "CWE":
                cwe_id = relationship["target"]["id"]
                return f"CWE-{cwe_id}"
        except (KeyError, TypeError):
            continue

    return None


def _parse_run(
    run: dict,
    tool_name: str,
    rule_cwe_registry: dict[str, str],
    sarif_path: Path,
) -> list[Vulnerability]:
    results = run.get("results", [])
    vulnerabilities: list[Vulnerability] = []

    for index, result in enumerate(results):
        try:
            vuln = _parse_result(result, tool_name, rule_cwe_registry)
            if vuln is not None:
                vulnerabilities.append(vuln)
        except Exception as exc:
            logger.warning(
                "Skipping malformed SARIF result at index %d in %s: %s",
                index,
                sarif_path,
                exc,
            )

    return vulnerabilities


def _parse_result(
    result: dict,
    tool_name: str,
    rule_cwe_registry: dict[str, str],
) -> Vulnerability | None:
    if not isinstance(result, dict):
        return None

    rule_id = _extract_rule_id(result)
    if not rule_id:
        return None

    message = _extract_message(result)
    if not message:
        return None

    locations = result.get("locations", [])
    path, start_line, start_col = _extract_physical_location(locations)
    function_name = _extract_function_name(locations)

    category = resolve_category(rule_id)
    category = _refine_category_from_message(category, rule_id, message)
    cwe = _extract_cwe_from_result(result, rule_id, rule_cwe_registry, category)

    return Vulnerability(
        tool=tool_name,
        rule_id=rule_id,
        message=message,
        path=path,
        start_line=start_line,
        start_col=start_col,
        function=function_name,
        cwe=cwe,
        category=category,
    )


_USE_AFTER_FREE_PATTERNS = ("use of memory after", "used after", "use-after-free", "after it is freed")
_DOUBLE_FREE_PATTERNS = ("double free", "freed twice", "attempt to free released")


def _refine_category_from_message(
    category: VulnerabilityCategory,
    rule_id: str,
    message: str,
) -> VulnerabilityCategory:
    if rule_id not in ("unix.Malloc", "cplusplus.NewDelete", "cplusplus.NewDeleteLeaks"):
        return category

    lower_message = message.lower()
    for pattern in _USE_AFTER_FREE_PATTERNS:
        if pattern in lower_message:
            return VulnerabilityCategory.USE_AFTER_FREE
    for pattern in _DOUBLE_FREE_PATTERNS:
        if pattern in lower_message:
            return VulnerabilityCategory.USE_AFTER_FREE
    return category


def _extract_rule_id(result: dict) -> str | None:
    rule_id = result.get("ruleId")
    if rule_id:
        return rule_id
    try:
        return result["rule"]["id"]
    except (KeyError, TypeError):
        return None


def _extract_message(result: dict) -> str | None:
    message_obj = result.get("message")
    if not isinstance(message_obj, dict):
        return None
    return message_obj.get("text") or message_obj.get("markdown")


def _extract_physical_location(
    locations: list,
) -> tuple[str, int | None, int | None]:
    if not locations or not isinstance(locations[0], dict):
        return "unknown", None, None

    physical = locations[0].get("physicalLocation", {})
    if not isinstance(physical, dict):
        return "unknown", None, None

    artifact = physical.get("artifactLocation", {})
    raw_path = artifact.get("uri", "unknown") if isinstance(artifact, dict) else "unknown"
    path = _normalize_file_path(raw_path)

    region = physical.get("region", {})
    if not isinstance(region, dict):
        return path, None, None

    start_line = region.get("startLine")
    start_col = region.get("startColumn")

    return (
        path,
        int(start_line) if start_line is not None else None,
        int(start_col) if start_col is not None else None,
    )


def _extract_function_name(locations: list) -> str | None:
    if not locations or not isinstance(locations[0], dict):
        return None

    logical_locations = locations[0].get("logicalLocations", [])
    if not isinstance(logical_locations, list):
        return None

    for entry in logical_locations:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind", "")
        if kind in ("function", "method") or not kind:
            name = entry.get("name") or entry.get("fullyQualifiedName")
            if name:
                return name

    return None


def _extract_cwe_from_result(
    result: dict,
    rule_id: str,
    rule_cwe_registry: dict[str, str],
    category: VulnerabilityCategory,
) -> str | None:
    cwe_from_props = _extract_cwe_from_tags(
        result.get("properties", {}).get("tags", [])
    )
    if cwe_from_props:
        return cwe_from_props

    if rule_id in rule_cwe_registry:
        return rule_cwe_registry[rule_id]

    return resolve_cwe(rule_id, category)


def _extract_cwe_from_tags(tags: list | None) -> str | None:
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, str) and tag.upper().startswith(_CWE_TAG_PREFIX.upper()):
            return tag.upper()
    return None
