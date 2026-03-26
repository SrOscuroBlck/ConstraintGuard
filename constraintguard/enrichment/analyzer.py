import json
import logging

from pathlib import Path

from constraintguard.enrichment.prompts import (
    DISCOVERY_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_discovery_prompt,
    build_user_prompt,
)
from constraintguard.enrichment.schemas import FileDiscoverySchema, LLMAnalysisSchema
from constraintguard.evidence.models import EvidenceBundle
from constraintguard.llm.client import LLMClient
from constraintguard.llm.cost import CostTracker
from constraintguard.llm.models import LLMRequest
from constraintguard.models.enums import VulnerabilityCategory
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import (
    EnrichmentOutput,
    EvidenceCitation,
    FixSuggestion,
    RiskItem,
)
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.scoring.engine import score_vulnerability

logger = logging.getLogger(__name__)

_CATEGORY_MAP: dict[str, VulnerabilityCategory] = {
    "race_condition": VulnerabilityCategory.UNKNOWN,
    "toctou": VulnerabilityCategory.UNKNOWN,
    "timing_issue": VulnerabilityCategory.UNKNOWN,
    "blocking_call_in_isr": VulnerabilityCategory.DEADLOCK,
    "incorrect_volatile": VulnerabilityCategory.UNKNOWN,
    "priority_inversion": VulnerabilityCategory.DEADLOCK,
    "stack_vla": VulnerabilityCategory.BUFFER_OVERFLOW,
    "unprotected_shared_state": VulnerabilityCategory.UNKNOWN,
    "buffer_overflow": VulnerabilityCategory.BUFFER_OVERFLOW,
    "null_deref": VulnerabilityCategory.NULL_DEREF,
    "leak": VulnerabilityCategory.LEAK,
    "use_after_free": VulnerabilityCategory.USE_AFTER_FREE,
    "integer_overflow": VulnerabilityCategory.INTEGER_OVERFLOW,
    "format_string": VulnerabilityCategory.FORMAT_STRING,
    "divide_by_zero": VulnerabilityCategory.DIVIDE_BY_ZERO,
    "uninitialized": VulnerabilityCategory.UNINITIALIZED,
    "deadlock": VulnerabilityCategory.DEADLOCK,
}


def _parse_enrichment(
    parsed: dict,
    response_model: str,
    response_tokens: int,
    response_cost: float,
) -> EnrichmentOutput:
    analysis = LLMAnalysisSchema.model_validate(parsed)

    fix_suggestions = [
        FixSuggestion(
            line=fs.line,
            original_code=fs.original_code,
            proposed_code=fs.proposed_code,
            rationale=fs.rationale,
        )
        for fs in analysis.fix_suggestions
    ]

    evidence_citations = [
        EvidenceCitation(
            file_path=nd.file_path,
            start_line=nd.start_line,
            end_line=nd.end_line,
            snippet=nd.evidence_citation,
        )
        for nd in analysis.new_discoveries
    ]

    return EnrichmentOutput(
        tags=analysis.tags,
        llm_explanation=analysis.explanation if analysis.explanation else None,
        fix_suggestions=fix_suggestions,
        evidence_citations=evidence_citations,
        model_used=response_model,
        tokens_used=response_tokens,
        cost=response_cost,
        suggested_category=analysis.suggested_category,
        suggested_base_score=analysis.suggested_base_score,
        category_suggestion_reasoning=analysis.category_reasoning,
    )


def _enrich_single_item(
    item: RiskItem,
    bundle: EvidenceBundle,
    spec: HardwareSpec,
    client: LLMClient,
    tracker: CostTracker,
) -> list[dict]:
    user_prompt = build_user_prompt(item, bundle, spec)
    request = LLMRequest(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_schema=LLMAnalysisSchema,
    )

    response = client.analyze(request)
    tracker.record(response)

    if not response.parsed_content and not response.raw_content:
        logger.warning(
            "Empty LLM response for %s:%s — keeping expert-only data",
            item.vulnerability.path,
            item.vulnerability.start_line,
        )
        return []

    parsed = response.parsed_content
    if not parsed and response.raw_content:
        try:
            parsed = json.loads(response.raw_content)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Malformed LLM JSON for %s:%s — skipping enrichment",
                item.vulnerability.path,
                item.vulnerability.start_line,
            )
            return []

    if not parsed:
        return []

    total_tokens = response.input_tokens + response.output_tokens
    cost = float(
        tracker._records[-1].cost if tracker._records else 0
    )

    try:
        enrichment = _parse_enrichment(
            parsed, response.model, total_tokens, cost
        )
        item.enrichment = enrichment
    except Exception as exc:
        logger.warning(
            "Failed to parse enrichment for %s:%s — %s",
            item.vulnerability.path,
            item.vulnerability.start_line,
            exc,
        )
        return []

    discoveries = parsed.get("new_discoveries", [])
    return discoveries


def _overlaps(
    existing_items: list[RiskItem],
    file_path: str,
    start_line: int,
    end_line: int,
) -> bool:
    for item in existing_items:
        if item.vulnerability.path != file_path:
            continue
        existing_line = item.vulnerability.start_line
        if existing_line is None:
            continue
        if start_line <= existing_line <= end_line:
            return True
    return False


def create_new_findings_from_discoveries(
    discoveries: list[dict],
    spec: HardwareSpec,
    existing_items: list[RiskItem] | None = None,
) -> list[RiskItem]:
    if existing_items is None:
        existing_items = []

    new_items: list[RiskItem] = []

    for discovery in discoveries:
        try:
            file_path = discovery["file_path"]
            start_line = int(discovery["start_line"])
            end_line = int(discovery["end_line"])
            discovery_type = discovery.get("type", "unknown")
            severity_rationale = discovery.get("severity_rationale", "")
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Skipping unparseable discovery: %s — %s", discovery, exc)
            continue

        all_items = existing_items + new_items
        if _overlaps(all_items, file_path, start_line, end_line):
            logger.info(
                "Skipping duplicate discovery at %s:%d-%d",
                file_path,
                start_line,
                end_line,
            )
            continue

        category = _CATEGORY_MAP.get(discovery_type, VulnerabilityCategory.UNKNOWN)

        vuln = Vulnerability(
            tool="llm",
            rule_id=f"LLM-{discovery_type.upper().replace(' ', '-')}",
            message=severity_rationale or f"LLM-discovered {discovery_type}",
            path=file_path,
            start_line=start_line,
            category=category,
        )

        risk_item = score_vulnerability(vuln, spec)
        risk_item.source = "llm"
        new_items.append(risk_item)

    return new_items


def resolve_suggested_category(suggested: str | None) -> VulnerabilityCategory | None:
    """Map an LLM-suggested category string to a VulnerabilityCategory enum value.

    Returns None for novel categories that don't match any predefined category.
    Returns VulnerabilityCategory.UNKNOWN if the LLM explicitly says "unknown".
    """
    if not suggested:
        return None
    normalized = suggested.lower().strip().replace("-", "_").replace(" ", "_")
    if normalized == "unknown":
        return VulnerabilityCategory.UNKNOWN
    # Try direct enum value match
    for cat in VulnerabilityCategory:
        if cat.value == normalized:
            return cat
    # Try the existing _CATEGORY_MAP
    if normalized in _CATEGORY_MAP:
        mapped = _CATEGORY_MAP[normalized]
        if mapped != VulnerabilityCategory.UNKNOWN:
            return mapped
    # Novel category — caller decides what to do
    return None


def _scan_single_file(
    file_path: str,
    all_items: list[RiskItem],
    spec: HardwareSpec,
    client: LLMClient,
    tracker: CostTracker,
    source_root: Path,
    max_lines: int,
) -> list[dict]:
    """Send one file to the LLM for vulnerability discovery. Returns raw discovery dicts."""
    source_file = source_root / file_path
    try:
        content = source_file.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s — %s", source_file, exc)
        return []

    file_findings = [
        item for item in all_items
        if item.vulnerability.path == file_path
    ]

    user_prompt = build_discovery_prompt(file_path, content, file_findings, spec)
    request = LLMRequest(
        system_prompt=DISCOVERY_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_schema=FileDiscoverySchema,
    )

    try:
        response = client.analyze(request)
        tracker.record(response)
    except Exception as exc:
        logger.warning("LLM call failed for file %s — %s", file_path, exc)
        return []

    parsed = response.parsed_content
    if not parsed and response.raw_content:
        try:
            parsed = json.loads(response.raw_content)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Malformed JSON response for file %s", file_path)
            return []

    if not parsed:
        return []

    return parsed.get("discoveries", [])


def discover_file_vulnerabilities(
    seed_items: list[RiskItem],
    all_items: list[RiskItem],
    spec: HardwareSpec,
    client: LLMClient,
    tracker: CostTracker,
    source_root: Path,
    max_lines: int = 3000,
    max_files: int = 15,
    max_depth: int = 2,
) -> list[RiskItem]:
    """Scan source files for vulnerabilities the static analyzer missed.

    Starts from files containing the top-K scored findings (seed files), then
    follows references to additional files discovered by the LLM (escalation),
    up to max_files total and max_depth levels deep.

    Returns new RiskItem objects with source="llm".
    """
    # Build ordered seed file list (highest-scoring file first)
    seen_paths: dict[str, int] = {}  # file_path -> depth
    for item in seed_items:
        p = item.vulnerability.path
        if p and p not in seen_paths:
            seen_paths[p] = 0

    queue: list[tuple[str, int]] = [(p, 0) for p in seen_paths]
    scanned: set[str] = set()
    all_raw_discoveries: list[dict] = []

    while queue and len(scanned) < max_files:
        file_path, depth = queue.pop(0)
        if file_path in scanned:
            continue

        logger.info("Scanning file (depth=%d): %s", depth, file_path)
        print(f"    Scanning: {file_path}")

        raw = _scan_single_file(
            file_path, all_items, spec, client, tracker, source_root, max_lines
        )
        scanned.add(file_path)
        all_raw_discoveries.extend(raw)

        # Escalation: queue new files referenced in discoveries
        if depth < max_depth:
            for discovery in raw:
                ref_path = discovery.get("file_path", "")
                if ref_path and ref_path != file_path and ref_path not in scanned:
                    if not any(ref_path == q[0] for q in queue):
                        queue.append((ref_path, depth + 1))
                        logger.info("Escalating to referenced file: %s", ref_path)

    print(f"    Scanned {len(scanned)} file(s), found {len(all_raw_discoveries)} raw candidates")
    return create_new_findings_from_discoveries(all_raw_discoveries, spec, all_items)


def enrich_items(
    selected_items: list[RiskItem],
    evidence_bundles: list[EvidenceBundle],
    spec: HardwareSpec,
    client: LLMClient,
    tracker: CostTracker,
) -> list[RiskItem]:
    all_discoveries: list[dict] = []

    for item, bundle in zip(selected_items, evidence_bundles):
        try:
            discoveries = _enrich_single_item(item, bundle, spec, client, tracker)
            all_discoveries.extend(discoveries)
        except Exception as exc:
            logger.warning(
                "Enrichment failed for %s:%s — %s",
                item.vulnerability.path,
                item.vulnerability.start_line,
                exc,
            )

    new_findings = create_new_findings_from_discoveries(
        all_discoveries, spec, selected_items
    )

    return list(selected_items) + new_findings
