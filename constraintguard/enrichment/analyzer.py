import json
import logging

from constraintguard.enrichment.prompts import SYSTEM_PROMPT, build_user_prompt
from constraintguard.enrichment.schemas import LLMAnalysisSchema
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
