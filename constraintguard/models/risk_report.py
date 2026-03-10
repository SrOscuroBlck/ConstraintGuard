from datetime import datetime

from pydantic import BaseModel, Field

from constraintguard.models.enums import SeverityTier
from constraintguard.models.hardware_spec import ConstraintProvenance, HardwareSpec
from constraintguard.models.vulnerability import Vulnerability


class RuleFiring(BaseModel):
    rule_id: str
    delta: int
    rationale: str
    constraints_used: list[str]


class FixSuggestion(BaseModel):
    line: int
    original_code: str
    proposed_code: str
    rationale: str


class EvidenceCitation(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    snippet: str


class EnrichmentOutput(BaseModel):
    tags: list[str] = Field(default_factory=list)
    llm_explanation: str | None = None
    fix_suggestions: list[FixSuggestion] = Field(default_factory=list)
    evidence_citations: list[EvidenceCitation] = Field(default_factory=list)
    model_used: str | None = None
    tokens_used: int = 0
    cost: float = 0.0


class RiskItem(BaseModel):
    vulnerability: Vulnerability
    base_score: int
    final_score: int
    tier: SeverityTier
    rule_firings: list[RuleFiring]
    explanation: str
    remediation: str
    enrichment: EnrichmentOutput | None = None
    source: str = "sarif"


class TierCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ReportSummary(BaseModel):
    total_findings: int
    tier_counts: TierCounts
    top_findings: list[str] = Field(default_factory=list)


class RunMetadata(BaseModel):
    tool_version: str
    timestamp: datetime
    command: str | None = None
    source_path: str | None = None
    config_path: str | None = None
    mode: str = "expert"
    llm_model: str | None = None
    llm_provider: str | None = None
    llm_total_cost: float | None = None
    llm_total_tokens: int | None = None


class RiskReport(BaseModel):
    run_metadata: RunMetadata
    hardware_spec: HardwareSpec
    provenance: ConstraintProvenance
    summary: ReportSummary
    items: list[RiskItem]
