from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from constraintguard.models.enums import SeverityTier
from constraintguard.models.hardware_spec import ConstraintProvenance, HardwareSpec
from constraintguard.models.vulnerability import Vulnerability


class RuleFiring(BaseModel):
    rule_id: str
    delta: int
    rationale: str
    constraints_used: list[str]


class RiskItem(BaseModel):
    vulnerability: Vulnerability
    base_score: int
    final_score: int
    tier: SeverityTier
    rule_firings: list[RuleFiring]
    explanation: str
    remediation: str
    enrichment: dict[str, Any] | None = None


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


class RiskReport(BaseModel):
    run_metadata: RunMetadata
    hardware_spec: HardwareSpec
    provenance: ConstraintProvenance
    summary: ReportSummary
    items: list[RiskItem]
