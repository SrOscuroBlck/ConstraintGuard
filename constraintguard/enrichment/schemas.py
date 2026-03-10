from pydantic import BaseModel, Field


class FixSuggestionSchema(BaseModel):
    line: int
    original_code: str
    proposed_code: str
    rationale: str


class NewDiscoverySchema(BaseModel):
    type: str
    severity_rationale: str
    file_path: str
    start_line: int
    end_line: int
    evidence_citation: str


class LLMAnalysisSchema(BaseModel):
    tags: list[str] = Field(default_factory=list)
    explanation: str = ""
    fix_suggestions: list[FixSuggestionSchema] = Field(default_factory=list)
    new_discoveries: list[NewDiscoverySchema] = Field(default_factory=list)


LLM_OUTPUT_JSON_SCHEMA: dict = LLMAnalysisSchema.model_json_schema()
