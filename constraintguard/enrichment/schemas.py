from pydantic import AliasChoices, BaseModel, Field


class FixSuggestionSchema(BaseModel):
    line: int = Field(validation_alias=AliasChoices("line", "original_line", "line_number"))
    original_code: str = Field(validation_alias=AliasChoices("original_code", "original", "before"))
    proposed_code: str = Field(validation_alias=AliasChoices("proposed_code", "proposed", "replacement", "after"))
    rationale: str = Field(validation_alias=AliasChoices("rationale", "reason", "explanation"))


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
