from enum import Enum

from pydantic import BaseModel, Field


class SnippetType(Enum):
    FUNCTION_BODY = "function_body"
    SURROUNDING_CONTEXT = "surrounding_context"
    CALL_SITE = "call_site"
    DATA_STRUCTURE = "data_structure"


class CodeSnippet(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    content: str
    snippet_type: SnippetType


class EvidenceBundle(BaseModel):
    vulnerability_path: str
    vulnerability_line: int | None
    function_body: CodeSnippet | None = None
    surrounding_context: CodeSnippet | None = None
    call_sites: list[CodeSnippet] = Field(default_factory=list)
    data_structures: list[CodeSnippet] = Field(default_factory=list)
    constraint_context: dict = Field(default_factory=dict)
    total_size_bytes: int = 0
