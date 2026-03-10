from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMConfig(BaseModel):
    provider: LLMProvider
    model: str
    api_key: str
    timeout: int = 300
    max_retries: int = 3
    reasoning_effort: str = "medium"


class LLMRequest(BaseModel):
    system_prompt: str
    user_prompt: str
    response_schema: type | None = None

    model_config = {"arbitrary_types_allowed": True}


class LLMResponse(BaseModel):
    parsed_content: dict[str, Any] = Field(default_factory=dict)
    raw_content: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    provider: LLMProvider = LLMProvider.OPENAI


class LLMCostRecord(BaseModel):
    model: str
    input_tokens: int
    output_tokens: int
    cost: Decimal
    timestamp: datetime


class LLMRunSummary(BaseModel):
    total_calls: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost: Decimal
    records: list[LLMCostRecord]
