from datetime import datetime, timezone
from decimal import Decimal

from constraintguard.llm.models import LLMCostRecord, LLMResponse, LLMRunSummary

DEFAULT_PRICE_TABLE: dict[str, dict[str, Decimal]] = {
    "gpt-4o": {
        "input": Decimal("0.0000025"),
        "output": Decimal("0.000010"),
    },
    "gpt-4o-mini": {
        "input": Decimal("0.00000015"),
        "output": Decimal("0.0000006"),
    },
    "gpt-5": {
        "input": Decimal("0.00000125"),
        "output": Decimal("0.000010"),
    },
    "gpt-5-mini": {
        "input": Decimal("0.00000025"),
        "output": Decimal("0.000002"),
    },
    "gpt-5-mini-2025-08-07": {
        "input": Decimal("0.00000025"),
        "output": Decimal("0.000002"),
    },
    "gpt-5-nano": {
        "input": Decimal("0.00000005"),
        "output": Decimal("0.0000004"),
    },
    "claude-sonnet-4-20250514": {
        "input": Decimal("0.000003"),
        "output": Decimal("0.000015"),
    },
    "claude-3-5-haiku-20241022": {
        "input": Decimal("0.0000008"),
        "output": Decimal("0.000004"),
    },
}

_FALLBACK_INPUT_PRICE = Decimal("0.000003")
_FALLBACK_OUTPUT_PRICE = Decimal("0.000015")


def calculate_cost(
    response: LLMResponse,
    price_table: dict[str, dict[str, Decimal]] | None = None,
) -> Decimal:
    table = price_table or DEFAULT_PRICE_TABLE
    model_prices = table.get(response.model)

    if model_prices:
        input_price = model_prices["input"]
        output_price = model_prices["output"]
    else:
        input_price = _FALLBACK_INPUT_PRICE
        output_price = _FALLBACK_OUTPUT_PRICE

    return (
        Decimal(response.input_tokens) * input_price
        + Decimal(response.output_tokens) * output_price
    )


class CostTracker:
    def __init__(
        self,
        price_table: dict[str, dict[str, Decimal]] | None = None,
    ) -> None:
        self._price_table = price_table
        self._records: list[LLMCostRecord] = []

    def record(self, response: LLMResponse) -> LLMCostRecord:
        cost = calculate_cost(response, self._price_table)
        cost_record = LLMCostRecord(
            model=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost=cost,
            timestamp=datetime.now(timezone.utc),
        )
        self._records.append(cost_record)
        return cost_record

    def summarize(self) -> LLMRunSummary:
        return LLMRunSummary(
            total_calls=len(self._records),
            total_input_tokens=sum(r.input_tokens for r in self._records),
            total_output_tokens=sum(r.output_tokens for r in self._records),
            total_cost=sum((r.cost for r in self._records), Decimal("0")),
            records=list(self._records),
        )
