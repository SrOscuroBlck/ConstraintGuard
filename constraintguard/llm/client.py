import json
import logging
import time
from abc import ABC, abstractmethod

from constraintguard.llm.models import LLMConfig, LLMProvider, LLMRequest, LLMResponse

logger = logging.getLogger(__name__)

_REASONING_MODEL_PREFIXES = ("o1", "o3", "o4", "gpt-5")

_NON_RETRYABLE_STATUS_CODES = {401, 403, 404}

_EMPTY_RESPONSE = LLMResponse()


def _is_reasoning_model(model: str) -> bool:
    return any(model.startswith(prefix) for prefix in _REASONING_MODEL_PREFIXES)


def _is_retryable(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if status_code and status_code in _NON_RETRYABLE_STATUS_CODES:
        return False
    return True


def _build_empty_response(config: LLMConfig) -> LLMResponse:
    return LLMResponse(model=config.model, provider=config.provider)


class LLMClient(ABC):
    @abstractmethod
    def analyze(self, request: LLMRequest) -> LLMResponse:
        pass


class OpenAIClient(LLMClient):
    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        try:
            import openai

            self._client = openai.OpenAI(
                api_key=config.api_key,
                timeout=config.timeout,
            )
        except Exception as exc:
            logger.warning("Failed to initialize OpenAI client: %s", exc)
            self._client = None

    def analyze(self, request: LLMRequest) -> LLMResponse:
        if self._client is None:
            return _build_empty_response(self._config)

        for attempt in range(self._config.max_retries + 1):
            try:
                return self._call_api(request)
            except Exception as exc:
                if not _is_retryable(exc) or attempt >= self._config.max_retries:
                    logger.warning(
                        "OpenAI request failed (non-retryable or max attempts): %s",
                        exc,
                    )
                    return _build_empty_response(self._config)
                wait_time = 2**attempt
                logger.warning(
                    "OpenAI request failed (attempt %d/%d): %s. Retrying in %ds",
                    attempt + 1,
                    self._config.max_retries + 1,
                    exc,
                    wait_time,
                )
                time.sleep(wait_time)

        return _build_empty_response(self._config)

    def _call_api(self, request: LLMRequest) -> LLMResponse:
        if _is_reasoning_model(self._config.model):
            return self._call_responses_api(request)
        return self._call_chat_completions_api(request)

    def _call_responses_api(self, request: LLMRequest) -> LLMResponse:
        input_messages = [
            {"role": "developer", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ]

        kwargs: dict = {
            "model": self._config.model,
            "input": input_messages,
            "reasoning": {"effort": self._config.reasoning_effort},
        }

        if request.response_schema is not None:
            kwargs["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "analysis_output",
                    "schema": request.response_schema.model_json_schema(),
                }
            }
        else:
            kwargs["text"] = {"format": {"type": "json_object"}}

        response = self._client.responses.create(**kwargs)

        raw_content = response.output_text or ""
        parsed_content = _safe_parse_json(raw_content)

        input_tokens = getattr(response.usage, "input_tokens", 0) if response.usage else 0
        output_tokens = getattr(response.usage, "output_tokens", 0) if response.usage else 0

        return LLMResponse(
            parsed_content=parsed_content,
            raw_content=raw_content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self._config.model,
            provider=self._config.provider,
        )

    def _call_chat_completions_api(self, request: LLMRequest) -> LLMResponse:
        messages = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ]

        kwargs: dict = {
            "model": self._config.model,
            "messages": messages,
            "timeout": self._config.timeout,
        }

        if request.response_schema is not None:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "analysis_output",
                    "schema": request.response_schema.model_json_schema(),
                },
            }
        else:
            kwargs["response_format"] = {"type": "json_object"}

        response = self._client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        raw_content = choice.message.content or ""
        parsed_content = _safe_parse_json(raw_content)

        input_tokens = response.usage.prompt_tokens if response.usage else 0
        output_tokens = response.usage.completion_tokens if response.usage else 0

        return LLMResponse(
            parsed_content=parsed_content,
            raw_content=raw_content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self._config.model,
            provider=self._config.provider,
        )


class AnthropicClient(LLMClient):
    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        try:
            import anthropic

            self._client = anthropic.Anthropic(
                api_key=config.api_key,
                timeout=config.timeout,
            )
        except Exception as exc:
            logger.warning("Failed to initialize Anthropic client: %s", exc)
            self._client = None

    def analyze(self, request: LLMRequest) -> LLMResponse:
        if self._client is None:
            return _build_empty_response(self._config)

        for attempt in range(self._config.max_retries + 1):
            try:
                return self._call_api(request)
            except Exception as exc:
                if not _is_retryable(exc) or attempt >= self._config.max_retries:
                    logger.warning(
                        "Anthropic request failed (non-retryable or max attempts): %s",
                        exc,
                    )
                    return _build_empty_response(self._config)
                wait_time = 2**attempt
                logger.warning(
                    "Anthropic request failed (attempt %d/%d): %s. Retrying in %ds",
                    attempt + 1,
                    self._config.max_retries + 1,
                    exc,
                    wait_time,
                )
                time.sleep(wait_time)

        return _build_empty_response(self._config)

    def _call_api(self, request: LLMRequest) -> LLMResponse:
        schema = _build_anthropic_tool_schema(request)

        response = self._client.messages.create(
            model=self._config.model,
            max_tokens=4096,
            system=request.system_prompt,
            messages=[{"role": "user", "content": request.user_prompt}],
            tools=[schema],
            tool_choice={"type": "tool", "name": "analysis_output"},
            timeout=self._config.timeout,
        )

        parsed_content: dict = {}
        raw_content = ""

        for block in response.content:
            if block.type == "tool_use" and block.name == "analysis_output":
                parsed_content = block.input if isinstance(block.input, dict) else {}
                raw_content = json.dumps(parsed_content)
                break

        if not parsed_content and response.content:
            for block in response.content:
                if hasattr(block, "text"):
                    raw_content = block.text
                    parsed_content = _safe_parse_json(raw_content)
                    break

        input_tokens = response.usage.input_tokens if response.usage else 0
        output_tokens = response.usage.output_tokens if response.usage else 0

        return LLMResponse(
            parsed_content=parsed_content,
            raw_content=raw_content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self._config.model,
            provider=self._config.provider,
        )


def _build_anthropic_tool_schema(request: LLMRequest) -> dict:
    if request.response_schema is not None:
        json_schema = request.response_schema.model_json_schema()
        properties = json_schema.get("properties", {})
        required = json_schema.get("required", [])
    else:
        properties = {
            "result": {
                "type": "object",
                "description": "Analysis result as JSON",
            }
        }
        required = ["result"]

    return {
        "name": "analysis_output",
        "description": "Structured analysis output",
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def _safe_parse_json(text: str) -> dict:
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
        return {"result": result}
    except (json.JSONDecodeError, TypeError):
        return {}


def create_llm_client(config: LLMConfig) -> LLMClient:
    if config.provider == LLMProvider.OPENAI:
        return OpenAIClient(config)
    if config.provider == LLMProvider.ANTHROPIC:
        return AnthropicClient(config)
    raise ValueError(f"Unsupported LLM provider: {config.provider}")
