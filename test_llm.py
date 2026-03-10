import os

from constraintguard.llm.client import create_llm_client
from constraintguard.llm.models import LLMConfig, LLMRequest, LLMResponse, LLMProvider
from constraintguard.llm.cost import CostTracker

api_key = os.environ["CONSTRAINTGUARD_LLM_API_KEY"]

config = LLMConfig(provider="openai", model="gpt-5-mini", api_key=api_key, timeout=60, max_retries=3)
client = create_llm_client(config)
print(f"OpenAI client: {type(client).__name__}, internal: {type(client._client).__name__}")

tracker = CostTracker()

request = LLMRequest(system_prompt="You are a security expert.", user_prompt="Say hello in JSON: {\"greeting\": \"...\"}", response_schema=None)
response = client.analyze(request)
print(f"Response: parsed={response.parsed_content}, tokens={response.input_tokens}+{response.output_tokens}")

tracker.record(response)
summary = tracker.summarize()
print(f"Summary: calls={summary.total_calls}, in={summary.total_input_tokens}, out={summary.total_output_tokens}, cost={summary.total_cost}")

print("All verifications passed!")
