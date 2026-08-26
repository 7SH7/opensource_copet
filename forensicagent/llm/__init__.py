"""Local LLM wrapper.

명세 3.x 의 제약을 코드로 흡수하는 자리:
  - format="json" 강제
  - JSON 파싱 실패 시 1회 재시도 (다시 JSON 으로만 답하라는 보강 프롬프트)
  - 그래도 실패하면 룰 fallback 으로 분기할 수 있게 sentinel 반환
"""

from forensicagent.llm.ollama_client import (
    JsonRetryFailed,
    OllamaClient,
    OllamaUnavailable,
)

__all__ = ["OllamaClient", "JsonRetryFailed", "OllamaUnavailable"]
