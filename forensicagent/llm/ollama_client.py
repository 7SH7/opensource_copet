"""Thin Ollama client with structured-output discipline.

로컬 LLM 의 두 가지 신뢰성 이슈를 흡수한다:
  1. JSON 출력이 깨지면 한 번 더 시도, 실패 시 명확한 예외 → 룰 fallback
  2. 모델/데몬이 없으면 OllamaUnavailable — Selector/Analyzer 가 잡아
     graceful degradation 으로 분기

Lazy import: ollama 패키지는 CLI 부팅과 무관하므로 chat 호출 시점에만 import.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable

from forensicagent import config as settings

logger = logging.getLogger(__name__)


class OllamaUnavailable(RuntimeError):
    """ollama 데몬 또는 지정 모델이 사용 불가."""


class JsonRetryFailed(ValueError):
    """JSON 으로 응답하라고 강제했는데 두 번 모두 파싱 실패."""

    def __init__(self, message: str, last_raw: str) -> None:
        super().__init__(message)
        self.last_raw = last_raw


@dataclass
class ChatMessage:
    role: str   # "system" | "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


def _response_content(response: Any) -> str:
    """Read content from both legacy dict and modern Pydantic Ollama replies."""
    if isinstance(response, dict):
        message = response.get("message") or {}
    else:
        message = getattr(response, "message", None)
    if isinstance(message, dict):
        value = message.get("content", "")
    else:
        value = getattr(message, "content", "") if message is not None else ""
    return str(value or "")


class OllamaClient:
    """forensicagent 의 모든 LLM 호출이 통과하는 단일 진입점."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        num_ctx: int | None = None,
        num_predict: int | None = None,
    ) -> None:
        self.base_url = base_url or settings.LLM_BASE_URL
        self.model = model or settings.LLM_MODEL
        self.temperature = (
            temperature if temperature is not None else settings.LLM_TEMPERATURE
        )
        # Ollama 기본 num_ctx 는 4096 — DFIR / EZTools 매뉴얼은 그것보다 훨씬
        # 큼. 16K 컨텍스트로 띄워야 입력 + 시스템 + JSON 출력 다 들어간다.
        # GPU/RAM 여유에 따라 env 로 조정 가능.
        import os
        self.num_ctx = (
            num_ctx if num_ctx is not None
            else int(os.getenv("FORENSICAGENT_LLM_NUM_CTX", "16384"))
        )
        # JSON 출력은 ToolMetadata 한 건 기준 ~1500 토큰 정도면 충분.
        self.num_predict = (
            num_predict if num_predict is not None
            else int(os.getenv("FORENSICAGENT_LLM_NUM_PREDICT", "2048"))
        )

    # ---------- low level ----------

    def _client(self, *, timeout: float | None = None):
        # Lazy import — ollama 패키지가 없거나 데몬이 죽었을 때
        # forensicagent 자체는 부팅되어야 한다 (doctor 가 그걸 알려줘야 함).
        try:
            import ollama  # type: ignore
        except ImportError as e:
            raise OllamaUnavailable(
                "ollama python package not installed (pip install ollama)"
            ) from e
        kwargs: dict[str, Any] = {"host": self.base_url}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return ollama.Client(**kwargs)

    def is_available(self) -> tuple[bool, str]:
        """doctor 가 쓰기 좋은 형태로 가용성 점검.

        반환: (ok, detail_message)
        """
        try:
            client = self._client(timeout=settings.LLM_HEALTH_TIMEOUT_SEC)
        except OllamaUnavailable as e:
            return False, str(e)

        try:
            resp = client.list()
        except Exception as e:  # noqa: BLE001
            return False, f"cannot reach ollama at {self.base_url}: {e}"

        # ollama python lib changed shape between versions:
        #   < 0.4: dict with {"models": [{"name": "..."}]}
        #   >= 0.5: Pydantic ListResponse with .models = [Model(model="...")]
        models_iter = (
            resp.models if hasattr(resp, "models")
            else (resp.get("models", []) if isinstance(resp, dict) else [])
        )
        names: list[str] = []
        for m in models_iter:
            # New shape: Model(model="qwen2.5:7b", ...)
            # Old shape: {"name": "qwen2.5:7b"}
            name = (
                getattr(m, "model", None)
                or getattr(m, "name", None)
                or (m.get("name") or m.get("model") if isinstance(m, dict) else None)
                or ""
            )
            if name:
                names.append(name)

        # A different size/tag of the same family is not interchangeable.  The
        # old family-prefix fallback reported qwen2.5:3b as satisfying a
        # qwen2.5:14b request and the first real inference then failed.
        if ":" in self.model:
            ready = self.model in names
        else:
            ready = self.model in names or any(
                n.startswith(self.model + ":") for n in names
            )
        if not ready:
            return False, (
                f"ollama is reachable but model '{self.model}' not pulled. "
                f"Available: {', '.join(names) or '(none)'}"
            )
        return True, f"ollama ok, model {self.model} ready ({len(names)} pulled)"

    # ---------- text chat ----------

    def chat(
        self,
        messages: Iterable[ChatMessage | dict[str, str]],
        *,
        temperature: float | None = None,
    ) -> str:
        """plain text chat. 빈 응답이면 빈 문자열 반환."""
        try:
            client = self._client(timeout=settings.LLM_REQUEST_TIMEOUT_SEC)
        except OllamaUnavailable:
            raise

        msgs = [m.to_dict() if isinstance(m, ChatMessage) else m for m in messages]
        try:
            resp = client.chat(
                model=self.model,
                messages=msgs,
                options={
                    "temperature": (
                        temperature if temperature is not None else self.temperature
                    ),
                    "num_ctx": self.num_ctx,
                    "num_predict": self.num_predict,
                },
            )
        except Exception as e:  # noqa: BLE001
            raise OllamaUnavailable(f"ollama chat failed: {e}") from e
        return _response_content(resp)

    # ---------- structured JSON chat ----------

    def json_chat(
        self,
        messages: Iterable[ChatMessage | dict[str, str]],
        *,
        temperature: float | None = None,
        retry: int = 1,
        format_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """JSON 강제 응답. 파싱 실패 시 retry 번 재시도 후 JsonRetryFailed.

        Args:
            format_schema: 있으면 Ollama 의 structured output 기능 사용
                (`format=<json_schema_dict>`). 모델 출력이 schema 의 필드명,
                타입, required 를 그대로 따르도록 *강제* 됨. 일반적으로
                `MyPydanticModel.model_json_schema()` 결과를 그대로 넘긴다.
                None 이면 `format="json"` 만 사용 (필드명 자유).

        format="json" 옵션과 함께, 시스템 메시지를 마지막에 한 줄 더 박아
        모델이 산문 답변을 섞지 않도록 강제한다.

        Schema 강제와 단순 JSON 의 trade-off:
            * 강제: 필드명/타입 보장 → Stage 2 처럼 우리 Pydantic 검증 통과
              확률이 크게 오른다. 단점은 모델이 추론 시간 더 쓰고, 컨텍스트
              한도에 더 빨리 닿을 수 있음.
            * 비강제: 모델이 자기 자연스러운 키로 응답해서 매핑 필요.
        """
        try:
            client = self._client(timeout=settings.LLM_REQUEST_TIMEOUT_SEC)
        except OllamaUnavailable:
            raise

        base_msgs = [
            m.to_dict() if isinstance(m, ChatMessage) else dict(m) for m in messages
        ]
        attempts = retry + 1
        last_raw = ""
        last_err = ""

        # Ollama python >=0.4 accepts dict for `format` for JSON-Schema-constrained
        # generation. Fall back to "json" string otherwise.
        format_arg: Any = format_schema if format_schema is not None else "json"

        for attempt in range(attempts):
            msgs = list(base_msgs)
            if attempt > 0:
                # 보강: 이전 응답이 깨졌으니 JSON 만 달라고 명시.
                msgs.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous reply could not be parsed as JSON. "
                            "Reply ONLY with a single valid JSON value - no prose, "
                            "no markdown fences, no commentary."
                        ),
                    }
                )
            try:
                resp = client.chat(
                    model=self.model,
                    messages=msgs,
                    format=format_arg,
                    options={
                        "temperature": (
                            temperature
                            if temperature is not None
                            else self.temperature
                        ),
                        "num_ctx": self.num_ctx,
                        "num_predict": self.num_predict,
                    },
                )
            except Exception as e:  # noqa: BLE001
                raise OllamaUnavailable(f"ollama json_chat failed: {e}") from e

            last_raw = _response_content(resp)
            try:
                return json.loads(last_raw)
            except json.JSONDecodeError as e:
                last_err = str(e)
                logger.warning(
                    "json_chat parse attempt %d/%d failed: %s",
                    attempt + 1,
                    attempts,
                    last_err,
                )

        raise JsonRetryFailed(
            f"JSON parse failed after {attempts} attempt(s): {last_err}",
            last_raw=last_raw,
        )
