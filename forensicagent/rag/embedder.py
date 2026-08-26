"""Embedding interface for forensicagent's tool-metadata RAG.

도구 YAML 인덱싱 시점과 (드물게 발생하는) 자연어 도구 추천 질의 시점이
**같은 임베딩 모델**을 써야 의미 검색이 동작한다. 그 일치를 코드 구조로
강제하기 위해 인덱서와 셀렉터가 모두 이 모듈을 import 한다.

모델 라우팅: `settings.EMBEDDING_MODEL` 이 `openai:` 로 시작하면 OpenAI
API 백엔드, 아니면 로컬 sentence-transformers.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable, Protocol

from forensicagent import config as settings


class _EmbeddingBackend(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class _SentenceTransformerBackend:
    """sentence-transformers 기반 로컬 임베딩."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer  # lazy

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        # convert_to_numpy=True 가 기본; .tolist() 로 JSON 직렬화 가능하게.
        vectors = self._model.encode(texts, convert_to_numpy=True)
        return [v.tolist() for v in vectors]


class _OpenAIBackend:
    """OpenAI API 기반 임베딩.

    모델명 표기: `openai:text-embedding-3-small` → 실제 호출은 `text-embedding-3-small`.
    """

    def __init__(self, model_name: str) -> None:
        from openai import OpenAI  # lazy

        if not settings.OPENAI_API_KEY:
            raise RuntimeError(
                "OPENAI_API_KEY is empty — set the env var or switch "
                "FORENSICAGENT_EMBEDDING_MODEL to a local model."
            )
        self._model = model_name.removeprefix("openai:")
        self._client = OpenAI(api_key=settings.OPENAI_API_KEY)

    def embed(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embeddings.create(model=self._model, input=texts)
        return [item.embedding for item in resp.data]


@lru_cache(maxsize=1)
def _get_backend() -> _EmbeddingBackend:
    """프로세스당 1회만 모델을 로드."""
    model_name = settings.EMBEDDING_MODEL
    if model_name.startswith("openai:"):
        return _OpenAIBackend(model_name)
    return _SentenceTransformerBackend(model_name)


def embed_texts(texts: Iterable[str]) -> list[list[float]]:
    """배치 임베딩. 빈 입력은 [] 반환."""
    text_list = list(texts)
    if not text_list:
        return []
    return _get_backend().embed(text_list)


def embed_text(text: str) -> list[float]:
    """단일 텍스트 임베딩."""
    return embed_texts([text])[0]
