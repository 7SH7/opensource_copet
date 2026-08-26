"""ChromaDB-backed vector store for forensicagent tool metadata.

forensicagent 의 rag/ 는 **도구 YAML 메타데이터의 lookup-heavy 검색**용이다.
50+ 개 도구의 usage_description / suspicious_indicators / command_templates
각 섹션을 청크로 임베딩해서 보관하고, Selector 가 결정론 필터로 1차 후보를
좁힌 뒤 LLM 컨텍스트에 넣을 자연어 설명을 가져온다.

설계 원칙: **저장은 storage 가, 정책은 retrieval 이.**
이 모듈은 CRUD + 의미 검색만, threshold/필터 정책은 호출자가 결정.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from forensicagent import config as settings


@dataclass
class RetrievedChunk:
    content: str
    metadata: dict[str, Any]
    similarity_score: float
    chunk_id: str


# ChromaDB 메타데이터는 scalar 만 받는다 (str/int/float/bool).
# list/dict/None 같은 값은 거부되므로 sanitize 단계에서 변환.
_SCALAR_TYPES = (str, int, float, bool)


def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """Chroma 가 허용하는 scalar 만 통과시키고 나머지는 str() 로."""
    clean: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, bool):
            clean[k] = v
        elif isinstance(v, _SCALAR_TYPES):
            clean[k] = v
        else:
            clean[k] = str(v)
    return clean


class VectorStore:
    """ChromaDB 단일 컬렉션 위의 thin wrapper."""

    def __init__(
        self,
        persist_dir: str | None = None,
        collection_name: str | None = None,
    ) -> None:
        # Lazy import — chromadb 는 무겁고 CLI 부팅 시간에 영향을 준다.
        import chromadb
        from chromadb.config import Settings as ChromaSettings

        persist = persist_dir or settings.CHROMA_PERSIST_DIR
        Path(persist).mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(
            path=persist,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collection_name = collection_name or settings.CHROMA_COLLECTION
        # cosine space — 명세에서 cosine similarity 사용 명시.
        self._collection = self._client.get_or_create_collection(
            name=self._collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    # ---------- writes ----------

    def add(
        self,
        contents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        ids: list[str] | None = None,
    ) -> list[str]:
        """청크 N 개를 한 번에 저장. ids 없으면 UUID 로 생성."""
        n = len(contents)
        if not (len(embeddings) == n and len(metadatas) == n):
            raise ValueError(
                f"length mismatch: contents={n}, embeddings={len(embeddings)}, "
                f"metadatas={len(metadatas)}"
            )
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in range(n)]
        elif len(ids) != n:
            raise ValueError(f"ids length {len(ids)} != contents length {n}")

        clean_metas = [_sanitize_metadata(m) for m in metadatas]
        self._collection.add(
            documents=contents,
            embeddings=embeddings,
            metadatas=clean_metas,
            ids=ids,
        )
        return ids

    def delete(self, ids: Iterable[str]) -> None:
        id_list = list(ids)
        if not id_list:
            return
        self._collection.delete(ids=id_list)

    def reset(self) -> None:
        """컬렉션을 완전히 비운다 (테스트/재인덱싱용)."""
        name = self._collection_name
        self._client.delete_collection(name=name)
        self._collection = self._client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

    # ---------- reads ----------

    def query(
        self,
        embedding: list[float],
        top_k: int,
        where: dict[str, Any] | None = None,
    ) -> list[RetrievedChunk]:
        """질문 벡터로 Top-K 검색.

        cosine distance ∈ [0, 2] 를 유사도 = 1 - distance 로 변환하고
        [0, 1] 범위로 클램프한다 (Chroma 는 가끔 음수 distance 를 반환).
        """
        result = self._collection.query(
            query_embeddings=[embedding],
            n_results=top_k,
            where=where,
        )

        # Chroma 는 [[...]] 처럼 1-batch 의 nested list 로 반환.
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]

        chunks: list[RetrievedChunk] = []
        for cid, doc, meta, dist in zip(ids, docs, metas, dists):
            sim = max(0.0, min(1.0, 1.0 - float(dist)))
            chunks.append(
                RetrievedChunk(
                    content=doc or "",
                    metadata=dict(meta or {}),
                    similarity_score=sim,
                    chunk_id=cid,
                )
            )
        return chunks

    def count(self) -> int:
        return int(self._collection.count())
