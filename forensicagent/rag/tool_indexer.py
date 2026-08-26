"""Index tools_metadata/*.yaml into a dedicated ChromaDB collection.

이 컬렉션(config.TOOL_COLLECTION)이 **런타임 Selector 가 실제로 질의하는**
도구 코퍼스다. seed_docs 크롤 코퍼스(seed_*)는 도구 선택엔 무용지물이라,
여기서는 도구 YAML 자체를 문서화한다.

문서 구성 (도구 1 개 = 문서 1 개, id = tool_id):
  * display_name / tool_id
  * category (+ subcategory)
  * applicable_evidence_types
  * usage_description
  * command_templates 의 when 절
  * suspicious_indicators 의 pattern + description (severity 태그)

무거운 의존성(chromadb, sentence-transformers)은 함수 내부에서 lazy import.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from forensicagent import config as settings
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger("rag.tool_indexer")


def build_tool_document(meta: ToolMetadata) -> str:
    """도구 메타데이터를 임베딩용 자연어 문서 한 덩어리로."""
    parts: list[str] = [
        f"Tool: {meta.display_name} ({meta.tool_id})",
        "Category: "
        + meta.category
        + (f" / {meta.subcategory}" if meta.subcategory else ""),
        "Applicable evidence types: "
        + ", ".join(meta.applicable_evidence_types),
    ]
    if meta.usage_description.strip():
        parts.append("Usage: " + meta.usage_description.strip())

    whens = [ct.when.strip() for ct in meta.command_templates if ct.when.strip()]
    if whens:
        parts.append("When to use:\n" + "\n".join(f"- {w}" for w in whens))

    if meta.suspicious_indicators:
        ind_lines = []
        for ind in meta.suspicious_indicators:
            seg = ind.pattern.strip()
            if ind.description.strip():
                seg += f": {ind.description.strip()}"
            ind_lines.append(f"- [{ind.severity_baseline}] {seg}")
        parts.append("Suspicious indicators:\n" + "\n".join(ind_lines))

    return "\n".join(parts)


def _metadata_for(meta: ToolMetadata) -> dict:
    return {
        "tool_id": meta.tool_id,
        "display_name": meta.display_name,
        "category": meta.category,
        "evidence_types": ",".join(meta.applicable_evidence_types),
    }


@dataclass
class ToolIndexStats:
    collection: str = ""
    tools_seen: int = 0
    tools_indexed: int = 0
    embedding_ms: int = 0
    chroma_ms: int = 0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)


def index_tools(
    tools: Optional[dict[str, ToolMetadata]] = None,
    *,
    tools_dir: str | Path | None = None,
    overwrite: bool = True,
) -> ToolIndexStats:
    """tools_metadata/*.yaml 전부 → 도구별 문서 → embed → TOOL_COLLECTION.

    overwrite=True 면 컬렉션을 reset 후 새로 채운다 (재인덱싱 기본).
    임베딩/Chroma 의존성은 이 함수 안에서만 로드된다.
    """
    from forensicagent.rag.embedder import embed_texts
    from forensicagent.rag.vector_store import VectorStore

    stats = ToolIndexStats(collection=settings.TOOL_COLLECTION)
    start = time.perf_counter()

    if tools is None:
        from forensicagent.tools import load_all_tools

        tools = load_all_tools(tools_dir)
    stats.tools_seen = len(tools)
    if not tools:
        stats.errors.append("no tool metadata loaded")
        stats.elapsed_s = time.perf_counter() - start
        return stats

    ids: list[str] = []
    docs: list[str] = []
    metas: list[dict] = []
    for tid, meta in tools.items():
        ids.append(tid)
        docs.append(build_tool_document(meta))
        metas.append(_metadata_for(meta))

    store = VectorStore(
        persist_dir=settings.CHROMA_PERSIST_DIR,
        collection_name=settings.TOOL_COLLECTION,
    )
    if overwrite:
        store.reset()

    t0 = time.perf_counter()
    vectors = embed_texts(docs)
    stats.embedding_ms = int((time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    store.add(contents=docs, embeddings=vectors, metadatas=metas, ids=ids)
    stats.chroma_ms = int((time.perf_counter() - t0) * 1000)

    stats.tools_indexed = len(ids)
    stats.elapsed_s = time.perf_counter() - start
    return stats


def tool_collection_status() -> tuple[bool, int, str]:
    """(available, count, detail) — doctor / `rag status` 표시용. 절대 raise 안 함."""
    if not settings.USE_RAG:
        return False, 0, "FORENSICAGENT_USE_RAG=off"
    try:
        from forensicagent.rag.vector_store import VectorStore

        store = VectorStore(
            persist_dir=settings.CHROMA_PERSIST_DIR,
            collection_name=settings.TOOL_COLLECTION,
        )
        n = store.count()
        return True, n, "ok" if n > 0 else "empty - run `forensicagent rag index-tools`"
    except Exception as e:  # noqa: BLE001 — deps missing etc.
        return False, 0, f"{type(e).__name__}: {str(e)[:100]}"
