"""RAG layer — tool metadata indexing + lookup.

검색은 거의 메타데이터 lookup 이고, 자연어 의미 검색은 보조 경로다.
구성: vector_store (ChromaDB CRUD), embedder (provider 라우팅).
"""

from forensicagent.rag.embedder import embed_text, embed_texts
from forensicagent.rag.vector_store import RetrievedChunk, VectorStore

__all__ = ["VectorStore", "RetrievedChunk", "embed_text", "embed_texts"]
