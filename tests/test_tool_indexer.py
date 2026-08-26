"""rag/tool_indexer — 문서 빌더 + 인덱싱 (임베더/스토어 mock).

chromadb / sentence-transformers 없이 결정론적으로 검증한다.
"""

from __future__ import annotations

from forensicagent.rag import tool_indexer
from forensicagent.rag import embedder as embedder_mod
from forensicagent.rag import vector_store as vs_mod
from forensicagent.tools.schema import (
    CommandTemplate,
    SuspiciousIndicator,
    ToolMetadata,
)


def _meta(
    tool_id: str,
    *,
    category: str = "log_analysis",
    applicable=("evtx_log",),
    usage: str = "usage text",
    indicators=(),
    whens=("default when clause",),
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category=category,
        applicable_evidence_types=list(applicable),  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(name="c", template="tool {evidence_path}", when=w)
            for w in whens
        ],
        usage_description=usage,
        suspicious_indicators=[
            SuspiciousIndicator(
                id=f"i{n}", pattern=p, severity_baseline=s, description=d  # type: ignore[arg-type]
            )
            for n, (p, d, s) in enumerate(indicators)
        ],
    )


# ---- document builder ----

def test_build_tool_document_contains_key_fields():
    m = _meta(
        "chainsaw",
        category="log_analysis",
        applicable=("evtx_log",),
        usage="Hunt Windows EVTX logs for threats",
        indicators=[("EventID 4624 logon", "successful logon", "high")],
        whens=("when evtx logs present",),
    )
    doc = tool_indexer.build_tool_document(m)
    assert "chainsaw" in doc
    assert "evtx_log" in doc
    assert "Hunt Windows EVTX" in doc
    assert "4624" in doc
    assert "when evtx logs present" in doc
    assert "high" in doc  # severity tag


class _FakeStore:
    def __init__(self, *a, **k):
        self.added = None
        self.reset_called = False

    def reset(self):
        self.reset_called = True

    def add(self, contents, embeddings, metadatas, ids):
        self.added = (contents, embeddings, metadatas, ids)

    def count(self):
        return len(self.added[3]) if self.added else 0


# ---- index_tools ----

def test_index_tools_embeds_and_stores_one_doc_per_tool(monkeypatch):
    monkeypatch.setattr(
        embedder_mod, "embed_texts", lambda texts: [[0.1, 0.2, 0.3] for _ in texts]
    )
    store = _FakeStore()
    monkeypatch.setattr(vs_mod, "VectorStore", lambda *a, **k: store)

    tools = {"chainsaw": _meta("chainsaw"), "volatility3": _meta("volatility3", category="memory_analysis", applicable=("memory_dump",))}
    stats = tool_indexer.index_tools(tools, overwrite=True)

    assert stats.tools_indexed == 2
    assert store.reset_called is True
    contents, embeddings, metadatas, ids = store.added
    assert set(ids) == {"chainsaw", "volatility3"}          # id == tool_id
    assert len(contents) == len(embeddings) == len(metadatas) == 2
    # metadata carries tool_id for retrieval-time mapping.
    assert {m["tool_id"] for m in metadatas} == {"chainsaw", "volatility3"}


def test_index_tools_empty_input_is_safe(monkeypatch):
    monkeypatch.setattr(embedder_mod, "embed_texts", lambda texts: [])
    monkeypatch.setattr(vs_mod, "VectorStore", lambda *a, **k: _FakeStore())
    stats = tool_indexer.index_tools({}, overwrite=True)
    assert stats.tools_indexed == 0
    assert stats.errors  # reports "no tool metadata loaded"


def test_no_reset_when_keep(monkeypatch):
    monkeypatch.setattr(
        embedder_mod, "embed_texts", lambda texts: [[0.0] for _ in texts]
    )
    store = _FakeStore()
    monkeypatch.setattr(vs_mod, "VectorStore", lambda *a, **k: store)
    tool_indexer.index_tools({"a": _meta("a")}, overwrite=False)
    assert store.reset_called is False
