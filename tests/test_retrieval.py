"""Runtime RAG retrieval policy tests (no Chroma/model/network required)."""

from __future__ import annotations

from forensicagent import config as settings
from forensicagent.rag import embedder as embedder_mod
from forensicagent.rag import vector_store as vector_store_mod
from forensicagent.rag.retrieval import retrieve_tools
from forensicagent.rag.vector_store import RetrievedChunk


class _FakeStore:
    captured_where = None
    chunks: list[RetrievedChunk] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def count(self) -> int:
        return 20

    def query(self, embedding, top_k, where=None):
        type(self).captured_where = where
        return list(type(self).chunks)


def _wire(monkeypatch, chunks: list[RetrievedChunk]) -> None:
    monkeypatch.setattr(settings, "USE_RAG", True)
    monkeypatch.setattr(embedder_mod, "embed_text", lambda text: [0.1, 0.2])
    monkeypatch.setattr(vector_store_mod, "VectorStore", _FakeStore)
    _FakeStore.chunks = chunks
    _FakeStore.captured_where = None


def test_eligible_tools_are_filtered_inside_chroma_query(monkeypatch):
    _wire(
        monkeypatch,
        [
            RetrievedChunk("A", {"tool_id": "chainsaw"}, 0.8, "1"),
            RetrievedChunk("B", {"tool_id": "evtxecmd"}, 0.7, "2"),
        ],
    )

    hits = retrieve_tools(
        "event log",
        top_k=2,
        tool_ids={"chainsaw", "evtxecmd"},
        min_score=0.0,
    )

    assert hits is not None
    assert {h.tool_id for h in hits} == {"chainsaw", "evtxecmd"}
    assert _FakeStore.captured_where == {
        "tool_id": {"$in": ["chainsaw", "evtxecmd"]}
    }


def test_low_similarity_hits_are_discarded(monkeypatch):
    _wire(
        monkeypatch,
        [
            RetrievedChunk("noise", {"tool_id": "chainsaw"}, 0.24, "1"),
            RetrievedChunk("useful", {"tool_id": "evtxecmd"}, 0.61, "2"),
        ],
    )

    hits = retrieve_tools("event log", top_k=2, min_score=0.25)

    assert hits is not None
    assert [h.tool_id for h in hits] == ["evtxecmd"]


def test_empty_eligible_set_short_circuits_without_loading_backend(monkeypatch):
    called = {"embed": 0}
    monkeypatch.setattr(settings, "USE_RAG", True)

    def _embed(text):
        called["embed"] += 1
        return [0.1]

    monkeypatch.setattr(embedder_mod, "embed_text", _embed)

    assert retrieve_tools("event log", tool_ids=set()) == []
    assert called["embed"] == 0
