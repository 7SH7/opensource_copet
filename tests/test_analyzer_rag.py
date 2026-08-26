"""Analyzer RAG 컨텍스트 주입 (mock retrieval + fake LLM client).

  * _rag_context_for: 검색 스니펫을 컨텍스트 문자열로. 폴백(None)이면 빈 문자열.
  * llm_extract: rag_context 를 LLM 프롬프트에 실제로 주입.
"""

from __future__ import annotations

from forensicagent.analyzer import analyzer as analyzer_mod
from forensicagent.analyzer import llm_extract as le
from forensicagent.rag import retrieval as retrieval_mod
from forensicagent.rag.retrieval import ToolHit
from forensicagent.tools.schema import (
    CommandTemplate,
    SuspiciousIndicator,
    ToolMetadata,
)


def _meta(tool_id="chainsaw"):
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(name="c", template="t {evidence_path}", when="w")
        ],
        usage_description="hunt evtx",
        suspicious_indicators=[
            SuspiciousIndicator(id="a", pattern="EventID 4624", description="logon")
        ],
    )


def test_rag_context_built_from_hits(monkeypatch):
    captured = {}

    def fake_retrieve(query, **kwargs):
        captured.update(kwargs)
        return [ToolHit("chainsaw", 0.9, "domain snippet about logon 4624")]

    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        fake_retrieve,
    )
    ctx = analyzer_mod._rag_context_for(_meta())
    assert "domain snippet about logon 4624" in ctx
    assert captured["tool_ids"] == {"chainsaw"}


def test_rag_context_empty_on_fallback(monkeypatch):
    monkeypatch.setattr(retrieval_mod, "retrieve_tools", lambda q, **k: None)
    assert analyzer_mod._rag_context_for(_meta()) == ""


class _FakeClient:
    def __init__(self):
        self.messages = None

    def json_chat(self, messages, **kwargs):
        self.messages = messages
        return {"findings": [], "summary": "ok"}


def test_llm_extract_injects_rag_context():
    fc = _FakeClient()
    le.extract(
        _meta(),
        "some tool output line",
        client=fc,
        rag_context="RAG-CTX-MARKER-123",
    )
    user_content = fc.messages[-1].content
    assert "RAG-CTX-MARKER-123" in user_content


def test_llm_extract_without_rag_context_omits_block():
    fc = _FakeClient()
    le.extract(_meta(), "some tool output line", client=fc, rag_context=None)
    user_content = fc.messages[-1].content
    assert "Reference forensic domain knowledge" not in user_content
