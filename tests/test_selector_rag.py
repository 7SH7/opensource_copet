"""Selector RAG 배선 — query 호출 시 재정렬, 폴백, Stage1 안전속성 (mock).

절대 원칙 검증:
  * RAG 는 순서만 바꾼다 — Stage1 자격 밖 도구를 절대 승격시키지 않는다.
  * retrieve_tools 가 None(의존성/질의 실패) 이면 결정론 순서로 조용히 폴백.
  * use_rag=False 면 RAG 를 아예 건드리지 않는다.
"""

from __future__ import annotations

from forensicagent.rag import retrieval as retrieval_mod
from forensicagent.rag.retrieval import ToolHit
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import select
from forensicagent.tools.schema import CommandTemplate, ToolMetadata


def _meta(tool_id, *, category, applicable):
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category=category,
        applicable_evidence_types=list(applicable),  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(name="c", template="t {evidence_path}", when="w")
        ],
        usage_description="desc",
    )


def _evtx_and_mem_tools():
    return {
        "chainsaw": _meta("chainsaw", category="log_analysis", applicable=["evtx_log"]),
        "evtxecmd": _meta("evtxecmd", category="log_analysis", applicable=["evtx_log"]),
        "volatility3": _meta("volatility3", category="memory_analysis", applicable=["memory_dump"]),
    }


def _evtx_only_inventory():
    return Inventory(evidence_list=[
        Evidence(path="S.evtx", filename="S.evtx", size_bytes=1,
                 evidence_type="evtx_log", detected_by="extension"),
    ])


def test_rag_reorders_candidates(monkeypatch):
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("evtxecmd", 0.9, "snip"), ToolHit("chainsaw", 0.4, "snip")],
    )
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    assert plan.rag_used is True
    ids = [t.tool_id for t in plan.selected_tools]
    assert ids == ["evtxecmd"]  # highest-ranked owner only


def test_rag_partial_scores_do_not_reorder(monkeypatch):
    monkeypatch.setattr(
        retrieval_mod,
        "retrieve_tools",
        lambda q, **k: [ToolHit("evtxecmd", 0.9, "snip")],
    )

    plan = select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
    )

    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]
    assert plan.rag_used is False


def test_rag_rejects_scores_below_configured_similarity(monkeypatch):
    import forensicagent.selector.selector as selector_mod

    monkeypatch.setattr(selector_mod.settings, "RAG_MIN_SIMILARITY", 0.5)
    monkeypatch.setattr(
        retrieval_mod,
        "retrieve_tools",
        lambda q, **k: [
            ToolHit("evtxecmd", 0.9, "high"),
            ToolHit("chainsaw", 0.49, "noise"),
        ],
    )

    plan = select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
    )

    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]
    assert plan.rag_used is False


def test_rag_near_tied_scores_do_not_reorder(monkeypatch):
    import forensicagent.selector.selector as selector_mod

    monkeypatch.setattr(selector_mod.settings, "RAG_MIN_SIMILARITY", 0.25)
    monkeypatch.setattr(selector_mod.settings, "RAG_MIN_SCORE_MARGIN", 0.05)
    monkeypatch.setattr(
        retrieval_mod,
        "retrieve_tools",
        lambda q, **k: [
            ToolHit("evtxecmd", 0.80, "slightly higher"),
            ToolHit("chainsaw", 0.77, "slightly lower"),
        ],
    )

    plan = select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
    )

    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]
    assert plan.rag_used is False


def test_rag_used_false_when_complete_scores_keep_existing_order(monkeypatch):
    monkeypatch.setattr(
        retrieval_mod,
        "retrieve_tools",
        lambda q, **k: [
            ToolHit("chainsaw", 0.9, "first"),
            ToolHit("evtxecmd", 0.4, "second"),
        ],
    )

    plan = select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
    )

    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]
    assert plan.rag_used is False


def test_rag_none_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setattr(retrieval_mod, "retrieve_tools", lambda q, **k: None)
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    assert plan.rag_used is False
    # 동점이면 결정론 필터 순서의 첫 후보가 owner다.
    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]


def test_rag_never_promotes_tool_outside_stage1(monkeypatch):
    # retrieve_tools 가 (버그로) 자격 밖 도구를 반환해도 selector 는 무시해야 한다.
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("volatility3", 0.99, "x"), ToolHit("chainsaw", 0.3, "y")],
    )
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    ids = [t.tool_id for t in plan.selected_tools]
    assert "volatility3" not in ids      # 증거(evtx)에 없는 도구는 절대 실행 계획에 없음
    assert ids == ["chainsaw"]
    assert plan.rag_used is False


def test_rag_invalid_score_does_not_complete_score_set(monkeypatch):
    monkeypatch.setattr(
        retrieval_mod,
        "retrieve_tools",
        lambda q, **k: [
            ToolHit("evtxecmd", 0.9, "valid"),
            ToolHit("chainsaw", float("nan"), "invalid"),
        ],
    )

    plan = select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
    )

    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw"]
    assert plan.rag_used is False


def test_plan_shows_one_owner_per_target_but_keeps_unique_targets():
    inventory = Inventory(
        evidence_list=[
            Evidence(
                path="S.evtx",
                filename="S.evtx",
                size_bytes=1,
                evidence_type="evtx_log",
                detected_by="extension",
            ),
            Evidence(
                path="notes.txt",
                filename="notes.txt",
                size_bytes=1,
                evidence_type="text_log",
                detected_by="extension",
            ),
        ]
    )
    tools = {
        "evtx_owner": _meta(
            "evtx_owner", category="log_analysis", applicable=["evtx_log"]
        ),
        "mixed_owner": _meta(
            "mixed_owner",
            category="log_analysis",
            applicable=["evtx_log", "text_log"],
        ),
    }

    plan = select(inventory, tools, use_llm=False, use_rag=False)

    assert plan.stage_one_candidates == 2
    assert [item.tool_id for item in plan.selected_tools] == [
        "evtx_owner",
        "mixed_owner",
    ]
    assert plan.selected_tools[0].target_evidence == ["S.evtx"]
    assert plan.selected_tools[1].target_evidence == ["notes.txt"]
    assert [spec.target_evidence for item in plan.selected_tools for spec in item.run_specs] == [
        "S.evtx",
        "notes.txt",
    ]


def test_same_target_keeps_distinct_analysis_roles_only():
    inventory = Inventory(
        evidence_list=[
            Evidence(
                path="SYSTEM",
                filename="SYSTEM",
                size_bytes=1,
                evidence_type="registry_hive",
                detected_by="filename_pattern",
            )
        ]
    )
    regripper = _meta(
        "regripper", category="registry_analysis", applicable=["registry_hive"]
    )
    regripper.subcategory = "windows_hive"
    recmd = _meta(
        "recmd", category="registry_analysis", applicable=["registry_hive"]
    )
    recmd.subcategory = "windows_hive_batch"
    shimcache = _meta(
        "appcompatcacheparser",
        category="registry_analysis",
        applicable=["registry_hive"],
    )
    shimcache.subcategory = "shimcache"

    plan = select(
        inventory,
        {
            "regripper": regripper,
            "recmd": recmd,
            "appcompatcacheparser": shimcache,
        },
        use_llm=False,
        use_rag=False,
    )

    assert [item.tool_id for item in plan.selected_tools] == [
        "regripper",
        "appcompatcacheparser",
    ]
    assert all(item.target_evidence == ["SYSTEM"] for item in plan.selected_tools)


def test_rag_query_contains_filename_type_and_configured_threshold(monkeypatch):
    import forensicagent.selector.selector as selector_mod

    captured = {}
    monkeypatch.setattr(selector_mod.settings, "RAG_MIN_SIMILARITY", 0.42)

    def _capture(query, **kwargs):
        captured["query"] = query
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr(retrieval_mod, "retrieve_tools", _capture)

    select(
        _evtx_only_inventory(),
        _evtx_and_mem_tools(),
        use_llm=False,
        use_rag=True,
        scenario="Investigate account compromise",
    )

    assert "S.evtx" in captured["query"]
    assert "evtx_log" in captured["query"]
    assert "Investigate account compromise" in captured["query"]
    assert captured["kwargs"]["min_score"] == 0.42


def test_use_rag_false_skips_retrieval(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return None

    monkeypatch.setattr(retrieval_mod, "retrieve_tools", _spy)
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=False)
    assert called["n"] == 0
    assert plan.rag_used is False


def test_single_eligible_tool_skips_rag_cold_start(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return [ToolHit("volatility3", 0.9, "unused")]

    monkeypatch.setattr(retrieval_mod, "retrieve_tools", _spy)
    inventory = Inventory(evidence_list=[
        Evidence(
            path="memory.raw",
            filename="memory.raw",
            size_bytes=1,
            evidence_type="memory_dump",
            detected_by="filename",
        )
    ])

    plan = select(inventory, _evtx_and_mem_tools(), use_llm=False, use_rag=True)

    assert [item.tool_id for item in plan.selected_tools] == ["volatility3"]
    assert called["n"] == 0
    assert plan.rag_used is False


def test_rag_snippets_passed_to_llm_rank(monkeypatch):
    """RAG 스니펫이 Stage2 LLM 프롬프트 컨텍스트로 전달되는지."""
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("chainsaw", 0.9, "SNIPPET-MARKER-XYZ")],
    )
    captured = {}

    def fake_rank(candidates, metas, inventory, client, *, scenario=None, rag_snippets=None):
        captured["snippets"] = rag_snippets
        return candidates, True, False

    import forensicagent.selector.selector as sel_mod
    monkeypatch.setattr(sel_mod, "rank_with_llm", fake_rank)

    select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=True, use_rag=True, client=object())
    assert captured["snippets"].get("chainsaw") == "SNIPPET-MARKER-XYZ"
