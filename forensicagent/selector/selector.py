"""Selector orchestrator — 2단계 하이브리드.

  Stage 1 (filter.py)   결정론 evidence_type + input_format 매칭
  Stage 2 (llm_rank.py) LLM 우선순위 보강 (실패시 Stage 1 결과 그대로)

CLI 플래그 매핑:
  --auto       Stage 2 까지 실행 후 사용자 승인 없이 다음으로 (CLI 영역).
  --quick      Stage 1 이후 estimated_runtime == "short" 만 통과.
  --tools t1,t2  Stage 1/2 모두 건너뛰고 명시 도구만 (force_tools).
Forced choices still pass the deterministic host/evidence/input gate. RAG and
LLM may reorder eligible tools but cannot expand the eligible set.
"""

from __future__ import annotations

import logging
import math
import os
from typing import Iterable

from forensicagent import config as settings
from forensicagent.llm import OllamaClient
from forensicagent.observability import Stopwatch
from forensicagent.scanner.types import Inventory
from forensicagent.selector.filter import (
    filter_by_evidence,
    skipped_by_evidence_gap,
    unhandled_evidence_paths,
)
from forensicagent.selector.llm_rank import rank_with_llm
from forensicagent.selector.run_specs import populate_run_specs
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)

_RAG_QUERY_MAX_EVIDENCE = 50
_ROLE_ALIASES = {
    "windows_hive": "registry",
    "windows_hive_batch": "registry",
}


def _analysis_role(metadata: ToolMetadata | None) -> str:
    """Collapse interchangeable tools while preserving distinct analyses."""
    if metadata is None:
        return "unknown"
    subcategory = metadata.subcategory.strip().casefold()
    return _ROLE_ALIASES.get(
        subcategory,
        subcategory or metadata.category.strip().casefold(),
    )


def _finalize_run_specs(
    plan: Plan,
    tools: dict[str, ToolMetadata],
    scenario: str | None,
) -> Plan:
    owners: dict[tuple[str, str], str] = {}
    for _, selection in sorted(
        enumerate(plan.selected_tools),
        key=lambda item: (-item[1].priority, item[0]),
    ):
        role = _analysis_role(tools.get(selection.tool_id))
        for target in selection.target_evidence:
            key = (os.path.normcase(os.path.abspath(target)), role)
            owners.setdefault(key, selection.tool_id)
    for selection in plan.selected_tools:
        role = _analysis_role(tools.get(selection.tool_id))
        selection.target_evidence = [
            target
            for target in selection.target_evidence
            if owners[(os.path.normcase(os.path.abspath(target)), role)]
            == selection.tool_id
        ]
    plan.selected_tools = [
        selection for selection in plan.selected_tools if selection.target_evidence
    ]
    populate_run_specs(plan.selected_tools, tools, scenario)
    return plan


def _rag_query(inventory: Inventory, scenario: str | None) -> str:
    """Build a bounded RAG query with evidence types and representative names."""
    by_type: dict[str, int] = {}
    evidence_details: list[str] = []
    seen_details: set[tuple[str, str]] = set()
    for e in inventory.evidence_list:
        if e.evidence_type == "unknown":
            continue
        by_type[e.evidence_type] = by_type.get(e.evidence_type, 0) + 1
        detail_key = (e.filename.casefold(), e.evidence_type)
        if (
            detail_key not in seen_details
            and len(evidence_details) < _RAG_QUERY_MAX_EVIDENCE
        ):
            seen_details.add(detail_key)
            evidence_details.append(f"{e.filename} [{e.evidence_type}]")
    ev = (
        ", ".join(f"{t}({n})" for t, n in sorted(by_type.items()))
        or "unknown evidence"
    )
    parts = [f"Evidence present: {ev}."]
    if evidence_details:
        omitted = max(0, sum(by_type.values()) - len(evidence_details))
        detail_text = ", ".join(evidence_details)
        if omitted:
            detail_text += f", and {omitted} additional evidence files"
        parts.append(f"Evidence files and types: {detail_text}.")
    if scenario and scenario.strip():
        parts.append(f"Investigation scenario: {scenario.strip()}")
    parts.append("Which forensic tools are most relevant?")
    return " ".join(parts)


def _build_forced(
    force_tools: Iterable[str],
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[ToolSelection]:
    out: list[ToolSelection] = []
    for tid in force_tools:
        meta = tools.get(tid)
        if meta is None:
            logger.warning("--tools requested unknown tool_id=%r, skipping", tid)
            continue
        # --tools forces the tool choice, not unsafe or redundant targets.
        # Reuse the same evidence-type/input-format/scan-root routing contract
        # as Stage 1 so a forced recursive code tool still runs only once.
        matches = filter_by_evidence(inventory, {tid: meta})
        if not matches:
            logger.warning(
                "--tools requested tool_id=%r but no compatible evidence was found",
                tid,
            )
            continue
        selection = matches[0]
        selection.reason = "forced by --tools"
        selection.priority = 10
        out.append(selection)
    return out


def select(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
    *,
    quick: bool = False,
    force_tools: list[str] | None = None,
    use_llm: bool = True,
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> Plan:
    """Return the execution Plan.

    use_llm=False 는 테스트/오프라인용 (Stage 2 건너뛰기).
    use_rag=True 면 Stage1 후보를 RAG 관련도로 재정렬하고 LLM 컨텍스트에
    스니펫을 주입한다. RAG 는 순서/프롬프트에만 영향 — Stage1 자격 게이트는
    그대로. 의존성/질의 실패 시 조용히 결정론 순서로 폴백.
    """
    plan = Plan()
    plan.unhandled_evidence = unhandled_evidence_paths(inventory, tools)

    if force_tools:
        with Stopwatch() as sw:
            plan.selected_tools = _build_forced(force_tools, inventory, tools)
            plan.stage_one_candidates = len(plan.selected_tools)
        if stage_ms is not None:
            stage_ms["select_force"] = (
                stage_ms.get("select_force", 0) + sw.elapsed_ms
            )
        return _finalize_run_specs(plan, tools, scenario)

    # ---- Stage 1: deterministic filter ----
    with Stopwatch() as sw:
        candidates = filter_by_evidence(inventory, tools)
        plan.skipped_no_evidence = skipped_by_evidence_gap(inventory, tools)
    if stage_ms is not None:
        stage_ms["select_filter"] = stage_ms.get("select_filter", 0) + sw.elapsed_ms

    if quick:
        candidates = [c for c in candidates if c.estimated_runtime == "short"]
    plan.stage_one_candidates = len(candidates)

    if not candidates:
        return _finalize_run_specs(plan, tools, scenario)

    # ---- RAG: 순서 힌트 + 스니펫 (Stage1 자격은 불변, 실패 시 조용히 폴백) ----
    rag_snippets: dict[str, str] = {}
    if use_rag:
        with Stopwatch() as sw_rag:
            rag_snippets = _apply_rag(plan, candidates, inventory, scenario)
        if stage_ms is not None:
            stage_ms["select_rag"] = (
                stage_ms.get("select_rag", 0) + sw_rag.elapsed_ms
            )

    # ---- Stage 2: LLM ranking ----
    if not use_llm:
        # RAG 가 candidates 를 in-place 재정렬했으므로 그 순서로 확정.
        plan.selected_tools = candidates
        return _finalize_run_specs(plan, tools, scenario)

    with Stopwatch() as sw:
        ranked, used, fallback = rank_with_llm(
            candidates, tools, inventory, client,
            scenario=scenario, rag_snippets=rag_snippets,
        )
    if stage_ms is not None:
        stage_ms["select_rank"] = stage_ms.get("select_rank", 0) + sw.elapsed_ms

    plan.selected_tools = ranked
    plan.llm_used = used
    plan.llm_fallback = fallback
    return _finalize_run_specs(plan, tools, scenario)


def _apply_rag(
    plan: Plan,
    candidates: list[ToolSelection],
    inventory: Inventory,
    scenario: str | None,
) -> dict[str, str]:
    """candidates 를 RAG 관련도로 in-place 재정렬하고 tool_id→스니펫 맵 반환.

    RAG 를 못 쓰면(None) 아무것도 바꾸지 않고 빈 dict 를 반환한다.
    """
    # One eligible tool cannot be reranked. Avoid paying the cold-start cost
    # of importing the local embedding stack for a result that is immutable.
    if len(candidates) < 2:
        return {}

    from forensicagent.rag.retrieval import retrieve_tools

    eligible = {c.tool_id for c in candidates}
    hits = retrieve_tools(
        _rag_query(inventory, scenario),
        top_k=len(candidates),
        tool_ids=eligible,
        min_score=settings.RAG_MIN_SIMILARITY,
    )
    if not hits:  # None(폴백) 또는 [](관련 히트 없음) → 순서 불변.
        return {}

    scores: dict[str, float] = {}
    snippets: dict[str, str] = {}
    for hit in hits:
        if hit.tool_id not in eligible:
            continue
        try:
            score = float(hit.score)
        except (TypeError, ValueError):
            continue
        if (
            not math.isfinite(score)
            or not 0.0 <= score <= 1.0
            or score < settings.RAG_MIN_SIMILARITY
        ):
            continue
        # Retrieval normally deduplicates tools. If a custom backend returns
        # duplicates, retain the strongest valid hit and matching snippet.
        if hit.tool_id not in scores or score > scores[hit.tool_id]:
            scores[hit.tool_id] = score
            snippets[hit.tool_id] = hit.snippet
    # Partial retrieval must not demote missing Stage-1 candidates. Snippets
    # from valid hits may still enrich Stage 2 while ordering stays deterministic.
    if set(scores) != eligible:
        return snippets

    margin = max(0.0, settings.RAG_MIN_SCORE_MARGIN)
    if max(scores.values()) - min(scores.values()) < margin:
        return snippets

    before = [candidate.tool_id for candidate in candidates]
    ranked = sorted(
        candidates,
        key=lambda candidate: scores[candidate.tool_id],
        reverse=True,
    )
    after = [candidate.tool_id for candidate in ranked]
    if after != before:
        candidates[:] = ranked
        plan.rag_used = True
    return snippets
