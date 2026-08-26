"""Selector output types — 명세 2.2 의 실행 계획 스키마."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunSpec:
    """One concrete tool invocation for one evidence target.

    ``ToolSelection`` keeps its legacy aggregate fields for API compatibility,
    while run specs let a selector choose a different metadata template (and
    placeholder values) for each target.
    """

    target_evidence: str
    command_template: str
    variables: dict[str, str] = field(default_factory=dict)
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_evidence": self.target_evidence,
            "command_template": self.command_template,
            "variables": dict(self.variables),
            "label": self.label,
        }


@dataclass
class ToolSelection:
    tool_id: str
    tool_version: str = ""
    reason: str = ""
    target_evidence: list[str] = field(default_factory=list)
    command_template: str = ""
    estimated_runtime: str = "short"  # short | medium | long
    priority: int = 5                  # 1 (low) ~ 10 (high)
    run_specs: list[RunSpec] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "reason": self.reason,
            "target_evidence": list(self.target_evidence),
            "command_template": self.command_template,
            "run_specs": [spec.to_dict() for spec in self.run_specs],
            "estimated_runtime": self.estimated_runtime,
            "priority": self.priority,
        }


@dataclass
class Plan:
    selected_tools: list[ToolSelection] = field(default_factory=list)
    stage_one_candidates: int = 0       # Stage 1 통과 도구 수
    llm_used: bool = False              # Stage 2 가 실제 LLM 을 호출했는지
    llm_fallback: bool = False          # JSON 파싱 실패로 Stage 1 결과를 그대로 썼는지
    rag_used: bool = False              # RAG 검색이 순서/컨텍스트에 실제 반영됐는지
    skipped_no_evidence: list[str] = field(default_factory=list)  # 적용 가능 증거 없음
    unhandled_evidence: list[str] = field(default_factory=list)  # 소비 가능한 도구가 없는 증거

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_tools": [t.to_dict() for t in self.selected_tools],
            "stage_one_candidates": self.stage_one_candidates,
            "llm_used": self.llm_used,
            "llm_fallback": self.llm_fallback,
            "rag_used": self.rag_used,
            "skipped_no_evidence": list(self.skipped_no_evidence),
            "unhandled_evidence": list(self.unhandled_evidence),
        }
