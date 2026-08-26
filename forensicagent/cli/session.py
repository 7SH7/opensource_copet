"""REPL 세션 상태 — Scanner~Reporter 결과물을 턴 사이에 들고 다닌다."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from forensicagent import config as settings
from forensicagent.analyzer.types import ToolAnalysis
from forensicagent.executor.types import ExecutionBundle
from forensicagent.llm import OllamaClient
from forensicagent.reporter.types import Report, now_iso
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan
from forensicagent.tools.schema import ToolMetadata


@dataclass
class SessionOptions:
    no_llm: bool = False
    quick: bool = False
    use_rag: bool = True   # RAG 순서/컨텍스트 보강 (의존성 없으면 런타임 자동 폴백).
    max_depth: int = 5
    timeout_sec: int = 0
    max_job_output_bytes: int = settings.MAX_JOB_OUTPUT_BYTES
    max_total_output_bytes: int = settings.MAX_TOTAL_OUTPUT_BYTES
    min_free_disk_bytes: int = settings.MIN_FREE_DISK_BYTES
    forced_tools: list[str] = field(default_factory=list)
    auto_yes: bool = True  # REPL 안에서는 매 단계 사용자 입력이 곧 승인.


@dataclass
class SessionState:
    target_path: Path
    output_dir: Path
    tool_metas: dict[str, ToolMetadata]
    options: SessionOptions = field(default_factory=SessionOptions)
    # 사용자가 --output-dir 또는 /set output_dir 로 고정했는지 여부. 고정하지
    # 않았다면 조사 대상을 바꿀 때 새 case 경로로 함께 이동한다.
    output_dir_pinned: bool = False

    # 조사 시나리오 — 사용자가 /scenario 로 넣는 자유 텍스트. Selector 의 LLM
    # 우선순위와 Analyzer 의 finding 추출에 컨텍스트로 주입된다. reset_run 이
    # 지워도 유지되는 세션 수준 컨텍스트.
    scenario: Optional[str] = None

    inventory: Optional[Inventory] = None
    plan: Optional[Plan] = None
    bundle: Optional[ExecutionBundle] = None
    analyses: Optional[list[ToolAnalysis]] = None
    last_report: Optional[Report] = None
    last_report_paths: dict[str, Path] = field(default_factory=dict)

    started_at: str = field(default_factory=now_iso)
    stage_ms: dict[str, int] = field(default_factory=dict)
    _client: Optional[OllamaClient] = None

    def client(self) -> Optional[OllamaClient]:
        if self.options.no_llm:
            return None
        if self._client is None:
            self._client = OllamaClient()
        return self._client

    def invalidate_after_analysis(self) -> None:
        """분석 결과가 바뀌었으므로 이전 리포트만 폐기한다."""
        self.last_report = None
        self.last_report_paths = {}

    def invalidate_after_execution(self) -> None:
        """실행 결과가 바뀌었으므로 분석·리포트를 폐기한다."""
        self.analyses = None
        self.invalidate_after_analysis()

    def invalidate_after_plan(self) -> None:
        """계획이 바뀌었으므로 실행 이후 상태를 폐기한다."""
        self.bundle = None
        self.invalidate_after_execution()

    def invalidate_after_inventory(self) -> None:
        """인벤토리가 바뀌었으므로 계획 이후 상태를 폐기한다."""
        self.plan = None
        self.invalidate_after_plan()

    def set_target(self, path: Path) -> None:
        """조사 대상을 바꾸고 해당 대상에 종속된 모든 상태를 폐기한다."""
        self.target_path = path.resolve()
        if not self.output_dir_pinned:
            self.output_dir = settings.default_output_dir(self.target_path)
        self.reset_run()

    def set_output_dir(self, path: Path) -> None:
        self.output_dir = path.resolve()
        self.output_dir_pinned = True
        # 기존 분석은 유효하며 같은 내용을 새 위치에 다시 쓸 수 있다.
        self.invalidate_after_analysis()

    def reset_run(self) -> None:
        """현재 조사 산출물을 모두 비운다 (대상·옵션·시나리오는 유지)."""
        self.inventory = None
        self.invalidate_after_inventory()
        self.started_at = now_iso()
        self.stage_ms = {}


def make_session(
    *,
    path: Optional[Path],
    output_dir: Optional[Path],
    tool_metas: dict[str, ToolMetadata],
    options: Optional[SessionOptions] = None,
) -> SessionState:
    target = (path or Path(os.getcwd())).resolve()
    out_dir = output_dir.resolve() if output_dir else settings.default_output_dir(target)
    return SessionState(
        target_path=target,
        output_dir=out_dir,
        tool_metas=tool_metas,
        options=options or SessionOptions(),
        output_dir_pinned=output_dir is not None,
    )
