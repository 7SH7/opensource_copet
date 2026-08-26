"""Executor output types — 명세 2.3 의 실행 결과 묶음."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

ExecStatus = Literal[
    "success",
    "failed",
    "timeout",
    "cancelled",
    "output_limit",
    "skipped",
    "output_missing",
]
ArtifactRole = Literal["stdout", "stderr", "generated"]
MAX_INLINE_JSON_BYTES = 100 * 1024


@dataclass
class OutputArtifact:
    """One immutable output captured from a tool invocation."""

    path: str
    role: ArtifactRole
    format: str = "binary"
    size_bytes: int = 0
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "format": self.format,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


# The product language uses "produced artifact" while the concrete type name
# stays concise.  Keep both names public for downstream consumers.
ProducedArtifact = OutputArtifact


@dataclass
class ExecutionResult:
    tool_id: str
    target_evidence: str = ""           # 1 tool x 1 evidence per record
    status: ExecStatus = "skipped"
    command_executed: str = ""
    stdout_path: str = ""               # 항상 파일 경로. inline 금지.
    stderr_path: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0
    output_format: str = "text"
    output_size_bytes: int = 0
    error_message: str = ""             # status != success 일 때 사람이 읽는 요약
    # parsed_output 는 어댑터가 가벼운 dict 로 변환했을 때만 채움.
    # 대용량 raw 출력은 stdout_path 로만 노출하고 inline 화 X (명세 2.3).
    parsed_output: Optional[dict[str, Any]] = None

    # Appended fields preserve positional construction compatibility with the
    # original ExecutionResult contract.
    command_template_used: str = ""
    artifacts: list[OutputArtifact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # The runner records the real stdout byte size.  Keep large structured
        # output as an artifact instead of duplicating it inside every report.
        parsed_output = (
            self.parsed_output
            if self.output_size_bytes <= MAX_INLINE_JSON_BYTES
            else None
        )
        return {
            "tool_id": self.tool_id,
            "target_evidence": self.target_evidence,
            "status": self.status,
            "command_executed": self.command_executed,
            "command_template_used": self.command_template_used,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "output_format": self.output_format,
            "output_size_bytes": self.output_size_bytes,
            "error_message": self.error_message,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "warnings": list(self.warnings),
            "provenance": dict(self.provenance),
            "parsed_output": parsed_output,
        }


@dataclass
class ExecutionBundle:
    results: list[ExecutionResult] = field(default_factory=list)
    output_dir: str = ""                 # 모든 stdout/stderr 가 저장된 루트
    parallel_max: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_dir": self.output_dir,
            "parallel_max": self.parallel_max,
            "results": [r.to_dict() for r in self.results],
        }

    def for_tool(self, tool_id: str) -> list[ExecutionResult]:
        return [r for r in self.results if r.tool_id == tool_id]
